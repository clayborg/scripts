#!/usr/bin/python

# Python imports
import binascii
import io
import sys

# Package imports
from dwarf.defines import is_string
from dwarf.DW.ACCESS import DW_ACCESS
from dwarf.DW.AT import DW_AT
from dwarf.DW.ATE import DW_ATE
from dwarf.DW.CC import DW_CC
from dwarf.DW.FORM import DW_FORM
from dwarf.DW.INL import DW_INL
from dwarf.DW.LANG import DW_LANG
from dwarf.DW.SECT import DW_SECT
from dwarf.DW.VIRTUALITY import DW_VIRTUALITY
import dwarf.debug.loc

# Local imports
import file_extract


class Spec:
    '''An attribute specification with the DWARF attribute and form.'''
    def __init__(self, attr, form, implicit_const = None):
        self.attr = DW_AT(attr)
        self.form = DW_FORM(form)
        if implicit_const:
            self.implicit_const = implicit_const

    def get_fixed_size(self, dwarf_info=None):
        '''Get the fixed byte size of the DW_FORM in this attribute spec.'''
        return self.get_form().get_fixed_size(dwarf_info)

    def get_attr(self):
        return self.attr

    def get_form(self):
        return self.form

    def __repr__(self):
        return str(self)

    def dump(self, f=sys.stdout):
        f.write('%-*s %s' % (DW_AT.max_width(),
                             dwarf.options.get_color_attr(self.get_attr()),
                             dwarf.options.get_color_form(self.get_form())))

    def __str__(self):
        output = io.StringIO()
        self.dump(output)
        return output.getvalue()

    def __eq__(self, rhs):
        if rhs is None:
            return False
        return self.attr == rhs.attr and self.form == rhs.form

    def __ne__(self, rhs):
        if rhs is None:
            return True
        return self.attr != rhs.attr or self.form != rhs.form


class Value:
    '''An attribute value object.

    This object contains the offset in the .debug_XXX section for the data
    for this attribute, the attribute specification and the value will be
    fetched on demand.'''
    def __init__(self, attr_spec):
        self.offset = 0
        self.attr_spec = attr_spec
        self.value = None
        self.value_raw = None

    def get_attr(self):
        '''Get the form as a dwarf.AT.DW_AT() object.'''
        return self.attr_spec.get_attr()

    def get_form(self):
        '''Get the form as a dwarf.FORM.DW_FORM() object.'''
        return self.attr_spec.get_form()

    def get_fixed_size(self, die):
        return self.attr_spec.get_fixed_size(die.cu.dwarf_info)

    def extract_value(self, data, die=None):
        self.offset = data.tell()
        reloc_sect = None
        if self.get_attr() == DW_AT.stmt_list:
            reloc_sect = DW_SECT.LINE
        (self.value, self.value_raw) = self.get_form().extract_value(data, die, dw_sect=reloc_sect)
        return self.value is not None

    def get_resolved_address(self):
        form = self.get_form()
        if form.is_indexed_address():
            # If we both value and value_raw are filled in, we were able to
            # resolve our address
            if self.value is not None and self.value_raw is not None:
                return self.value
        if form.value == DW_FORM.addr:
            return self.value
        return None

    def get_value(self, die):
        attr = self.attr_spec.attr
        if attr == DW_AT.language:
            return DW_LANG(self.value)
        if attr == DW_AT.encoding:
            return DW_ATE(self.value)
        if attr == DW_AT.virtuality:
            return DW_VIRTUALITY(self.value)
        if attr == DW_AT.accessibility:
            return DW_ACCESS(self.value)
        if attr == DW_AT.inline:
            return DW_INL(self.value)
        if attr == DW_AT.calling_convention:
            return DW_CC(self.value)
        if attr in [DW_AT.frame_base, DW_AT.location,
                    DW_AT.data_member_location, DW_AT.vtable_elem_location,
                    DW_AT.data_location]:
            # If we have a DW_AT_data_member_location and the form is a data
            # form, then we have no location expression, just a constant offset
            # from the parent.
            form = self.get_form()
            if attr == DW_AT.data_member_location and form.is_data():
                if die:
                    return "+" + get_sized_hex(self.get_fixed_size(die),
                                               self.value)
                return None
            if die:
                if form.is_block():
                    return dwarf.debug.loc.Location(self.get_block_data(die))
                else:
                    return die.cu.get_location_list(self.value)
        return None

    def encode_dwarfdb(self, die, data):
        data.put_uleb128(self.attr_spec.attr)
        sys.stdout.write(str(self.attr_spec))
        if self.attr_spec.attr in [DW_AT.decl_file, DW_AT.call_file]:
            form = DW_FORM(DW_FORM.strp)
            data.put_uleb128(DW_FORM.strp)
            path = die.get_file(self.value)
            form.encode_dwarfdb(die, data, path)
        else:
            data.put_uleb128(self.attr_spec.form)
            self.get_form().encode_dwarfdb(die, data, self.value)

    def get_block_data(self, die):
        if self.get_form().is_block():
            return file_extract.FileExtract(io.BytesIO(self.value),
                                            die.cu.data.get_byte_order(),
                                            die.cu.data.addr_size)
        return None

    def get_value_as_string(self, die=None, verbose=False):
        attr = self.attr_spec.attr
        if attr == DW_AT.decl_file or attr == DW_AT.call_file:
            if die:
                filename = die.get_file(self.value)
                if filename:
                    if verbose:
                        return '%u "%s"' % (self.value, filename)
                    return '"%s"' % (filename)
            return 'file[%u]' % (self.value)
        elif attr == DW_AT.decl_line or attr == DW_AT.call_line:
            return '%u' % (self.value)
        # elif die is not None and attr == DW_AT.ranges:
        #     return str(die.get_debug_ranges())
        enum_value = self.get_value(die)
        if enum_value:
            return str(enum_value)
        else:
            form = self.get_form()
            if form.is_block():
                output = io.StringIO()
                data_len = len(self.value)
                fixed_size = form.get_block_length_size()
                output.write('<%s> ' % (get_sized_hex(fixed_size, data_len)))
                output.write('%s ' % (binascii.hexlify(self.value, ' ').decode('utf-8')))
                return '%s' % (output.getvalue().strip())
            elif form.is_reference():
                return '{0x%8.8x}' % (self.value)
            elif is_string(self.value):
                max_length = dwarf.options.options.max_strlen
                truncated = False
                if max_length is None or len(self.value) <= max_length:
                    s = self.value
                else:
                    truncated = True
                    s = self.value[0:max_length]
                if verbose:
                    if form.value == DW_FORM.strp:
                        return '.debug_str[%#8.8x] -> "%s"%s' % (self.value_raw, s, "..." if truncated else "")
                    elif form.is_indexed_string():
                        return '.debug_str_offsets[%u] -> "%s"%s' % (self.value_raw, s, "..." if truncated else "")
                return '"%s"%s' % (s, "..." if truncated else "")
            elif form.is_flag():
                if self.value == 1:
                    return "true"
                elif self.value == 0:
                    return "false"
                else:
                    return '<invalid flag value %u>' % self.value
            elif form == DW_FORM.sec_offset:
                fixed_size = self.get_fixed_size(die)
                if verbose and self.value_raw is not None:
                    return get_sized_hex(fixed_size, self.value) + ' (without relocation = ' + get_sized_hex(fixed_size, self.value_raw) + ')'
                else:
                    return get_sized_hex(fixed_size, self.value)
            else:
                if form.value in [DW_FORM.addrx,
                                  DW_FORM.addrx1,
                                  DW_FORM.addrx2,
                                  DW_FORM.addrx3,
                                  DW_FORM.addrx4]:
                    if self.value_raw is None:
                        # If we don't have a raw value, we weren't able to
                        # resolve the indexed address and the value in
                        # self.value is the index
                        return 'indexed (%u) address = <unresolved>' % (self.value)
                    elif verbose:
                        return 'indexed (%u) -> %#8.8x' % (self.value_raw, self.value)
                    else:
                        if die.cu.data.addr_size == 4:
                            return '%#8.8x' % (self.value)
                        else:
                            return '%#16.16x' % (self.value)
                # Check if we have a high PC value that is an offset from the
                # low PC
                if attr == DW_AT.high_pc and form.is_data():
                    low_pc_value = die.get_attr_value(DW_AT.low_pc)
                    if low_pc_value:
                        resolved_addr = low_pc_value.get_resolved_address()
                        if resolved_addr is not None:
                            return get_sized_hex(die.cu.data.addr_size,
                                                 resolved_addr + self.value)
                    return 'DW_AT_low_pc + ' + get_sized_hex(self.get_fixed_size(die), self.value)
                return get_sized_hex(self.get_fixed_size(die), self.value)

    def dump(self, die, verbose, f=sys.stdout, offset_adjust=0,
             indent_width=4):
        if die:
            indent_level = die.depth
        else:
            indent_level = 0
        colorizer = dwarf.options.get_colorizer()
        form_value = self.get_value_as_string(die=die, verbose=verbose)
        attr = self.get_attr()
        form = self.get_form()
        if form.is_reference():
            form_value_color = colorizer.yellow()
        elif form_value.startswith('"'):
            form_value_color = colorizer.green()
        elif form_value.startswith('DW_'):
            form_value_color = colorizer.magenta()
        else:
            form_value_color = ''
        if verbose:
            fixed_size = self.get_fixed_size(die)
            # Print the offset of each attribute
            if fixed_size == 0:
                f.write('            ')
            else:
                f.write('%s: ' % (
                        dwarf.options.get_color_offset(self.offset +
                                                       offset_adjust)))
            # Indent
            f.write('%*s' % (1 + indent_level * indent_width, ''))
            # Print fixed width attribute enum
            f.write('%s ' % (dwarf.options.get_color_attr(attr.fixed_str())))
            # Print fixed width form enum
            f.write('%s ' % (dwarf.options.get_color_form(form.fixed_str())))
        else:
            # Indent
            f.write('%*s' % (13 + indent_level * indent_width, ''))
            # Print attribute enum
            f.write('%s(' % (dwarf.options.get_color_attr(attr)))
        # Print form value
        f.write('%s%s%s' % (form_value_color, form_value,
                            colorizer.reset()))
        # Finish off the line
        if verbose:
            f.write('\n')
        else:
            f.write(')\n')

    def __str__(self):
        output = io.StringIO()
        self.dump(die=None, verbose=True, f=output)
        return output.getvalue()


def get_sized_hex(fixed_form_size, value):
    '''Print out an integer with the correct byte size as a hex string.

    Fixed size integers will be printed out with the correct hex width and
    padded with zeros. ULEB and SLEB values will be printed out using hex with
    no width.
    '''
    if fixed_form_size == 1:
        return '0x%2.2x' % (value)
    elif fixed_form_size == 2:
        return '0x%4.4x' % (value)
    elif fixed_form_size == 4:
        return '0x%8.8x' % (value)
    elif fixed_form_size == 8:
        return '0x%16.16x' % (value)
    elif fixed_form_size == 16:
        return '0x%32.32x' % (value)
    else:
        # ULEB or SLEB
        return '0x%x' % (value)
