#!/usr/bin/python

from dwarf.DW.TAG import DW_TAG
from dwarf.DW.AT import DW_AT
from dwarf.DW.FORM import DW_FORM
import dwarf.attr
import dwarf.options
import sys
import io

class debug_abbrev:
    '''Represents the .debug_abbrev section in DWARF.'''
    def __init__(self, data):
        self.sets = None
        self.data = data
        self.offset_to_set = {}

    def get_sets(self):
        if self.sets is not None:
            return self.sets
        self.sets = []
        offset = 0
        while 1:
            abbrev_set = self.get_abbrev_set(offset)
            if abbrev_set is None:
                break
            self.sets.append(abbrev_set)
            offset = abbrev_set.end_offset
        return self.sets

    def get_abbrev_set(self, debug_abbrev_offset):
        if debug_abbrev_offset in self.offset_to_set:
            return self.offset_to_set[debug_abbrev_offset]
        self.data.seek(debug_abbrev_offset)
        actual_offset = self.data.tell()
        if actual_offset != debug_abbrev_offset:
            print('error: failed to seek to .debug_abbrev[%#8.8x], could only seek to %#8.8x' % (debug_abbrev_offset, actual_offset))
            return None
        # print('unpacking .debug_abbrev[%#8.8x]...' % (actual_offset))
        abbrev_set = Set()
        if abbrev_set.unpack(self.data):
            self.offset_to_set[debug_abbrev_offset] = abbrev_set
            return abbrev_set
        return None

    def dump(self, f=sys.stdout):
        f.write('debug_abbrev:\n')
        for abbrev_set in self.get_sets():
            abbrev_set.dump(f=f)

    def __str__(self):
        output = io.StringIO()
        self.dump(output)
        return output.getvalue()


class Decl:
    def __init__(self):
        self.offset = 0
        self.code = 0
        self.tag = DW_TAG.null
        self.has_children = False
        self.attribute_specs = []
        self.fixed_size = -1
        self.fixed_addrs = 0

    def get_tag(self):
        return self.tag

    def has_attributes(self):
        return len(self.attribute_specs) > 0

    def might_have_attribute(self, attr_enum_value):
        for attr_spec in self.attribute_specs:
            attr = attr_spec.attr
            if (attr == attr_enum_value or attr == DW_AT.specification or
                    attr == DW_AT.abstract_origin):
                return True
        return False

    def might_have_any_attributes(self, attr_enum_values):
        for attr_spec in self.attribute_specs:
            attr = attr_spec.attr
            if (attr in attr_enum_values or attr == DW_AT.specification or
                    attr == DW_AT.abstract_origin):
                return True
        return False

    def encode(self, encoder):
        self.offset = encoder.file.tell()
        encoder.put_uleb128(self.code)
        encoder.put_uleb128(self.tag)
        encoder.put_uint8(self.has_children)
        for attr_spec in self.attribute_specs:
            encoder.put_uleb128(attr_spec.attr)
            encoder.put_uleb128(attr_spec.form)
        encoder.put_uleb128(0)
        encoder.put_uleb128(0)

    def unpack(self, data):
        self.offset = data.tell()
        self.code = data.get_uleb128()
        if self.code != 0:
            self.tag = DW_TAG(data.get_uleb128())
            self.has_children = data.get_uint8()
            fixed_size = 0
            fixed_addrs = 0
            while 1:
                attr = data.get_uleb128()
                form = data.get_uleb128()
                if attr and form:
                    implicit_const = None
                    if form == DW_FORM.implicit_const:
                        implicit_const = data.get_sleb128()
                    attr_spec = dwarf.attr.Spec(attr, form, implicit_const)
                    self.attribute_specs.append(attr_spec)
                    if fixed_size >= 0:
                        attr_fixed_size = attr_spec.get_fixed_size()
                        if attr_fixed_size >= 0:
                            fixed_size += attr_fixed_size
                        elif attr_spec.get_form().is_address():
                            fixed_addrs += 1
                        else:
                            fixed_size = -1
                else:
                    break
            if fixed_size >= 0:
                self.fixed_size = fixed_size
                self.fixed_addrs = fixed_addrs
            return self.tag != DW_TAG.null
        else:
            self.tag = DW_TAG.null
            self.has_children = False
            self.attribute_specs = []
            return False

    def get_fixed_size(self, die):
        if self.fixed_size >= 0:
            return (self.fixed_size +
                    self.fixed_addrs * die.cu.dwarf_info.addr_size)
        else:
            return -1

    def skip(self, die, data):
        fixed_size = self.get_fixed_size(die)
        if fixed_size >= 0:
            data.seek(data.tell() + fixed_size)
            return True
        else:
            for attr_spec in self.attribute_specs:
                if not attr_spec.get_form().skip(die, data):
                    return False
            return True

    def is_null(self):
        return self.get_tag().is_null()

    def dump(self, f=sys.stdout):
        if self.has_children:
            child_str = dwarf.options.get_color_DW_constant('DW_CHILDREN_yes')
        else:
            child_str = dwarf.options.get_color_DW_constant('DW_CHILDREN_no')
        f.write('[%u]:\n  %-*s     %s\n' % (self.code, DW_TAG.max_width(),
                                            dwarf.options.get_color_tag(self.get_tag()),
                                            child_str))

        for attr_spec in self.attribute_specs:
            f.write('  ')
            attr_spec.dump(f=f)
            f.write('\n')

    def __str__(self):
        output = io.StringIO()
        self.dump(output)
        return output.getvalue()


class Set:
    def __init__(self):
        self.offset = 0
        self.abbrevs = []

    def encode(self, encoder):
        for abbrev in self.abbrevs:
            abbrev.encode(encoder)
        encoder.put_uint8(0)

    def unpack(self, data):
        self.offset = data.tell()
        abbrev = Decl()
        while abbrev.unpack(data):
            self.abbrevs.append(abbrev)
            abbrev = Decl()
        self.end_offset = data.tell()
        return len(self.abbrevs) > 0

    def dump(self, f=sys.stdout):
        f.write('%s:\n' % (dwarf.options.get_color_offset(self.offset)))
        for abbrev in self.abbrevs:
            abbrev.dump(f=f)
            f.write('\n')

    def __str__(self):
        output = io.StringIO()
        self.dump(output)
        return output.getvalue()

    def getCode(self, abbrev):
        '''Look through all abbreviations and calculate the abbreviation code
        by finding one that matches, or by adding a new one'''
        abbrev_len = len(abbrev.attribute_specs)
        for (idx, curr_abbrev) in enumerate(self.abbrevs):
            if abbrev.tag == curr_abbrev.tag:
                if abbrev.has_children == curr_abbrev.has_children:
                    curr_abbrev_len = len(curr_abbrev.attribute_specs)
                    if abbrev_len == curr_abbrev_len:
                        match = True
                        for i in range(abbrev_len):
                            if (abbrev.attribute_specs[i] !=
                                    curr_abbrev.attribute_specs[i]):
                                match = False
                                break
                        if match:
                            return curr_abbrev.code
        abbrev.code = len(self.abbrevs) + 1
        self.abbrevs.append(abbrev)
        return abbrev.code

    def get_abbrev_decl(self, code):
        if code <= 0:
            return None
        code_idx = code - 1
        if code_idx < len(self.abbrevs):
            if self.abbrevs[code_idx].code == code:
                return self.abbrevs[code_idx]
        for abbrev in self.abbrevs:
            if abbrev.code == code:
                return abbrev
        return None
