#!/usr/bin/python

# Local imports
import file_extract

# Python Imports
import binascii
import copy
import io
import os
import shlex
import subprocess
import sys
import tempfile

# Package Imports
from dwarf.defines import is_string
import dwarf.attr
import dwarf.context
import dwarf.debug.abbrev
import dwarf.debug.line
from dwarf.defines import UINT32_MAX, UINT64_MAX
from dwarf.DW.AT import DW_AT
from dwarf.DW.ATE import *
from dwarf.DW.FORM import *
from dwarf.DW.LANG import *
from dwarf.DW.TAG import *
from dwarf.ranges import AddressRange, AddressRangeList


INT8_MIN = -128
INT16_MIN = -32768
INT32_MIN = -2147483648
INT64_MIN = -9223372036854775808
INT8_MAX = 127
INT16_MAX = 32767
INT32_MAX = 2147483647
INT64_MAX = 9223372036854775807
UINT8_MAX = 255
UINT16_MAX = 65535
UINT32_MAX = 4294967295
UINT64_MAX = 18446744073709551615


class DWARF:
    '''Classes to generate DWARF debug information.'''
    def __init__(self, dwarf_info):
        self.dwarf_info = dwarf_info
        self.compile_units = []
        self.abbrevs = dwarf.debug.abbrev.Set()
        self.ranges = []
        self.debug_abbrev = self.create_encoder()
        self.debug_aranges = self.create_encoder()
        self.debug_info = self.create_encoder()
        self.debug_line = self.create_encoder()
        self.debug_ranges = self.create_encoder()
        self.strtab = StringTable()
        self.did_generate = False

    def create_encoder(self):
        return file_extract.FileEncode(io.BytesIO(),
                                       self.dwarf_info.byte_order,
                                       self.dwarf_info.addr_size)

    def addr_is_valid(self, addr):
        # Since python has infinite sized integers, we can't rely on unsigned
        # math like we can in C/C++ code.
        if self.dwarf_info.addr_size == 4:
            return addr <= UINT32_MAX
        elif self.dwarf_info.addr_size == 8:
            return addr <= UINT64_MAX
        raise ValueError('invalid addr_size %u' % (self.dwarf_info.addr_size))

    def get_debug_abbrev_bytes(self):
        '''Get the .debug_abbrev bytes as a python string.'''
        return self.debug_abbrev.file.getvalue()

    def get_debug_aranges_bytes(self):
        '''Get the .debug_aranges bytes as a python string.'''
        return self.debug_aranges.file.getvalue()

    def get_debug_info_bytes(self):
        '''Get the .debug_info bytes as a python string.'''
        return self.debug_info.file.getvalue()

    def get_debug_line_bytes(self):
        '''Get the .debug_lime bytes as a python string.'''
        return self.debug_line.file.getvalue()

    def get_debug_ranges_bytes(self):
        '''Get the .debug_ranges bytes as a python string.'''
        return self.debug_ranges.file.getvalue()

    def get_debug_str_bytes(self):
        '''Get the .debug_str bytes as a python string.'''
        return self.strtab.bytes

    def addCompileUnit(self, tag):
        cu = CompileUnit(self, tag)
        self.compile_units.append(cu)
        return cu

    def generate(self):
        if self.did_generate:
            return  # Can only generate once.
        self.did_generate = True
        # When generating DWARF we must first run through all DWARF
        # compile units and DIEs and let them figure out their offsets
        # since we might have one DIE attribute that is a reference to
        # another DIE and we must have all DIEs having their final
        # offsets before we try to emit the DWARF.
        offset = 0
        for cu in self.compile_units:
            offset = cu.prepare_for_encoding(offset)

        # Now emit all of the abbreviations in the .debug_abbrev section
        self.abbrevs.encode(self.debug_abbrev)
        # Emit all required info to all required sections for the CU itself
        # and all of its DIEs
        for cu in self.compile_units:
            cu.encode()

    def save(self, filename):
        self.generate()
        command = 'clang -Wl,-r -x c -o "%s"' % (filename)
        remove_files = []
        # Save the DWARF that was generated with a previous call to generate.
        debug_abbrev_bytes = self.get_debug_abbrev_bytes()
        if len(debug_abbrev_bytes):
            debug_abbrev_file = tempfile.NamedTemporaryFile(delete=False)
            debug_abbrev_file.write(debug_abbrev_bytes)
            debug_abbrev_file.close()
            remove_files.append(debug_abbrev_file.name)
            command += ' -Wl,-sectcreate,__DWARF,__debug_abbrev,%s' % (
                debug_abbrev_file.name)

        debug_aranges_bytes = self.get_debug_aranges_bytes()
        if len(debug_aranges_bytes):
            debug_aranges_file = tempfile.NamedTemporaryFile(delete=False)
            debug_aranges_file.write(debug_aranges_bytes)
            debug_aranges_file.close()
            #remove_files.append(debug_aranges_file.name)
            command += ' -Wl,-sectcreate,__DWARF,__debug_aranges,%s' % (
                debug_aranges_file.name)

        debug_info_bytes = self.get_debug_info_bytes()
        if len(debug_info_bytes):
            debug_info_file = tempfile.NamedTemporaryFile(delete=False)
            debug_info_file.write(debug_info_bytes)
            debug_info_file.close()
            remove_files.append(debug_info_file.name)
            command += ' -Wl,-sectcreate,__DWARF,__debug_info,%s' % (
                debug_info_file.name)

        debug_line_bytes = self.get_debug_line_bytes()
        if len(debug_line_bytes):
            debug_line_file = tempfile.NamedTemporaryFile(delete=False)
            debug_line_file.write(debug_line_bytes)
            debug_line_file.close()
            remove_files.append(debug_line_file.name)
            command += ' -Wl,-sectcreate,__DWARF,__debug_line,%s' % (
                debug_line_file.name)

        debug_ranges_bytes = self.get_debug_ranges_bytes()
        if len(debug_ranges_bytes):
            debug_ranges_file = tempfile.NamedTemporaryFile(delete=False)
            debug_ranges_file.write(debug_ranges_bytes)
            debug_ranges_file.close()
            remove_files.append(debug_ranges_file.name)
            command += ' -Wl,-sectcreate,__DWARF,__debug_ranges,%s' % (
                debug_ranges_file.name)

        debug_str_bytes = self.get_debug_str_bytes()
        if len(debug_str_bytes):
            debug_str_file = tempfile.NamedTemporaryFile(delete=False)
            debug_str_file.write(str.encode(debug_str_bytes))
            debug_str_file.close()
            remove_files.append(debug_str_file.name)
            command += ' -Wl,-sectcreate,__DWARF,__debug_str,%s' % (
                debug_str_file.name)

        # Need at least .debug_abbrev and .debug_info to make a DWARF file.
        if len(debug_abbrev_bytes) and len(debug_info_bytes):
            command += ' -'
            print('%s' % (command))
            try:
                status = subprocess.check_call(shlex.split(command),
                                               stdin=open('/dev/null'))
            except subprocess.CalledProcessError as e:
                print("Ping stdout output:\n", e.output)
            if status != 0:
                print('error: %u' % (status))
            else:
                print('success')
        else:
            print('error: no .debug_abbrev or .debug_info bytes')

        for path in remove_files:
            os.remove(path)

    def get_dwarf(self):
        self.generate()
        byte_order = self.dwarf_info.byte_order
        addr_size = self.dwarf_info.addr_size
        debug_abbrev = file_extract.FileExtract(io.BytesIO(
            self.get_debug_abbrev_bytes()), byte_order, addr_size)
        debug_info = file_extract.FileExtract(io.BytesIO(
            self.get_debug_info_bytes()), byte_order, addr_size)
        debug_line = file_extract.FileExtract(io.BytesIO(
            self.get_debug_line_bytes()), byte_order, addr_size)
        debug_ranges = file_extract.FileExtract(io.BytesIO(
            self.get_debug_ranges_bytes()), byte_order, addr_size)
        debug_str = file_extract.FileExtract(io.BytesIO(
            self.get_debug_str_bytes()), byte_order, addr_size)
        return dwarf.context.DWARF(
                debug_abbrev=debug_abbrev,
                debug_info=debug_info,
                debug_line=debug_line,
                debug_ranges=debug_ranges,
                debug_str=debug_str)


class CompileUnit:
    '''DWARF generator compile unit'''
    def __init__(self, generator, tag):
        self.offset = -1
        self.length = -1
        self.dwarf_info = copy.copy(generator.dwarf_info)
        self.generator = generator
        self.die = DIE(self, tag)
        self.prologue = dwarf.debug.line.Prologue()
        self.prologue.generate_init()
        self.line_rows = []
        self.aranges = None
        self.die_ranges = None

    def get_die_ranges(self):
        if self.die_ranges is None:
            self.die_ranges = AddressRangeList()
            for die in self.die.children:
                die_ranges = die.get_die_ranges()
                if die_ranges:
                    self.die_ranges.ranges.extend(die_ranges.ranges)
            if len(self.die_ranges):
                self.die_ranges.finalize()
        return self.die_ranges

    def generate_debug_aranges(self):
        '''Auto generate the .debug_aranges by looking at all
            DW_TAG_subprogram DIEs and using their ranges.'''
        self.get_aranges().address_ranges = self.get_die_ranges()

    def generate_cu_ranges(self):
        '''Auto generate the .debug_aranges by looking at all
            DW_TAG_subprogram DIEs and using their ranges.'''
        ranges = copy.deepcopy(self.get_die_ranges())
        if len(ranges):
            base_addr = ranges.get_min_address()
            if base_addr >= 0:
                self.die.addAttribute(DW_AT.low_pc, DW_FORM.addr, base_addr)
                # Make all of the range information relative to the
                # compile unit base address
                for range in ranges:
                    range.lo -= base_addr
                    range.hi -= base_addr
            if ranges:
                self.die.addAttribute(DW_AT.ranges, DW_FORM.sec_offset, ranges)

    def get_aranges(self):
        if self.aranges is None:
            self.aranges = dwarf.debug.aranges.Set(self.dwarf_info)
        return self.aranges

    def add_arange(self, low_pc, high_pc):
        '''Manually add a range to the .debug_aranges'''
        self.get_aranges().append_range(low_pc, high_pc)

    def add_line_entry_with_file_index(self, file_idx, line, addr, end_sequence=False):
        row = dwarf.debug.line.Row(self.prologue)
        row.addr = addr
        row.file = file_idx
        row.line = line
        row.end_sequence = end_sequence
        self.line_rows.append(row)

    def add_line_entry(self, fullpath, line, addr, end_sequence=False):
        row = dwarf.debug.line.Row(self.prologue)
        row.addr = addr
        row.file = self.add_file(fullpath)
        row.line = line
        row.end_sequence = end_sequence
        self.line_rows.append(row)

    def add_file(self, fullpath):
        return self.prologue.add_file(fullpath)

    def prepare_for_encoding(self, offset):
        dwarf32 = self.dwarf_info.isDWARF32()
        # We must emit the line tables first so we know the value of the
        # DW_AT_stmt_list and add the attribute. We only need to emit a line
        # table if we have files in the prologue. If we don't have any
        # files, then we don't have a line table of anything that requires
        # the line table (DW_AT_decl_file or DW_AT_call_file).
        if len(self.prologue.files) > 0:
            debug_line = self.generator.debug_line
            self.prologue.encode(debug_line)
            prev_row = None
            for row in self.line_rows:
                row.encode(debug_line, prev_row)
                prev_row = row
            # Fixup the prologue length field after writing all rows.
            line_table_length = debug_line.tell() - (
                self.prologue.offset + 4)
            debug_line.fixup_uint_size(4, line_table_length,
                                        self.prologue.offset)
            # Add a DW_AT_stmt_list to the compile unit DIE with the
            # right offset
            self.die.addSectionOffsetAttribute(DW_AT.stmt_list,
                                               self.prologue.offset)

        # Now calculate the CU offset and let each DIE calculate its offset
        # so we can correctly emit relative and absolute DIE references in
        # the self.encode(...) later. This compile unit might contain DIEs
        # that refer to DIEs in previous compile units, this compile unit,
        # or subsequent compile units.
        self.offset = offset
        if dwarf32:
            cu_rel_offset = 11
        else:
            cu_rel_offset = 11 + 8
        cu_rel_end_offset = self.die.computeSizeAndOffsets(cu_rel_offset)
        offset += cu_rel_end_offset
        self.length = cu_rel_end_offset - 4
        return offset  # return the offset for the next CU

    def encode(self):
        debug_info = self.generator.debug_info
        actual_offset = debug_info.file.tell()
        if actual_offset != self.offset:
            print('error: compile unit actual offset is 0x%x when it '
                    'should be 0x%x' % (actual_offset, self.offset))
        # Encode the compile unit header
        debug_info.put_uint32(self.length)
        debug_info.put_uint16(self.dwarf_info.version)
        if self.dwarf_info.version <= 4:
            debug_info.put_uint32(0)  # Abbrev offset
            debug_info.put_uint8(self.dwarf_info.addr_size)
        else:
            # Unit type for DWARF 5 and later
            debug_info.put_uint8(DW_UT_compile)
            debug_info.put_uint8(self.dwarf_info.addr_size)
            debug_info.put_uint32(0)  # Abbrev offset
        # Encode all DIEs and their attribute
        self.die.encode(debug_info)

        # Encode the .debug_aranges if any
        if self.aranges:
            self.aranges.cu_offset = self.offset
            self.aranges.encode(self.generator.debug_aranges)


class Attribute:
    '''DWARF generator DIE attribute'''
    def __init__(self, attr, form, value):
        self.attr_spec = dwarf.attr.Spec(attr, form)
        self.value = value

    def get_form(self):
        return self.attr_spec.form

    def get_attr(self):
        return self.attr_spec.attr

    def encode(self, die, strm):
        form = self.attr_spec.form
        value = self.value
        if isinstance(self.value, AddressRangeList):
            die.cu.generator.debug_ranges.set_addr_size(die.cu.dwarf_info.addr_size)
            value = self.value.encode(die.cu.generator.debug_ranges)

        if form == DW_FORM.strp:
            if (is_string(value)):
                stroff = die.cu.generator.strtab.add(value)
            else:
                stroff = value
            strm.put_uint32(stroff)
        elif form == DW_FORM.addr:
            strm.put_address(value)
        elif form == DW_FORM.data1:
            strm.put_uint8(value)
        elif form == DW_FORM.data2:
            strm.put_uint16(value)
        elif form == DW_FORM.data4:
            strm.put_uint32(value)
        elif form == DW_FORM.data8:
            strm.put_uint64(value)
        elif form == DW_FORM.udata:
            strm.put_uleb128(value)
        elif form == DW_FORM.sdata:
            strm.put_sleb128(value)
        elif form == DW_FORM.string:
            strm.put_c_string(value)
        elif form == DW_FORM.block1:
            strm.put_uint8(len(value))
            if isinstance(value, list):
                for u8 in value:
                    strm.put_uint8(u8)
            else:
                strm.file.write(value)
        elif form == DW_FORM.block2:
            strm.put_uint16(len(value))
            strm.file.write(value)
        elif form == DW_FORM.block4:
            strm.put_uint32(len(value))
            strm.file.write(value)
        elif form == DW_FORM.block:
            strm.put_uleb128(len(value))
            strm.file.write(value)
        elif form == DW_FORM.exprloc:
            strm.put_uleb128(len(value))
            strm.file.write(value)
        elif form == DW_FORM.flag:
            if value:
                strm.put_uint8(1)
            else:
                strm.put_uint8(0)
        elif form == DW_FORM.ref1:
            if isinstance(value, DIE):
                strm.put_uint8(value.getCompileUnitOffset())
            else:
                strm.put_uint8(value)
        elif form == DW_FORM.ref2:
            if isinstance(value, DIE):
                strm.put_uint16(value.getCompileUnitOffset())
            else:
                strm.put_uint16(value)
        elif form == DW_FORM.ref4:
            if isinstance(value, DIE):
                strm.put_uint32(value.getCompileUnitOffset())
            else:
                strm.put_uint32(value)
        elif form == DW_FORM.ref8:
            if isinstance(value, DIE):
                strm.put_uint64(value.getCompileUnitOffset())
            else:
                strm.put_uint64(value)
        elif form == DW_FORM.ref_udata:
            if isinstance(value, DIE):
                strm.put_uleb128(value.getCompileUnitOffset())
            else:
                strm.put_uleb128(value)
            strm.put_uleb128(value)
        elif form == DW_FORM.sec_offset:
            int_size = self.attr_spec.get_form().get_fixed_size(
                die.cu.dwarf_info)
            strm.put_uint_size(int_size, value)
        elif form == DW_FORM.flag_present:
            pass
        elif form == DW_FORM.ref_sig8:
            strm.put_uint64(value)
        elif form in [DW_FORM.ref_addr, DW_FORM.GNU_ref_alt, DW_FORM.GNU_strp_alt]:
            int_size = self.attr_spec.get_form().get_fixed_size(
                die.cu.dwarf_info)
            if isinstance(value, DIE):
                strm.put_uint_size(int_size, value.getOffset())
            else:
                strm.put_uint_size(int_size, value)
        elif form == DW_FORM.indirect:
            raise ValueError("DW_FORM_indirect isn't handled")


class DIE:
    '''DWARF generator DIE (debug information entry)'''
    def __init__(self, cu, tag):
        self.offset = -1
        self.abbrev_code = -1
        self.cu = cu
        self.tag = tag
        self.attributes = []
        self.children = []

    def getAttribute(self, attr):
        for attribute in self.attributes:
            if attribute.get_attr() == attr:
                return attribute
        return None

    def getCompileUnitOffset(self):
        '''Get the compile unit relative offset for this DIE'''
        if self.offset == -1:
            raise ValueError("DIE hasn't had its size calculated yet")
        return self.offset

    def getOffset(self):
        '''Get the absolute offset within all DWARF for this DIE'''
        if self.cu.offset == -1:
            raise ValueError("DIE's compile unit hasn't had its size "
                                "calculated yet")
        return self.cu.offset + self.getCompileUnitOffset()

    def addAttribute(self, attr, form, value):
        attr = Attribute(attr, form, value)
        self.attributes.append(attr)
        return attr

    def addStringAttribute(self, attr, s):
        '''Add a string attribute using DW_FORM_strp.'''
        return self.addAttribute(attr, DW_FORM.strp, s)

    def addNameAttribute(self, name):
        '''Add a name attribute using DW_AT_name and DW_FORM_strp.'''
        return self.addAttribute(DW_AT.name, DW_FORM.strp, name)

    def addDataAttribute(self, attr, value):
        '''Add an integer attribute and select the right DW_FORM_data encoding.'''
        if INT8_MIN <= value and value <= INT8_MAX:
            return self.addAttribute(attr, DW_FORM.data1, value)
        if INT16_MIN <= value and value <= INT16_MAX:
            return self.addAttribute(attr, DW_FORM.data2, value)
        if INT32_MIN <= value and value <= INT32_MAX:
            return self.addAttribute(attr, DW_FORM.data4, value)
        if INT64_MIN <= value and value <= INT64_MAX:
            return self.addAttribute(attr, DW_FORM.data8, value)
        raise ValueError('integer too large')

    def addReferenceAttribute(self, attr, die):
        '''Add an attribute that references another DIE.'''
        self.addAttribute(attr, DW_FORM.ref4, die)

    def addGNUAltReferenceAttribute(self, attr, die):
        '''Add an attribute that references another DIE.'''
        self.addAttribute(attr, DW_FORM.GNU_ref_alt, die)

    def addAbsoluteReferenceAttribute(self, attr, die):
        '''Add an attribute that references another DIE.'''
        self.addAttribute(attr, DW_FORM.ref_addr, die)

    def addFileAttribute(self, attr, fullpath):
        '''Add an attribute that points to a file index.'''
        self.addDataAttribute(attr, self.cu.add_file(fullpath))

    def addSectionOffsetAttribute(self, attr, value):
        '''Correctly encode an attribute with the right DW_FORM for the
            current DWARF version.'''
        if self.cu.dwarf_info.version >= 4:
            self.addAttribute(attr, DW_FORM.sec_offset, value)
        elif self.cu.dwarf_info.isDWARF32():
            self.addAttribute(attr, DW_FORM.data4, value)
        else:
            self.addAttribute(attr, DW_FORM.data8, value)

    def addDeltaRangeAttributes(self, low_pc, high_pc):
        '''Add low and high PC attributes to a DIE where the high PC is an
           offset from the low pc.'''
        self.addAttribute(DW_AT.low_pc, DW_FORM.addr, low_pc)
        self.addDataAttribute(DW_AT.high_pc, high_pc - low_pc)

    def addRangeAttributes(self, low_pc, high_pc):
        '''Add low and high PC attributes to a DIE using absolute addresses.'''
        self.addAttribute(DW_AT.low_pc, DW_FORM.addr, low_pc)
        self.addAttribute(DW_AT.high_pc, DW_FORM.addr, high_pc)

    def addChild(self, tag):
        die = DIE(self.cu, tag)
        self.children.append(die)
        return die

    def addBaseTypeChild(self, name: str, encoding: DW_ATE, byte_size: int):
        die = self.addChild(DW_TAG.base_type)
        die.addNameAttribute(name)
        die.addDataAttribute(DW_AT.encoding, encoding)
        die.addDataAttribute(DW_AT.byte_size, byte_size)
        return die

    def createAbbrevDecl(self):
        abbrev = dwarf.debug.abbrev.Decl()
        abbrev.tag = self.tag
        abbrev.has_children = len(self.children) > 0
        for attr in self.attributes:
            abbrev.attribute_specs.append(attr.attr_spec)
        return abbrev

    def computeSizeAndOffsets(self, offset):
        self.offset = offset
        self.abbrev_code = self.cu.generator.abbrevs.getCode(
            self.createAbbrevDecl())
        offset += get_uleb128_byte_size(self.abbrev_code)
        for attr in self.attributes:
            byte_size = attr.attr_spec.get_form().get_byte_size(self,
                                                                attr.value)
            offset += byte_size
        if self.children:
            for child in self.children:
                offset = child.computeSizeAndOffsets(offset)
            offset += 1  # NULL tag to terminate children
        return offset

    def encode(self, encoder):
        actual_offset = encoder.file.tell()
        if actual_offset != self.offset:
            print('error: DIE actual offset is 0x%x when it should be 0x%x'
                    % (actual_offset, self.offset))
        encoder.put_uleb128(self.abbrev_code)
        for attr in self.attributes:
            attr.encode(self, encoder)
        if self.children:
            for child in self.children:
                child.encode(encoder)
            encoder.put_uleb128(0)  # Terminate child DIE chain

    def get_die_ranges(self):
        ranges = AddressRangeList()
        if self.tag == DW_TAG.subprogram:
            lo_pc = None
            hi_pc = None
            hi_pc_is_offset = False
            for attribute in self.attributes:
                attr = attribute.get_attr()
                if attr == DW_AT.low_pc:
                    lo_pc = attribute.value
                elif attr == DW_AT.high_pc:
                    hi_pc = attribute.value
                    if attribute.get_form() != DW_FORM.addr:
                        hi_pc_is_offset = True
                elif attr == DW_AT.ranges:
                    if isinstance(attribute.value, AddressRangeList):
                        ranges.append(attribute.value)
                    else:
                        raise ValueError
            if lo_pc is None and hi_pc is None:
                return
            if hi_pc_is_offset:
                hi_pc += lo_pc
            if lo_pc < hi_pc:
                if (self.cu.generator.addr_is_valid(lo_pc) and
                        self.cu.generator.addr_is_valid(hi_pc)):
                    ranges.append(AddressRange(lo_pc, hi_pc))
        if self.children:
            for child in self.children:
                child_ranges = child.get_die_ranges()
                if child_ranges:
                    ranges.append(child_ranges)
        if ranges:
            return ranges
        return None


class StringTable:
    '''A string table that uniques strings and hands out offsets'''
    def __init__(self):
        self.bytes = "\0"
        self.lookup = {}

    def add(self, s):
        if s in self.lookup:
            return self.lookup[s]
        else:
            offset = len(self.bytes)
            self.lookup[s] = offset
            self.bytes += s + "\0"
            return offset

    def dump(self):
        for (i, byte) in enumerate(self.bytes):
            if i % 32 == 0:
                sys.stdout.write("0x%8.8x: " % (i))
            sys.stdout.write('%s ' % (binascii.hexlify(byte)))
        print
