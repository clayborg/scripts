#!/usr/bin/python

# Python imports
import bisect
import io
import os
import sys

# Local imports
import objfile

# Package imports
import dwarf.parse
from dwarf.DW.TAG import *
from dwarf.DW.AT import DW_AT
from dwarf.DW.SECT import *
from dwarf.DW.UT import *
from dwarf.die import DIE
from dwarf.ranges import DIERanges
import dwarf.debug.line
import dwarf.parse


class CompileUnit:
    '''DWARF compile unit class'''
    def __init__(self, debug_info):
        self.debug_info = debug_info
        self.data = None
        self.offset = 0
        self.first_die_offset = None
        self.length = 0
        self.dwarf_info = dwarf.parse.Info(addr_size=0, version=0,
                                           dwarf_size=4)
        self.unit_type = DW_UT(0)
        self.__abbrev_offset = 0  # Use accessor for this as it might need to be relocated
        self.__abbrev_offset_relocated = False
        self.dwo_id = None  # only DW_UT_skeleton, DW_UT_split_compile
        self.dwo_objfile = None  # object file for .dwo file when there is no .dwp file
        self.dwo_dwarf = None  # The DWARF context for the DWO file
        self.type_sig = None  # only DW_UT_type, DW_UT_split_type
        self.type_offset = None  # only DW_UT_type, DW_UT_split_type
        self.path = None
        self.die = None # Just the compile unit DIE on its own for speed
        self.dies = None
        self.abbrev_set = None
        self.line_table = None
        self.base_address = -1
        self.aranges = None
        self.die_ranges = None
        self.addr_base = None
        self.str_offsets = None
        self.stmt_offset = None
        # If this is skeleton compile unit it will have a DWO unit
        self.dwo_unit = None
        self.dwo_error = None  # If we fail to get the DWO unit, then save the error
        self.dwo_path = -1
        # If this is a DWO file, a back pointer to the owning skeleton unit.
        self.skeleton_unit = None
        # If this is a DWO file within a DWP file, then we have the section
        # offsets from the .debug_cu_index/.debug_tu_index that we need to
        # apply to offsets from other sections.
        self.__sect_id_to_offset = None
        self.stmt_offset = None

    def get_dwarf(self):
        '''Return the DWARF context object for this DWARF Unit'''
        return self.debug_info.dwarf

    def __lt__(self, other):
        if type(other) is int:
            return self.offset < other
        else:
            raise ValueError

    def free_memory(self):
        '''Remove all things that take up memory.'''
        self.dies = None
        self.line_table = None

    def unpack(self, data):
        self.data = data
        self.offset = data.tell()
        self.length = data.get_uint32()
        self.dwarf_info.version = data.get_uint16()
        if self.dwarf_info.version >= 5:
            self.unit_type = DW_UT(data.get_uint8())
            self.dwarf_info.addr_size = data.get_uint8()
            self.__abbrev_offset = data.get_uint32()
            if self.unit_type in [DW_UT.skeleton, DW_UT.split_compile]:
                self.dwo_id = data.get_uint64()
            elif self.unit_type in [DW_UT.type, DW_UT.split_type]:
                self.type_sig = data.get_uint64()
                self.type_offset = data.get_offset()
        else:
            self.unit_type = DW_UT.compile
            self.__abbrev_offset = data.get_uint32()
            self.dwarf_info.addr_size = data.get_uint8()
        if self.dwarf_info.addr_size == 4 or self.dwarf_info.addr_size == 8:
            data.set_addr_size(self.dwarf_info.addr_size)
        self.first_die_offset = data.tell()
        return self.is_valid()

    def get_abbrev_offset(self):
        if not self.__abbrev_offset_relocated:
            self.__abbrev_offset_relocated = True
            self.__abbrev_offset = self.relocate_offset(self.__abbrev_offset,
                                                        DW_SECT.ABBREV)
        return self.__abbrev_offset

    def get_section_relocations(self):
        if self.__sect_id_to_offset is None:
            self.__sect_id_to_offset = {}
            # Check if this is a .dwo file within a .dwp file file. If so we need
            # to relocate many offsets
            dwarf = self.get_dwarf()
            if dwarf.is_dwp and (self.dwo_id or self.type_sig):
                index = None
                hash = None
                if self.type_sig:
                    index = dwarf.get_debug_tu_index()
                    hash = self.type_sig
                else:
                    index = dwarf.get_debug_cu_index()
                    hash = self.dwo_id
                if index and hash:
                    section_ids = index.get_section_ids()
                    row = index.get_row_for_hash(hash)
                    if row and row.section_infos:
                        for (i, sect_info) in enumerate(row.section_infos):
                            self.__sect_id_to_offset[section_ids[i]] = sect_info.offset
        return self.__sect_id_to_offset

    def relocate_offset(self, offset, sect_id):
        section_relocations = self.get_section_relocations()
        if section_relocations:
            if sect_id in section_relocations:
                return section_relocations[sect_id] + offset
        return offset


    def get_base_address(self):
        if self.base_address == -1:
            die = self.get_die()
            if die:
                self.base_address = die.get_attr_as_int(DW_AT.low_pc, -1)
                if self.base_address != -1:
                    return self.base_address
                self.base_address = die.get_attr_as_int(DW_AT.entry_pc, -1)
                if self.base_address == -1:
                    self.base_address = 0
        return self.base_address

    def get_ranges(self):
        if self.aranges is None:
            self.aranges = DebugRanges.Ranges(self, self.get_die().offset, [])
            die = self.get_die()
            if die:
                self.aranges = die.get_ranges()
        return self.aranges

    def get_die_ranges(self):
        '''Calculate the address map that maps address ranges to DIE offsets'''
        if self.die_ranges is None:
            self.die_ranges = DIERanges()
            dies = self.get_dies()
            for die in dies:
                tag = die.get_tag()
                if tag == DW_TAG.subprogram or tag == DW_TAG.variable:
                    die.append_die_ranges(self.die_ranges)
            self.die_ranges.sort()
        return self.die_ranges

    def get_path(self):
        if self.path is None:
            self.path = ''
            die = self.get_die()
            if die:
                name = die.get_name()
                self.path = name
                if not name.startswith('/'):
                    comp_dir = die.get_attr_as_string(DW_AT.DW_AT_comp_dir)
                    if comp_dir:
                        self.path = os.path.join(comp_dir, name)
        return self.path

    def get_file(self, file_num):
        line_table = self.get_line_table()
        if line_table:
            return line_table.get_file(file_num)
        return None

    def contains_offset(self, offset):
        return self.offset <= offset and offset < self.get_next_cu_offset()

    def dump_header(self, f=sys.stdout, offset_adjust=0):
        color_offset = dwarf.options.get_color_offset(self.offset +
                                                      offset_adjust)
        if self.dwarf_info.version <= 4:
            f.write('%s: Compile Unit: length=0x%8.8x, version=0x%4.4x, '
                    'abbrev_offset=0x%8.8x, addr_size=0x%2.2x (next CU at '
                    '0x%8.8x)\n' % (color_offset, self.length,
                                    self.dwarf_info.version,
                                    self.get_abbrev_offset(),
                                    self.dwarf_info.addr_size,
                                    self.get_next_cu_offset() + offset_adjust))
        else:
            f.write('%s: DWARF Unit: length=0x%8.8x, version=0x%4.4x, '
                    'unit_type=%s, addr_size=0x%2.2x, abbrev_offset=0x%8.8x' % (
                        color_offset, self.length, self.dwarf_info.version,
                        self.unit_type, self.dwarf_info.addr_size,
                        self.get_abbrev_offset()))
            if self.unit_type in [DW_UT.skeleton, DW_UT.split_compile]:
                f.write(', dwo_id=%#x' % (self.dwo_id))
            if self.unit_type in [DW_UT.type, DW_UT.split_type]:
                f.write(', type_sig=%#x, type_offset=%#x' % (self.type_sig,
                                                             self.type_offset))
            f.write(' (next CU at 0x%8.8x)\n' % (
                self.get_next_cu_offset() + offset_adjust))

    def __str__(self):
        output = io.StringIO()
        self.dump_header(f=output)
        return output.getvalue()

    def __repr__(self):
        # basename = 'none'
        objfile = self.debug_info.dwarf.objfile
        description = '' if objfile is None else objfile.description(show_offset=False)
        if self.dwo_id:
            return '%#8.8x: %s dwo_id=%#16.16x from %s' % (self.offset, self.unit_type, self.dwo_id, description)
        elif self.type_sig:
            return '%#8.8x: %s type_sig=%#16.16x from %s' % (self.offset, self.unit_type, self.type_sig, description)
        else:
            return '%#8.8x: %s (%s)' % (self.offset, self.unit_type, description)

    def dump(self, verbose, max_depth=sys.maxsize, f=sys.stdout,
             offset_adjust=0, indent_width=4):
        if max_depth is None:
            max_depth = sys.maxsize
        self.dump_header(f=f, offset_adjust=offset_adjust)
        die = None
        if max_depth == 0:
            die = self.get_die()
        else:
            dies = self.get_dies()
            if dies:
                die = dies[0]
        if die:
            die.dump(verbose=verbose, max_depth=max_depth, f=f,
                     offset_adjust=offset_adjust, indent_width=indent_width)

    def is_valid(self):
        return (self.length > 0 and
                self.dwarf_info.version > 0 and
                self.dwarf_info.version <= 7 and
                self.dwarf_info.addr_size > 0)

    def is_skeleton(self):
        return self.unit_type == DW_UT.skeleton

    def get_dwo_path(self):
        if self.dwo_path == -1:
            die = self.get_die()
            dwo_attrs = [DW_AT.dwo_name, DW_AT.GNU_dwo_name]
            self.dwo_path = die.get_first_attribute_value_as_string(dwo_attrs)
            if not os.path.isabs(self.dwo_path):
                # Path is relative, try and locate
                comp_dir = die.get_attr_as_string(DW_AT.comp_dir)
                if comp_dir:
                    self.dwo_path = os.path.join(comp_dir, self.dwo_path)
        return self.dwo_path

    def get_dwo_or_dwp_dwarf(self):
        '''Get the .dwp DWARF file if it exist, else get the .dwo file.'''
        if self.is_skeleton() and self.dwo_objfile is None and self.dwo_error is None:
            self.dwo_dwarf = self.get_dwarf().dwp
            if self.dwo_dwarf is None:
                dwo_path = self.get_dwo_path()
                if dwo_path is None:
                    self.dwo_error = "error: no DW_AT_dwo_name attribute was found"
                elif os.path.exists(dwo_path):
                    self.dwo_objfile = objfile.get_object_file(dwo_path)
                    self.dwo_dwarf = self.dwo_objfile.get_dwarf()
                else:
                    self.dwo_error = "error: dwo \"%s\" doesn't exist" % (self.dwo_path)
        return self.dwo_dwarf

    def get_dwo_unit(self):
        if self.dwo_unit is None:
            if self.dwo_id is None:
                return (None, None)  # Not a skeleton unit, so not an error
            # If we have a .dwp file, then use it to get the .dwo file from
            dwo_file = self.get_dwo_or_dwp_dwarf()
            if dwo_file:
                self.dwo_unit = dwo_file.get_debug_info().get_compile_unit_with_dwo_id(self.dwo_id)
                if self.dwo_unit:
                    self.dwo_unit.skeleton_unit = self
        return self.dwo_unit

    def get_stmt_offset(self):
        '''
            Return the value of the DW_AT_stmt_list attribute, or None if it
            doesn't have one. DIE.get_attr_as_int will relocate the value
            for .dwo in .dwp files.
        '''
        if self.stmt_offset is None:
            self.stmt_offset = self.get_die().get_attr_as_int(DW_AT.stmt_list, None)
        return self.stmt_offset

    def get_line_table(self):
        if self.line_table is None:
            if self.skeleton_unit:
                dwarf_unit = self.skeleton_unit
            else:
                dwarf_unit = self

            stmt_list = dwarf_unit.get_stmt_offset()
            if stmt_list is not None:
                dwarf_unit.line_table = dwarf_unit.get_dwarf().get_line_table(
                    stmt_list, dwarf_unit.dwarf_info.addr_size)
            self.line_table = dwarf_unit.line_table
        return self.line_table

    def get_next_cu_offset(self):
        return self.offset + self.length + 4

    def get_header_byte_size(self):
        return self.first_die_offset - self.offset

    def get_first_die_offset(self):
        return self.first_die_offset

    def get_die_with_offset(self, die_offset):
        self.get_dies()
        i = bisect.bisect_left(self.dies, die_offset)
        if i < len(self.dies) and self.dies[i].offset == die_offset:
            return self.dies[i]
        return None

    def find_dies_with_name(self, name):
        matching_dies = []
        dies = self.get_dies()
        for die in dies:
            die_name = die.get_name()
            if die_name:
                if die_name == name:
                    matching_dies.append(die)
        if len(matching_dies):
            return matching_dies
        return None

    def get_dies(self):
        if self.dies is None:
            self.dies = []
            abbrev_set = self.get_abbrev_set()
            data = self.data
            data.seek(self.get_first_die_offset())
            end_offset = self.get_next_cu_offset()
            depth = 0
            while data.tell() < end_offset:
                die = DIE(self, len(self.dies), depth, abbrev_set, data)
                if not die.is_valid():
                    raise ValueError('not able to decode die at %#8.8x' % (
                                     die.offset))
                self.dies.append(die)
                if die.abbrev is None:
                    depth -= 1
                elif die.abbrev.has_children:
                    depth += 1
                if depth < 0:
                    break
        return self.dies

    def get_die(self):
        '''Get the compile unit DIE'''
        if self.die is None:
            abbrev_set = self.get_abbrev_set()
            self.data.push_offset_and_seek(self.get_first_die_offset())
            die = DIE(self, 0, 0, abbrev_set, self.data)
            self.data.pop_offset_and_seek()
            if not die.is_valid():
                raise ValueError('not able to decode die at %#8.8x' % (
                                 die.offset))
            self.die = die
        return self.die

    def get_abbrev_set(self):
        if self.abbrev_set is None:
            debug_abbrev = self.get_dwarf().get_debug_abbrev()
            self.abbrev_set = debug_abbrev.get_abbrev_set(self.get_abbrev_offset())
        return self.abbrev_set

    def lookup_die_by_address(self, address):
        die_ranges = self.get_die_ranges()
        return die_ranges.lookup_die_by_address(address)

    def lookup_row_by_address(self, address):
        line_table = self.get_line_table()
        return line_table.lookup_address(address)

    def get_location_list(self, offset):
        '''Get a location list given a .debug_loc offset.'''
        debug_loc_data = self.get_dwarf().debug_loc_data
        if debug_loc_data:
            return dwarf.debug.loc.LocationList(offset, debug_loc_data,
                                                self.get_base_address())
        return None

    def get_str_offsets(self):
        '''
        Find the .debug_str_offsets table for this compile unit.
        '''
        if self.str_offsets is None:
            str_offsets_base = self.get_die().get_attr_as_int(DW_AT.str_offsets_base, None)
            if str_offsets_base is not None:
                # We have a DW_AT_str_offsets_base attribute. Find the
                # .debug_str_offsets table using this value.
                str_offsets_base = self.relocate_offset(str_offsets_base, DW_SECT.STR_OFFSETS)
                self.str_offsets = self.get_dwarf().debug_str_offsets.find_header_by_str_offsets_base(str_offsets_base)
            else:
                # We have a .dwo file as a stand alone file or in a .dwp file.
                # Find the .debug_str_offsets table using the header offset.
                str_offsets_offset = self.relocate_offset(0, DW_SECT.STR_OFFSETS)
                self.str_offsets = self.get_dwarf().debug_str_offsets.find_header_by_offset(str_offsets_offset)
        return self.str_offsets

    def get_string_at_index(self, idx):
        '''
        Get a string from the .debug_str_offsets table for this compile unit.
        '''
        str_offsets = self.get_str_offsets()
        if str_offsets is None:
            raise ValueError('unable to find .debug_str_offsets header for compile unit')
        return str_offsets.get_string_at_index(idx)

    def get_addr_base(self):
        '''Fixup the .debug_addr base for .dwo files.'''
        if self.addr_base is None:
            self.addr_base = self.get_die().get_attr_as_int(DW_AT.addr_base, None)
        return self.addr_base

    def get_indexed_address(self, addr_idx):
        if self.skeleton_unit:
            return self.skeleton_unit.get_indexed_address(addr_idx)
        addr_base = self.get_addr_base()
        dwarf = self.get_dwarf()
        if addr_base is None or dwarf.debug_addr_data is None:
            return None
        offset = addr_base + addr_idx * self.dwarf_info.addr_size
        debug_addr_data = dwarf.debug_addr_data
        debug_addr_data.push_offset_and_seek(offset)
        addr = debug_addr_data.get_address()
        debug_addr_data.pop_offset_and_seek()
        return addr
