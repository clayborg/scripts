#!/usr/bin/python

# Python imports
import os

# Package imports
from dwarf.debug.apple import AppleHash
from dwarf.debug.aranges import debug_aranges
from dwarf.debug.abbrev import debug_abbrev
from dwarf.debug.index import debug_index
from dwarf.debug.info import debug_info
from dwarf.debug.ranges import debug_ranges
from dwarf.debug.names import debug_names
import dwarf.debug.str


class DWARF:
    '''A full DWARF context with all sections needed for DWARF parsing'''
    def __init__(self,
                 objfile=None,
                 dwp=None,
                 is_dwo=False,
                 debug_abbrev=None,
                 debug_addr=None,
                 debug_aranges=None,
                 debug_cu_index=None,
                 debug_info=None,
                 debug_line=None,
                 debug_line_str=None,
                 debug_loc=None,
                 debug_loclists=None,
                 debug_ranges=None,
                 debug_str=None,
                 debug_str_offsets=None,
                 debug_tu_index=None,
                 debug_types=None,
                 debug_names=None,
                 apple_names=None,
                 apple_types=None):
        self.objfile = objfile
        self.dwp = dwp
        self.is_dwo = is_dwo
        self.is_dwp = debug_cu_index is not None or debug_tu_index is not None
        self.debug_addr_data = debug_addr
        self.debug_abbrev_data = debug_abbrev
        self.debug_aranges_data = debug_aranges
        self.debug_info_data = debug_info
        self.debug_line_data = debug_line
        self.debug_line_str_data = debug_line_str
        self.debug_names_data = debug_names
        self.debug_ranges_data = debug_ranges
        self.debug_str_data = debug_str
        self.debug_str_offsets_data = debug_str_offsets
        self.debug_types_data = debug_types
        self.apple_names_data = apple_names
        self.apple_types_data = apple_types
        self.debug_loc_data = debug_loc
        self.debug_loclists_data = debug_loclists
        self.debug_cu_index_data = debug_cu_index
        self.debug_tu_index_data = debug_tu_index

        self.debug_str = dwarf.debug.str.debug_str('.debug_str', self.debug_str_data)
        self.debug_line_str = dwarf.debug.str.debug_str('.debug_line_str', self.debug_line_str_data)
        if self.debug_str_offsets_data:
            self.debug_str_offsets = dwarf.debug.str.debug_str_offsets(
                    self.debug_str_offsets_data, self.debug_str)
        else:
            self.debug_str_offsets = 0
        self.debug_abbrev = None
        self.debug_aranges = None
        self.debug_info = None
        self.debug_ranges = None
        self.apple_names = None
        self.apple_types = None
        self.debug_names = None
        self.debug_cu_index = None
        self.debug_tu_index = None
        self.stmt_list_to_debug_line = {}

    def __str__(self):
        if self.objfile:
            return self.objfile.description()
        return 'objfile = None'

    def __repr__(self):
        return str(self)

    @classmethod
    def locate_dwp(cls, path):
        dwp_path = path + '.dwp'
        if os.path.exists(dwp_path):
            return dwp_path
        return None

    def get_line_table(self, stmt_list, addr_size):
        '''
            Many type units share line tables with the same DW_AT_stmt_list
            attribute value. This function allows us to shared the line table
            across different DWARF units.
        '''
        if stmt_list is None:
            return None
        if stmt_list in self.stmt_list_to_debug_line:
            return self.stmt_list_to_debug_line[stmt_list]
        line_table = dwarf.debug.line.debug_line(self,
                                                 self.debug_line_data,
                                                 stmt_list,
                                                 addr_size)
        if line_table is not None:
            self.stmt_list_to_debug_line[stmt_list] = line_table
        return line_table

    def get_string(self, offset):
        return self.debug_str.get_string(offset)

    def get_line_string(self, offset):
        return self.debug_line_str.get_string(offset)

    def get_string_at_index(self, str_idx, cu):
        return self.debug_str_offsets.get_string_at_index(str_idx, cu)

    def get_debug_names(self):
        if self.debug_names_data and self.debug_names is None:
            self.debug_names = debug_names(self)
        return self.debug_names

    def get_apple_names(self):
        if self.apple_names_data and self.apple_names is None:
            self.apple_names = AppleHash(self.apple_names_data,
                                         self.debug_str_data)
        return self.apple_names

    def get_apple_types(self):
        if self.apple_types_data and self.apple_types is None:
            self.apple_types = AppleHash(self.apple_types_data,
                                         self.debug_str_data)
        return self.apple_types

    def get_debug_abbrev(self):
        if self.debug_abbrev is None and self.debug_abbrev_data:
            self.debug_abbrev = debug_abbrev(self.debug_abbrev_data)
        return self.debug_abbrev

    def get_dwarf_units(self):
        debug_info = self.get_debug_info()
        if debug_info:
            return debug_info.get_dwarf_units()
        return []

    def get_type_units(self):
        debug_info = self.get_debug_info()
        if debug_info:
            return debug_info.get_type_units()
        return []

    def get_debug_info(self):
        if self.debug_info is None and self.debug_info_data:
            self.debug_info = debug_info(self)
        return self.debug_info

    def get_debug_ranges(self):
        if self.debug_ranges is None and self.debug_ranges_data:
            self.debug_ranges = debug_ranges(self)
        return self.debug_ranges

    def get_debug_aranges(self):
        if self.debug_aranges is None and self.debug_aranges_data:
            self.debug_aranges = debug_aranges()
            self.debug_aranges_data.seek(0)
            self.debug_aranges.unpack(self.debug_aranges_data)
        return self.debug_aranges

    def get_debug_cu_index(self):
        if self.debug_cu_index is None and self.debug_cu_index_data:
            self.debug_cu_index = debug_index(True, self.debug_cu_index_data)
        return self.debug_cu_index

    def get_debug_tu_index(self):
        if self.debug_tu_index is None and self.debug_tu_index_data:
            self.debug_tu_index = debug_index(False, self.debug_tu_index_data)
        return self.debug_tu_index

    def get_debug_cu_tu_index_row_indexes(self):
        cu_index = self.get_debug_cu_index()
        tu_index = self.get_debug_tu_index()
        row_indexes = []
        if cu_index:
            row_indexes.extend(cu_index.get_debug_info_index())
        if tu_index:
            row_indexes.extend(tu_index.get_debug_info_index())
        # Sort by debug info offset
        row_indexes.sort()
        # import sys  # REMOVE
        # for (i, row_index) in enumerate(row_indexes):
        #     sys.stdout.write('[%5u] ' % (i))
        #     row_index.dump()
        #     print()
        return (row_indexes, cu_index, tu_index)
