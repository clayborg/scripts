#!/usr/bin/python

import sys
import dwarf.options

from dwarf.DW.AT import DW_AT


class debug_str:
    '''Represents the a string section in DWARF.'''
    def __init__(self, name, data):
        self.name = name
        self.data = data
        if data is None:
            self.max_offset = 0
        else:
            self.max_offset = self.data.get_size()
        self.strings = {}

    def get_string(self, offset):
        if offset >= self.max_offset:
            return None
        if offset in self.strings:
            return self.strings[offset]
        self.data.seek(offset)
        str = self.data.get_c_string()
        self.strings[offset] = str
        return str

    def dump(self, f=sys.stdout):
        offset = 0
        f.write('%s:\n' % (self.name))
        while offset < self.max_offset:
            f.write(dwarf.options.get_color_offset(offset))
            str = self.get_string(offset)
            f.write(': %s\n' % (str))
            offset += len(str) + 1


class debug_str_offsets:
    '''Represents the .debug_str_offsets section in DWARF.'''
    def __init__(self, data, debug_str):
        self.data = data
        self.debug_str = debug_str
        self.max_offset = self.data.get_size()
        self.strings = {}

    def get_string_at_index(self, idx, cu):
        '''Get a string by index from a compile unit.'''
        offset = cu.get_str_offsets_base() + idx * cu.dwarf_info.dwarf_size
        self.data.push_offset_and_seek(offset)
        strp = self.data.get_offset()
        self.data.pop_offset_and_seek()
        return self.debug_str.get_string(strp)
