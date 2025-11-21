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
    class Header:
        def __init__(self, data, debug_str):
            self.debug_str = debug_str
            self.data = data
            self.offset = data.tell()
            (self.length, self.offset_size) = data.get_dwarf_inital_length()
            past_length_offset = data.tell()
            self.end_offset = self.length + past_length_offset
            self.version = data.get_uint16()
            data.get_uint16()  # Skip padding
            self.str_offsets_base = data.tell()
            self.str_offsets_data = None

        def dump(self, f=sys.stdout):
            f.write(dwarf.options.get_color_offset(self.offset))
            f.write(f': Length = 0x{self.length:08x} ({self.length})')
            f.write(f', Format = DWARF{"32" if self.offset_size == 4 else "64"}')
            f.write(f', Version = {self.version}\n')

        def dump_strings(self, f=sys.stdout):
            data = self.get_str_offsets_data(0)
            max_matches = dwarf.options.get_max_matches()
            num_strings = self.get_num_string_offsets()
            limited_output = False
            if max_matches is not None and max_matches < num_strings:
                num_strings = max_matches
                limited_output = True
            if self.offset_size == 8:
                offset_format = "%#16.16x "
            else:
                offset_format = "%#8.8x "
            index_width = calculate_index_width(num_strings)
            index_format = f'[%{index_width}u] '
            for idx in range(num_strings):
                offset = data.tell()
                f.write(f'{dwarf.options.get_color_offset(offset+self.str_offsets_base)}: ')
                strp = data.get_uint_size(self.offset_size, None)
                f.write(index_format % idx)
                f.write(offset_format % (strp))
                if strp is None:
                    f.write('error: unable to extract string\n')
                    break
                else:
                    f.write(f'"{self.debug_str.get_string(strp)}"\n')
            if limited_output and max_matches:
                f.write('...\n')


        def get_num_string_offsets(self):
            return (self.end_offset - self.str_offsets_base) // self.offset_size

        def get_next_header_offset(self):
            return self.end_offset

        def get_str_offsets_data(self, seek_offset = 0):
            if self.str_offsets_data is None:
                self.data.seek(self.str_offsets_base)
                self.str_offsets_data = self.data.read_data(self.end_offset - self.str_offsets_base)
            self.str_offsets_data.seek(seek_offset)
            return self.str_offsets_data

        def get_string_at_index(self, idx):
            data = self.get_str_offsets_data(idx * self.offset_size)
            strp = data.get_uint_size(self.offset_size, None)
            if strp is None:
                raise ValueError('unable to decode string offset')
            return self.debug_str.get_string(strp)


    '''Represents the .debug_str_offsets section in DWARF.'''
    def __init__(self, data, debug_str):
        self.name = ".debug_str_offsets"
        self.data = data
        self.debug_str = debug_str
        self.max_offset = self.data.get_size()
        self.headers = []
        self.str_offsets_base_to_header = {}
        self.offset_to_header = {}
        while data.tell() < self.max_offset:
            header = debug_str_offsets.Header(data, debug_str)
            self.headers.append(header)
            self.offset_to_header[header.offset] = header
            self.str_offsets_base_to_header[header.str_offsets_base] = header
            data.seek(header.get_next_header_offset())

    def find_header_by_offset(self, offset):
        return self.offset_to_header.get(offset)

    def find_header_by_str_offsets_base(self, offset):
        return self.str_offsets_base_to_header.get(offset)

    def get_string_at_index(self, idx, cu):
        '''Get a string by index from a compile unit.'''
        header = cu.get_string_offsets_header()
        if header is None:
            raise ValueError('unable to find .debug_str_offsets header')
        return header.get_string_at_index(idx)

    def dump(self, f=sys.stdout):
        offset = 0
        f.write('%s:\n' % (self.name))
        for (i, header) in enumerate(self.headers):
            if i > 0:
                f.write('\n')
            header.dump(f=f)
            header.dump_strings(f=f)


def calculate_index_width(count):
    width = 1
    while count >= 10:
        count = count // 10
        width += 1
    return width
