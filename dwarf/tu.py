#!/usr/bin/python

# Python imports
import io
import sys

from dwarf.cu import CompileUnit
import dwarf.options


class TypeUnit(CompileUnit):
    def __init__(self, debug_info):
        CompileUnit.__init__(self, debug_info)
        self.type_signature = None
        self.type_offset = None

    def dump_header(self, f=sys.stdout, offset_adjust=0):
        f.write('%s: Type Unit: length = 0x%8.8x, version = 0x%4.4x, '
                'abbrev_offset = 0x%8.8x, addr_size = 0x%2.2x, type_signature '
                '= 0x%16.16x, type_offset = 0x%8.8x {0x%8.8x} '
                '(new TU at 0x%8.8x)\n' % (
                    dwarf.options.get_color_offset(self.offset+offset_adjust),
                    self.length, self.dwarf_info.version, self.abbrev_offset,
                    self.dwarf_info.addr_size, self.type_signature,
                    self.type_offset,
                    self.type_offset + self.offset+offset_adjust,
                    self.get_next_cu_offset() + offset_adjust))

    def __str__(self):
        output = io.StringIO()
        self.dump_header(f=output)
        return output.getvalue()

    def get_header_byte_size(self):
        cu_header_length = CompileUnit.get_header_byte_size(self)
        # Sizes below are: sizeof(type_signature) + sizeof(type_offset)
        if self.dwarf_info.dwarf_size == 8:
            return cu_header_length + 8 + 8
        else:
            return cu_header_length + 8 + 4

    def unpack(self, data):
        CompileUnit.unpack(self, data)
        self.type_signature = data.get_uint64()
        self.type_offset = data.get_uint_size(self.dwarf_info.dwarf_size)
        return self.is_valid()
