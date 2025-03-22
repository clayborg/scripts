#!/usr/bin/python

# Python imports
import bisect
import sys
import io

# Package imports
import dwarf.parse
from dwarf.ranges import AddressRange, AddressRangeList
import dwarf.options


class debug_aranges:
    '''Represents the .debug_aranges section in DWARF.'''
    def __init__(self):
        self.sets = None
        self.max_range = None

    def unpack(self, data):
        arange_sets = list()
        arange_set = Set()
        while arange_set.unpack(data):
            arange_sets.append(arange_set)
            arange_set = Set()
        self.arange_sets = sorted(arange_sets)
        if len(self.arange_sets):
            self.max_range = AddressRange(
                self.arange_sets[0].address_ranges.max_range.lo,
                self.arange_sets[-1].address_ranges.max_range.hi)

    def get_cu_offset_for_address(self, address):
        if self.max_range and self.max_range.contains(address):
            i = bisect.bisect_left(self.arange_sets, address)
            num = len(self.arange_sets)
            if i == num and num > 0:
                i = num-1
            if i < num:
                if i > 0:
                    off = self.arange_sets[i-1].get_cu_offset_for_address(
                        address)
                    if off >= 0:
                        return off
                return self.arange_sets[i].get_cu_offset_for_address(address)
        return -1

    def dump(self, f=sys.stdout):
        f.write(".debug_aranges:\n")
        for arange_set in self.arange_sets:
            arange_set.dump(f=f)
        f.write('\n')

    def __str__(self):
        output = io.StringIO()
        self.dump(f=output)
        return output.getvalue()


class Set:
    def __init__(self, dwarf_info=None):
        self.offset = 0
        self.length = 0
        if dwarf_info is None:
            self.dwarf_info = dwarf.parse.Info(addr_size=0, version=0,
                                               dwarf_size=4)
        else:
            self.dwarf_info = dwarf_info
        self.cu_offset = 0
        self.seg_size = 0
        self.address_ranges = None

    def is_valid(self):
        return (self.length > 0 and self.dwarf_info.version <= 5 and
                self.dwarf_info.addr_size > 0 and
                len(self.address_ranges) > 0)

    def get_cu_offset_for_address(self, address):
        if self.address_ranges.contains(address):
            return self.cu_offset
        return -1

    def __lt__(self, other):
        '''Provide less than comparison for bisect functions'''
        if type(other) is int:
            return self.address_ranges.max_range.lo < other
        else:
            return (self.address_ranges.max_range.lo <
                    other.address_ranges.max_range.lo)

    def dump(self, f=sys.stdout, offset_adjust=0):
        f.write('%s: length = 0x%8.8x, version = %u, cu_offset = 0x%8.8x, '
                'addr_size = %u, seg_size = %u ' % (
                    dwarf.options.get_color_offset(self.offset+offset_adjust),
                    self.length, self.dwarf_info.version, self.cu_offset,
                    self.dwarf_info.addr_size, self.seg_size))
        self.address_ranges.dump(f=f, addr_size=self.dwarf_info.addr_size)
        f.write('\n')

    def __str__(self):
        output = io.StringIO()
        self.dump(f=output)
        return output.getvalue()

    def append_range(self, low_pc, high_pc):
        if self.address_ranges is None:
            self.address_ranges = AddressRangeList()
        self.address_ranges.append(AddressRange(low_pc, high_pc))

    def finalize(self):
        if self.address_ranges is not None:
            self.address_ranges.finalize(False)

    def encode(self, encoder):
        self.offset = encoder.file.tell()
        encoder.put_uint32(0)  # unit_length, fixup later
        encoder.put_uint16(self.dwarf_info.version)
        encoder.put_uint_size(self.dwarf_info.dwarf_size, self.cu_offset)
        encoder.put_uint8(self.dwarf_info.addr_size)
        encoder.put_uint8(self.seg_size)
        # Align the first tuple in the right boundary
        encoder.align_to(self.dwarf_info.addr_size*2)
        for address_range in self.address_ranges:
            encoder.put_address(address_range.lo)
            encoder.put_address(address_range.hi - address_range.lo)
        encoder.put_address(0)
        encoder.put_address(0)
        # Fixup the zero unit_length we wrote out earlier
        end_offset = encoder.file.tell()
        unit_length = end_offset - (self.offset + 4)
        encoder.fixup_uint_size(4, unit_length, self.offset)

    def unpack(self, data):
        self.offset = data.tell()
        self.length = data.get_uint32()
        self.dwarf_info.version = data.get_uint16()
        self.cu_offset = data.get_uint32()
        self.dwarf_info.addr_size = data.get_uint8()
        self.seg_size = data.get_uint8()
        if (self.length == 0 or self.dwarf_info.version == 0 or
                self.dwarf_info.addr_size == 0):
            return False
        data.set_addr_size(self.dwarf_info.addr_size)
        self.address_ranges = AddressRangeList()

        data.align_to(self.dwarf_info.addr_size * 2)

        while 1:
            addr = data.get_address()
            size = data.get_address()
            if addr == 0 and size == 0:
                break
            self.append_range(addr, addr + size)
        self.finalize()
        return self.is_valid()
