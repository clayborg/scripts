#!/usr/bin/python

# Python imports
import bisect
import sys
import io

# Package imports
from dwarf.defines import UINT32_MAX, UINT64_MAX
from dwarf.ranges import AddressRange, AddressRangeList


class debug_ranges:
    def __init__(self, dwarf):
        self.dwarf = dwarf
        self.ranges = {}

    def get_debug_ranges_at_offset(self, cu, offset):
        if offset in self.ranges:
            return self.ranges[offset]
        ranges = AddressRangeList()
        addr_size = cu.dwarf_info.addr_size
        data = self.dwarf.debug_ranges_data
        if data:
            data.set_addr_size(addr_size)
            base_address = cu.get_base_address()
            data.seek(offset)
            while 1:
                begin = data.get_address()
                end = data.get_address()
                if begin == 0 and end == 0:
                    ranges.finalize(False)
                    r = Ranges(cu, offset, ranges)
                    self.ranges[offset] = r
                    return r
                if addr_size == 4 and begin == UINT32_MAX:
                    base_address = end
                elif addr_size == 8 and begin == UINT64_MAX:
                    base_address = end
                else:
                    ranges.append(AddressRange(begin + base_address,
                                               end + base_address))
        return None


class Ranges:
    def __init__(self, cu, offset, ranges):
        self.offset = offset
        self.cu = cu
        self.ranges = ranges

    def get_min_address(self):
        if self.ranges:
            return self.ranges.get_min_address()
        return -1

    def contains(self, address):
        return not self.lookup_address(address) is None

    def lookup_address(self, address):
        i = bisect.bisect_left(self.ranges, address)
        n = len(self.ranges)
        if i == n and n > 0:
            i = n-1
        if i < n:
            if i > 0 and self.ranges[i-1].contains(address):
                return self.ranges[i-1]
            elif self.ranges[i].contains(address):
                return self.ranges[i]
        return None

    def dump(self, indent='', f=sys.stdout, flat=False):
        if flat:
            if self.offset >= 0:
                f.write('0x%8.8x:' % (self.offset))
            for r in self.ranges:
                f.write(' [%#x-%#x)' % (r.lo, r.hi))
        else:
            if self.offset >= 0:
                f.write('0x%8.8x\n' % (self.offset))
            for r in self.ranges:
                f.write('%s%s\n' % (indent, r))

    def __str__(self):
        output = io.StringIO()
        self.dump(indent='', f=output, flat=True)
        return output.getvalue()
