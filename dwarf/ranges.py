#!/usr/bin/python

# Python imports
import bisect
import sys
import copy
import io


class AddressRange:
    def __init__(self, lo, hi):
        self.lo = lo
        self.hi = hi

    def dump(self, f=sys.stdout, addr_size=8):
        if self.lo < self.hi:
            if addr_size == 8:
                f.write('[%#16.16x - %#16.16x)' % (self.lo, self.hi))
            elif addr_size == 4:
                f.write('[%#8.8x - %#8.8x)' % (self.lo, self.hi))
            elif addr_size == 2:
                f.write('[%#4.4x - %#4.4x)' % (self.lo, self.hi))
            else:
                f.write('[%#x - %#x)' % (self.lo, self.hi))
        else:
            if addr_size == 8:
                f.write('[%#16.16x                     )' % (self.lo))
            elif addr_size == 4:
                f.write('[%#8.8x             )' % (self.lo))
            elif addr_size == 2:
                f.write('[%#4.4x             )' % (self.lo))
            else:
                f.write('[%#x )' % (self.lo))

    def intersects(self, other):
        if self.size() == 0:
            return False
        if other.size() == 0:
            return False
        return self.lo < other.hi and self.hi > other.lo

    def __str__(self):
        if self.lo < self.hi:
            return '[0x%16.16x - 0x%16.16x)' % (self.lo, self.hi)
        else:
            return '[0x%16.16x                     )' % (self.lo)

    def __eq__(self, other):
        return self.lo == other.lo and self.hi == other.hi

    def __ne__(self, other):
        return self.lo != other.lo or self.hi != other.hi

    def __lt__(self, other):
        if type(other) is int:
            return self.lo < other
        else:
            if self.lo < other.lo:
                return True
            else:
                return self.hi < other.hi

    def __le__(self, other):
        if self.lo <= other.lo:
            return True
        else:
            return self.hi <= other.hi

    def __ge__(self, other):
        if self.lo >= other.lo:
            return True
        else:
            return self.hi >= other.hi

    def contains(self, value):
        if isinstance(value, AddressRange):
            if not self.contains(value.lo):
                return False
            if value.lo < value.hi:
                return self.contains(value.hi-1)
            return True
        else:
            return self.lo <= value and value < self.hi

    def contains_or_is(self, value):
        if self.size() == 0:
            return value == self.lo
        return self.contain(value)

    def size(self):
        return self.hi - self.lo

    def set_size(self, size):
        self.hi = self.lo + size


class AddressRangeList:
    def __init__(self):
        self.ranges = []
        self.max_range = None

    def __eq__(self, other):
        return self.ranges == other.ranges

    def __ne__(self, other):
        return self.ranges != other.ranges

    def __getitem__(self, key):
        return self.ranges[key]

    def __len__(self):
        return len(self.ranges)

    def __iter__(self):
        return iter(self.ranges)

    def contains(self, address):
        return not self.get_range_for_address(address) is None

    def get_min_address(self):
        if self.max_range is None:
            return -1
        else:
            return self.max_range.lo

    def encode(self, encoder):
        offset = encoder.file.tell()
        for range in self.ranges:
            encoder.put_address(range.lo)
            encoder.put_address(range.hi)
        encoder.put_address(0)
        encoder.put_address(0)
        return offset

    def get_range_for_address(self, address):
        if self.max_range and self.max_range.contains(address):
            i = bisect.bisect_left(self.ranges, address)
            num = len(self.ranges)
            if i == num and num > 0:
                i = num-1
            if i < num:
                if i > 0 and self.ranges[i-1].contains(address):
                    return self.ranges[i-1]
                elif self.ranges[i].contains(address):
                    return self.ranges[i]
        if self.max_range is None and len(self.ranges) > 0:
            raise ValueError('not finalized')
        return None

    def any_range_intersects(self, other_range):
        for range in self.ranges:
            if range.intersects(other_range):
                return True
        return False

    def append(self, value):
        if isinstance(value, AddressRange):
            self.ranges.append(copy.copy(value))
        elif isinstance(value, AddressRangeList):
            for range in value.ranges:
                self.ranges.append(copy.copy(range))
        else:
            raise ValueError

    def finalize(self, compress=True):
        num_ranges = len(self.ranges)
        if num_ranges > 1:
            sorted_ranges = sorted(self.ranges)
            if compress:
                compressed_ranges = []
                for range in sorted_ranges:
                    if (len(compressed_ranges) > 0 and
                            compressed_ranges[-1].hi == range.lo):
                        compressed_ranges[-1].hi = range.hi
                    else:
                        compressed_ranges.append(range)
                self.ranges = compressed_ranges
            else:
                self.ranges = sorted_ranges
        if len(self.ranges):
            self.max_range = AddressRange(self.ranges[0].lo,
                                          self.ranges[-1].hi)

    def dump(self, f=sys.stdout, addr_size=8):
        for (i, r) in enumerate(self.ranges):
            if i > 0:
                f.write(' ')
            r.dump(f=f, addr_size=addr_size)

    def __str__(self):
        output = io.StringIO()
        self.dump(f=output)
        return output.getvalue()


class DIERanges:
    class Range(AddressRange):
        def __init__(self, lo, hi, die):
            AddressRange.__init__(self, lo, hi)
            self.die = die

        def __str__(self):
            return '0x%8.8x [0x%16.16x - 0x%16.16x) %s' % (
                self.die.offset, self.lo, self.hi, self.die.get_display_name())

    def __init__(self):
        self.ranges = []

    def append_die_ranges(self, die, address_range_list):
        for address_range in address_range_list:
            self.ranges.append(DIERanges.Range(
                address_range.lo, address_range.hi, die))

    def append_die_range(self, die, address_range):
        self.ranges.append(DIERanges.Range(
            address_range.lo, address_range.hi, die))

    def lookup_die_by_address(self, address):
        i = bisect.bisect_left(self.ranges, address)
        num = len(self.ranges)
        if i == num and num > 0:
            i = num-1
        if i < num:
            if i > 0 and self.ranges[i-1].contains(address):
                return self.ranges[i-1].die
            elif self.ranges[i].contains(address):
                return self.ranges[i].die
        return None

    def sort(self):
        self.ranges = sorted(self.ranges)

    def dump(self, indent='', f=sys.stdout):
        f.write("DIE OFFSET ADDRESS RANGE                             NAME\n")
        f.write("---------- ----------------------------------------- ------------------\n")
        for range in self.ranges:
            f.write('%s%s\n' % (indent, str(range).encode('utf8')))

    def __str__(self):
        output = io.StringIO()
        self.dump(indent='', f=output)
        return output.getvalue()
