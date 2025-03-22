# Python imports
import sys
import time

# Package imports
import dwarf
from dwarf.DW.SECT import DW_SECT


class Row:
    def __init__(self):
        self.section_infos = []

    def __repr__(self):
        s = ''
        for section_info in self.section_infos:
            if s:
                s += ' '
            s += str(section_info)
        return s

    def __str__(self):
        return self.__repr__()


class SectionContribution:
    def __init__(self, offset):
        self.offset = offset
        self.length = None

    def get_contribution(self, dwp_data):
        dwp_data.push_offset_and_seek(self.offset)
        data = dwp_data.read_data(self.length)
        dwp_data.pop_offset_and_seek()
        return data

    def __repr__(self):
        if self.length is None:
            return '[%#8.8x-          )' % (self.offset)
        return '[%#8.8x-%#8.8x)' % (self.offset, self.offset+self.length)

    def __str__(self):
        return self.__repr__()


class RowIndex:
    '''
        A class that refers to a row within the .debug_cu_index or
        .debug_tu_index sections. This can be sorted and returned to allow
        easy iteration over all DWARF units in a .dwp file so we can create
        DWARF contexts for each one.
    '''
    def __init__(self, offset, row_idx, is_cu):
        self.offset = offset  # .debug_info offset
        self.row_idx = row_idx # Row index in the .debug_cu_index or .debug_tu_index
        self.is_cu = is_cu  # If true, this is for .debug_cu_index, else for .debug_tu_index

    def dump(self, f=sys.stdout):
        f.write('offset=%#8.8x, row_idx=%5u, is_cu=%s' % (self.offset, self.row_idx, str(self.is_cu)))

    def __eq__(self, rhs):
        return self.offset == rhs.offset

    def __ne__(self, rhs):
        return self.offset != rhs.offset

    def __le__(self, rhs):
        return self.offset <= rhs.offset

    def __lt__(self, rhs):
        return self.offset < rhs.offset

    def __ge__(self, rhs):
        return self.offset >= rhs.offset

    def __gt__(self, rhs):
        return self.offset > rhs.offset


class debug_index:
    '''A class that parses both .debug_cu_index and .debug_tu_index.'''
    def __init__(self, is_cu, data):
        self.is_cu = is_cu
        self.data = data
        self.version = data.get_uint16()
        data.get_uint16()  # Skip padding
        self.section_count = data.get_uint32()
        self.unit_count = data.get_uint32()
        self.bucket_count = data.get_uint32()
        self.column_section_ids = None
        self.bucket_hashes_offset = data.tell()
        self.bucket_indexes_offset = self.bucket_hashes_offset + (8 * self.bucket_count)
        self.section_ids_offset = self.bucket_indexes_offset + (4 * self.bucket_count)
        self.row_section_offsets_offset = self.section_ids_offset + (self.section_count * 4)
        self.row_section_lengths_offset = self.row_section_offsets_offset + (self.unit_count * 4 * self.section_count)

    def get_bucket_hash(self, index):
        self.data.seek(self.bucket_hashes_offset + index * 8)
        return self.data.get_uint64()

    def get_row_index(self, index):
        self.data.seek(self.bucket_indexes_offset + index * 4)
        return self.data.get_uint32()

    def get_section_ids(self):
        if self.column_section_ids is None:
            self.column_section_ids = []
            self.data.seek(self.section_ids_offset)
            for i in range(self.section_count):
                self.column_section_ids.append(DW_SECT(self.data.get_uint32()))
        return self.column_section_ids

    def get_row(self, row_idx):
        if row_idx <= 0:
            return None  # Zero is an invalid row index, they are 1 based.
        index = row_idx - 1
        # Read the CU/TU start offsets for each section corresponding to
        # the section ids in self.column_section_ids
        self.data.seek(self.row_section_offsets_offset + (index * 4 * self.section_count))
        row = Row()
        for s in range(self.section_count):
            row.section_infos.append(SectionContribution(self.data.get_uint32()))

        # Read the CU/TU end offsets for each section corresponding to
        # the section ids in self.column_section_ids
        self.data.seek(self.row_section_lengths_offset + (index * 4 * self.section_count))
        for s in range(self.section_count):
            row.section_infos[s].length = self.data.get_uint32()
        return row

    def get_debug_info_index(self):
        # First find the section info index of the .debug_info section (DW_SECT_INFO)
        info_idx = None
        for (idx, sect_id) in enumerate(self.get_section_ids()):
            if sect_id.value == DW_SECT.INFO:
                info_idx = idx
                break
        infos = []
        if info_idx == None:
            return infos
        for (row_idx, row) in enumerate(self.rows):
            infos.append(RowIndex(row.section_infos[info_idx].offset, row_idx, self.is_cu))
        return infos

    def dump_header(self, show_index, index_label, show_bucket, f=sys.stdout):
        if show_index:
            f.write('%-10s ' % (index_label))
        if show_bucket:
            if self.is_cu:
                f.write('RowIdx   DWO ID             ')
            else:
                f.write('RowIdx   Type signature     ')
        section_ids = self.get_section_ids()
        for sect_id in section_ids:
            f.write("%-23s " % (str(sect_id)))
        f.write('\n')
        if show_index:
            f.write('---------- ')
        if show_bucket:
            f.write('-------- ------------------ ')
        for sect_id in section_ids:
            f.write('----------------------- ')
        f.write('\n')

    def dump_hashes(self, hashes, f):
        printed_header = False
        for hash in hashes:
            row_idx = self.get_row_index_for_hash(hash)
            row = self.get_row(row_idx)
            if row:
                if not printed_header:
                    self.dump_header(False, None, True, f)
                    printed_header = True
                f.write('%8u %#16.16x ' % (row_idx, hash))
                f.write(str(row))
                f.write('\n')
            else:
                f.write('error: %s %#16.16x not found in .debug_%su_index' % (
                        'DWO id' if self.is_cu else 'type signature',
                        'c' if self.is_cu else 't',))

    def dump(self, options=None, f=sys.stdout):
        if options and options.verbose:
            for bucket_idx in range(self.bucket_count):
                row_idx = self.get_row_index(bucket_idx)
                if row_idx == 0:
                    f.write('bucket[%u] = <empty>\n' % (bucket_idx))
                else:
                    hash = self.get_bucket_hash(bucket_idx)
                    f.write('bucket[%u] = %#16.16x row = %u\n' % (bucket_idx, hash, row_idx))

            self.dump_header(True, "Row Index", False, f=f)
            for row_idx in range(1, self.unit_count+1):
                row = self.get_row(row_idx)
                f.write('[%8u] ' % (row_idx))
                f.write(str(row))
                f.write('\n')
        else:
            self.dump_header(True, "Bucket", True, f)
            for i in range(self.bucket_count):
            # for (i, bucket) in enumerate(self.buckets):
                row_idx = self.get_row_index(i)
                if row_idx == 0:
                    continue
                bucket_hash = self.get_bucket_hash(i)
                f.write('[%8u] %8u %#16.16x ' % (i, row_idx, bucket_hash))
                row = self.get_row(row_idx)
                f.write(str(row))
                f.write('\n')

    def handle_options(self, options, f):
        if self.is_cu:
            # .debug_cu_index
            if options.dwo_ids:
                self.dump_hashes(options.dwo_ids, f)
                return
        else:
            # .debug_tu_index
            if options.type_sigs:
                self.dump_hashes(options.type_sigs, f)
                return
        # Dump entire table
        self.dump(options=options, f=f)

    def get_row_index_for_hash(self, hash):
        mask = self.bucket_count - 1
        H = hash & mask
        HP = ((hash >> 32) & mask) | 1
        # The spec says "while 0 is a valid hash value, the row index in a used
        # slot will always be non-zero". Loop until we find a match or an empty
        # slot.
        while self.get_bucket_hash(H) != hash and self.get_row_index(H) != 0:
            H = (H + HP) & mask

        # If the slot is empty, we don't care whether the signature matches (it
        # could be zero and still match the zeros in the empty slot).
        return self.get_row_index(H)

    def get_row_for_hash(self, hash):
        row_idx = self.get_row_index_for_hash(hash)
        return self.get_row(row_idx)
