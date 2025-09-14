#!/usr/bin/python

# Local imports
from enum import IntEnum

# Python imports
import bisect
import copy
import io
import os
import sys

# Package imports
from dwarf.ranges import AddressRange
from dwarf.DW.AT import DW_AT
from dwarf.DW.LNCT import DW_LNCT
from dwarf.DW.FORM import DW_FORM
from dwarf.defines import UINT64_MAX, is_string

import dwarf.debug.ranges


class DW_LNS(IntEnum):
    copy = 0x01
    advance_pc = 0x02
    advance_line = 0x03
    set_file = 0x04
    set_column = 0x05
    negate_stmt = 0x06
    set_basic_block = 0x07
    const_add_pc = 0x08
    fixed_advance_pc = 0x09
    set_prologue_end = 0x0A
    set_epilogue_begin = 0x0B
    set_isa = 0x0C

    @classmethod
    def max_width(cls):
        return 25


class DW_LNE(IntEnum):
    end_sequence = 0x01
    set_address = 0x02
    define_file = 0x03
    set_discriminator = 0x04
    lo_user = 0x80
    hi_user = 0xFF

    def __str__(self):
        return 'DW_LNE_' + self.name

    @classmethod
    def max_width(cls):
        return 24


class FileAttribute:
    def __init__(self, lnct, form):
        self.lnct = DW_LNCT(lnct)
        self.form = DW_FORM(form)

    def __repr__(self):
        return '%s %s' % (self.lnct, self.form)

    def __str__(self):
        return self.__repr__()


class debug_line:
    '''Represents the .debug_line section in DWARF.'''
    def __init__(self, dwarf, data, offset, addr_size):
        self.dwarf = dwarf
        self.data = data
        self.offset = offset
        self.addr_size = addr_size
        self.prologue = None
        self.rows = None
        self.sequence_ranges = None
        self.row_arange = AddressRange(sys.maxsize, 0)

    def __repr__(self):
        return '.debug_line[%#8.8x]' % (self.offset)

    def get_sequence_ranges(self):
        if self.sequence_ranges is None:
            unsorted_sequence_ranges = []
            rows = self.get_rows()
            sequence_start_idx = 0
            for (i, row) in enumerate(rows):
                if row.end_sequence:
                    if sequence_start_idx >= 0:
                        unsorted_sequence_ranges.append(
                            SequenceRange(rows[sequence_start_idx].addr,
                                          row.addr, sequence_start_idx, i))
                    sequence_start_idx = -1
                elif sequence_start_idx == -1:
                    sequence_start_idx = i
            self.sequence_ranges = sorted(unsorted_sequence_ranges)
        return self.sequence_ranges

    def lookup_sequence_range(self, address):
        sequence_ranges = self.get_sequence_ranges()
        i = bisect.bisect_left(sequence_ranges, address)
        n = len(sequence_ranges)
        if i == n and n > 0:
            i = n-1
        if i < n:
            if i > 0 and sequence_ranges[i-1].contains(address):
                return sequence_ranges[i-1]
            elif sequence_ranges[i].contains(address):
                return sequence_ranges[i]
        return None

    def lookup_row_index_in_sequence(self, sequence, addr):
        rows = self.get_rows()
        i = bisect.bisect_left(rows, addr, sequence.start_idx,
                               sequence.end_idx)
        n = len(rows)
        if i == n and n > 0:
            i = n-1
        if i < len(rows):
            while (i > 0 and not rows[i-1].end_sequence and
                   rows[i-1].addr == addr):
                i -= 1
            if rows[i].addr <= addr:
                return i
        return -1

    def lookup_row_in_sequence_range(self, sequence, address):
        row_idx = self.lookup_row_index_in_sequence(sequence, address)
        if row_idx >= 0:
            return self.get_rows()[row_idx]
        return None

    def get_rows_for_range(self, arange):
        rows = self.get_rows()
        matching_rows = []
        if self.row_arange.contains(arange.lo):
            sequence = self.lookup_sequence_range(arange.lo)
            if sequence:
                row_idx = self.lookup_row_index_in_sequence(sequence,
                                                            arange.lo)
                if row_idx >= 0:
                    rows = self.get_rows()
                    for i in range(row_idx, sequence.end_idx+1):
                        row = rows[i]
                        if arange.contains(row.addr):
                            matching_rows.append(row)
                        if row.addr >= arange.hi:
                            break
        return matching_rows

    def lookup_address(self, address):
        self.get_rows()
        if self.row_arange.contains(address):
            sequence = self.lookup_sequence_range(address)
            if sequence:
                return self.lookup_row_in_sequence_range(sequence, address)
        return None

    def get_file(self, file_num):
        prologue = self.get_prologue()
        if prologue and prologue.is_valid():
            return prologue.get_file(file_num)
        return ''

    def get_prologue(self):
        if self.prologue is None:
            if self.data:
                self.data.push_offset_and_seek(self.offset)
                self.prologue = Prologue()
                self.prologue.unpack(self.dwarf, self.data)
                self.data.pop_offset_and_seek()
        return self.prologue

    def get_rows(self, debug=False):
        if self.rows is None:
            prologue = self.get_prologue()
            if prologue is None:
                return None
            self.rows = []
            if not prologue.is_valid():
                return self.rows
            data = self.data
            offset = prologue.get_rows_offset()
            if offset > 0:
                end_offset = prologue.get_rows_end_offset()
                data.seek(offset)
                row = Row(prologue)
                data.set_addr_size(self.addr_size)
                while data.tell() < end_offset:
                    opcode = data.get_uint8()
                    if debug:
                        sys.stdout.write('%s ' % (DW_LNS(opcode)))
                    if opcode == 0:
                        # Extended opcodes always start with zero followed
                        # by uleb128 length to they can be skipped
                        length = data.get_uleb128()
                        dw_lne = data.get_uint8()
                        if debug:
                            sys.stdout.write('%s ' % (DW_LNE(dw_lne)))
                        if dw_lne == DW_LNE.end_sequence:
                            row.end_sequence = True
                            self.rows.append(copy.copy(row))
                            # Keep up with the max range for the rows
                            if row.addr is not None and self.row_arange.hi < row.addr:
                                self.row_arange.hi = row.addr
                            if debug:
                                print('')
                                row.dump(prologue)
                            row = Row(prologue)
                        elif dw_lne == DW_LNE.set_address:
                            row.addr = data.get_address()
                            if debug:
                                sys.stdout.write('(0x%16.16x)' %
                                                 (row.addr))
                        elif dw_lne == DW_LNE.define_file:
                            file_entry = File()
                            file_entry.unpack(data)
                            if debug:
                                file_entry.dump(len(prologue.files))
                            prologue.files.append(file_entry)
                        elif dw_lne == DW_LNE.set_discriminator:
                            # We don't use the discriminator, so just
                            # parse it and toss it
                            discriminator = data.get_uleb128()
                            if debug:
                                sys.stdout.write('(0x%x)' % (discriminator))
                        else:
                            # Skip unknown extended opcode
                            data.seek(data.tell() + length)
                    elif opcode < prologue.opcode_base:
                        if opcode == DW_LNS.copy:
                            self.rows.append(copy.copy(row))
                            if row.addr < self.row_arange.lo:
                                self.row_arange.lo = row.addr
                            if debug:
                                print('')
                                row.dump(prologue)
                            row.post_append()
                        elif opcode == DW_LNS.advance_pc:
                            pc_offset = data.get_uleb128()
                            if debug:
                                sys.stdout.write('(%u)' % (pc_offset))
                            row.addr += pc_offset
                        elif opcode == DW_LNS.advance_line:
                            line_offset = data.get_sleb128()
                            if debug:
                                sys.stdout.write('(%i)' % (line_offset))
                            row.line += line_offset
                        elif opcode == DW_LNS.set_file:
                            row.file = data.get_uleb128()
                            if debug:
                                sys.stdout.write('(%u)' % (row.file))
                        elif opcode == DW_LNS.set_column:
                            row.column = data.get_uleb128()
                            if debug:
                                sys.stdout.write('(%u)' % (row.column))
                        elif opcode == DW_LNS.negate_stmt:
                            row.is_stmt = not row.is_stmt
                        elif opcode == DW_LNS.set_basic_block:
                            row.basic_block = True
                        elif opcode == DW_LNS.const_add_pc:
                            adjust_opcode = 255 - prologue.opcode_base
                            addr_units = adjust_opcode // prologue.line_range
                            addr_offset = addr_units * prologue.min_inst_length
                            if debug:
                                sys.stdout.write('(%u)' % (addr_offset))
                            row.addr += addr_offset
                        elif opcode == DW_LNS.fixed_advance_pc:
                            pc_offset = data.get_uint16()
                            if debug:
                                sys.stdout.write('(%u)' % (pc_offset))
                            row.addr += pc_offset
                        elif opcode == DW_LNS.set_prologue_end:
                            row.prologue_end = True
                        elif opcode == DW_LNS.set_epilogue_begin:
                            row.epilogue_begin = True
                        elif opcode == DW_LNS.set_isa:
                            row.isa = data.get_uleb128()
                            if debug:
                                sys.stdout.write('(%u)' % (row.isa))
                        else:
                            print('error: unhandled DW_LNS value %u' %
                                  (opcode))
                    else:
                        adjust_opcode = opcode - prologue.opcode_base
                        addr_units = adjust_opcode // prologue.line_range
                        line_units = adjust_opcode % prologue.line_range
                        addr_offset = addr_units * prologue.min_inst_length
                        line_offset = prologue.line_base + line_units
                        if debug:
                            sys.stdout.write('0x%2.2x address += %u, '
                                             'line += %d' % (opcode,
                                                             addr_offset,
                                                             line_offset))
                        row.line += line_offset
                        row.addr += addr_offset
                        self.rows.append(copy.copy(row))
                        if row.addr < self.row_arange.lo:
                            self.row_arange.lo = row.addr
                        if debug:
                            print('')
                            row.dump(prologue)
                        row.post_append()
                    if debug:
                        print('')
        return self.rows

    def dump(self, verbose=False, f=sys.stdout):
        prologue = self.get_prologue()
        if prologue is None:
            return
        f.write(".debug_line[%#8.8x]:\n" % (self.offset))
        colorizer = dwarf.options.get_colorizer()
        prologue.dump(verbose=verbose, f=f)
        rows = self.get_rows()
        if rows:
            f.write('Address            Line   File\n')
            f.write('------------------ ------ ----------------------------\n')
            prev_file = -1
            prev_row = None
            for row in rows:
                if verbose:
                    row.dump(prologue, f=f)
                    f.write('\n')
                else:
                    last_row_same_addr = (prev_row and
                                          prev_row.addr == row.addr)
                    if last_row_same_addr:
                        f.write(colorizer.faint())
                    f.write('%#16.16x' % (row.addr))
                    if last_row_same_addr:
                        f.write(colorizer.reset())
                    f.write(' %6u' % (row.line))
                    # Only print out the file name if the file if it changed.
                    if row.file != prev_file:
                        prev_file = row.file
                        f.write(' %s' % (prologue.get_file(row.file)))
                    f.write('\n')
                if row.end_sequence:
                    f.write('\n')
                    prev_file = -1
                    prev_row = None
                else:
                    prev_row = row
        f.write('\n')

    def __str__(self):
        output = io.StringIO()
        self.dump(True, output)
        return output.getvalue()


class Row:
    def __init__(self, prologue):
        self.addr = None
        self.file = 1
        self.line = 1
        self.column = 0
        self.is_stmt = prologue.default_is_stmt
        self.basic_block = False
        self.end_sequence = False
        self.prologue_end = False
        self.epilogue_begin = False
        self.isa = 0

    def encode(self, debug_line, prev=None):
        if prev and not prev.end_sequence:
            # If our address changed, advance it in the state machine
            if self.addr > prev.addr:
                debug_line.put_uint8(DW_LNS.advance_pc)
                debug_line.put_uleb128(self.addr - prev.addr)
            elif self.addr < prev.addr:
                sys.stdout.write('warning: row has address (%#x) that is '
                                 'less than previous row (%#x)' %
                                 (self.addr, prev.addr))
                # Pretend we have unsigned 32 or 64 bit overflow
                positive_delta = prev.addr - self.addr
                debug_line.put_uint8(DW_LNS.advance_pc)
                debug_line.put_uleb128(UINT64_MAX - positive_delta + 1)
            # If our file changed, set it
            if self.file != prev.file:
                debug_line.put_uint8(DW_LNS.set_file)
                debug_line.put_uleb128(self.file)
            # If our line number changed, advance it in the state machine
            line_delta = self.line - prev.line
            if line_delta != 0:
                debug_line.put_uint8(DW_LNS.advance_line)
                debug_line.put_sleb128(line_delta)
            # If our column changed, set it
            if self.column != prev.column:
                debug_line.put_uint8(DW_LNS.set_column)
                debug_line.put_uleb128(self.column)
        else:
            # Extended opcode
            debug_line.put_uint8(0)
            # Extended opcode length including DW_LNE_XXX
            debug_line.put_uleb128(1 + debug_line.addr_size)
            debug_line.put_uint8(DW_LNE.set_address)
            debug_line.put_address(self.addr)
            if self.file > 1:
                debug_line.put_uint8(DW_LNS.set_file)
                debug_line.put_uleb128(self.file)
            if self.line > 1:
                debug_line.put_uint8(DW_LNS.advance_line)
                debug_line.put_sleb128(self.line - 1)
            if self.column > 0:
                debug_line.put_uint8(DW_LNS.set_column)
                debug_line.put_uleb128(self.column)
            if self.isa != 0:
                debug_line.put_uint8(DW_LNS.set_isa)
                debug_line.put_uleb128(self.isa)
        if self.basic_block:
            debug_line.put_uint8(DW_LNS.set_basic_block)
        if self.prologue_end:
            debug_line.put_uint8(DW_LNS.set_prologue_end)
        if self.epilogue_begin:
            debug_line.put_uint8(DW_LNS.set_epilogue_begin)
        if self.end_sequence:
            # Extended opcode
            debug_line.put_uint8(0)
            # Extended opcode length including DW_LNE_XXX
            debug_line.put_uleb128(1)
            debug_line.put_uint8(DW_LNE.end_sequence)
        else:
            debug_line.put_uint8(DW_LNS.copy)

    def __lt__(self, other):
        if type(other) is int:
            return self.addr < other
        return self.addr < other.addr

    def post_append(self):
        # Called after a row is appended to the matrix
        self.basic_block = False
        self.prologue_end = False
        self.epilogue_begin = False
        self.addr = self.addr

    def dump_lookup_results(self, prologue, f=sys.stdout):
        filepath = prologue.get_file(self.file)
        f.write('.debug_line[0x%8.8x]: %#x %s:%u' % (prologue.offset,
                                                     self.addr,
                                                     filepath,
                                                     self.line))

    def dump(self, prologue, f=sys.stdout):
        f.write('0x%16.16x %5u %5u %5u' % (self.addr, self.file, self.line,
                                           self.column))
        if self.is_stmt:
            f.write(' is_stmt')
        if self.basic_block:
            f.write(' basic_block')
        if self.end_sequence:
            f.write(' end_sequence')
        if self.prologue_end:
            f.write(' prologue_end')
        if self.epilogue_begin:
            f.write(' epilogue_begin')
        if self.isa:
            f.write(' isa = %u' % (self.isa))

    def __str__(self):
        output = io.StringIO()
        self.dump(True, output)
        return output.getvalue()


class File:
    file_formats_v4 = [
        FileAttribute(DW_LNCT.path, DW_FORM.string),
        FileAttribute(DW_LNCT.directory_index, DW_FORM.udata),
        FileAttribute(DW_LNCT.timestamp, DW_FORM.udata),
        FileAttribute(DW_LNCT.size, DW_FORM.udata),
    ]
    dir_formats_v4 = [ FileAttribute(DW_LNCT.path, DW_FORM.string) ]

    @classmethod
    def create_file_with_path(cls, fullpath, prologue):
        if prologue.version >= 5:
            if prologue.file_entry_format:
                return cls(None, None, prologue, prologue.file_entry_format, fullpath)
            raise ValueError('DWARF5 line table with no file entry format')
        else:
            result = cls(None, None, prologue, cls.file_formats_v4, fullpath)
            # For DWARF4, we need to terminate when we have an empty path
            if result.info[DW_LNCT.path] == '':
                return None
            return result

    @classmethod
    def create_file(cls, dwarf, data, prologue):
        if prologue.version >= 5:
            if prologue.file_entry_format:
                return cls(dwarf, data, prologue, prologue.file_entry_format)
            raise ValueError('DWARF5 line table with no file entry format')
        else:
            result = cls(dwarf, data, prologue, cls.file_formats_v4)
            # For DWARF4, we need to terminate when we have an empty path
            if result.info[DW_LNCT.path] == '':
                return None
            return result

    @classmethod
    def create_dir(cls, dwarf, data, prologue):
        if prologue.version >= 5:
            if prologue.dir_entry_format:
                return cls(dwarf, data, prologue, prologue.dir_entry_format)
            raise ValueError('DWARF5 line table with no directory entry format')
        else:
            result = cls(dwarf, data, prologue, cls.dir_formats_v4)
            # Stop parsing any attributes if we run into an empty path for
            # DWARF 4 and earlier DWARF versions.
            if result.info[DW_LNCT.path] == '':
                return None
            return result

    def __init__(self, dwarf, data, prologue, formats, fullpath = None):
        self.path = fullpath
        self.prologue = prologue
        self.info = {}
        if data:
            for format in formats:
                (value, value_raw) = format.form.extract_value(data, None, dwarf)
                self.info[format.lnct] = value
                # Stop parsing any attributes if we run into an empty path for
                # DWARF 4 and earlier DWARF versions.
                if prologue.version < 5 and format.lnct == DW_LNCT.path and not value:
                    break
        else:
            for format in formats:
                if format.lnct == DW_LNCT.path:
                    self.info[format.lnct] = fullpath
                else:
                    self.info[format.lnct] = 0

    def get_directory(self):
        if DW_LNCT.directory_index in self.info:
            dir_idx = self.info[DW_LNCT.directory_index]
            if dir_idx == 0 and self.prologue.version < 5:
                return None
            idx_adjust = 1 if self.prologue.version < 5 else 0
            return self.prologue.directories[dir_idx - idx_adjust]
        return None

    def get_path(self):
        if self.path is None:
            self.path = self.info[DW_LNCT.path]
            if not self.path.startswith('/'):
                dir = self.get_directory()
                if dir:
                    self.path = os.path.join(dir.get_path(), self.path)
            self.path = os.path.normpath(self.path)
        return self.path

    def dump(self, verbose, f=sys.stdout):
        if not verbose:
            f.write('"%s"' % (self.get_path()))
            return

        f.write('{ ')
        first = True
        for lnct in self.info:
            if first:
                first = False
            else:
                f.write(', ')
            value = self.info[lnct]
            attr_name = lnct.name
            if is_string(value):
                f.write('%s="%s"' % (attr_name, value))
            else:
                f.write('%s=%s' % (attr_name, str(value)))
        f.write(' }')

    def encode(self, version, debug_line):
        if version <= 4:
            for format in File.file_formats_v4:
                value = self.info[format.lnct]
                if format.lnct == DW_LNCT.path:
                    debug_line.put_c_string(value)
                else:
                    debug_line.put_uleb128(value)

        else:
            raise ValueError("DWARF 5 line table generation isn't supported")

class Prologue:
    def __init__(self):
        self.offset = 0
        self.total_length = 0
        self.version = 0
        self.prologue_length = 0
        self.min_inst_length = 0
        self.default_is_stmt = 0
        self.line_base = 0
        self.line_range = 0
        self.opcode_base = 0
        self.opcode_lengths = None
        self.directories = None
        self.files = None
        self.rows_offset = 0

    def generate_init(self):
        '''Initialize this class for use with the DWARF generator'''
        self.version = 2
        self.min_inst_length = 1
        self.default_is_stmt = 1
        self.line_base = -5
        self.line_range = 14
        self.opcode_base = 0xd
        self.opcode_lengths = [0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]
        self.directories = []
        self.files = []

    def add_directory(self, dir):
        '''Function used with DWARF generation to add a directory to the
            line table prologue'''
        if len(dir) == 0:
            return 0
        if dir not in self.directories:
            self.directories.append(dir)
        return self.directories.index(dir) + 1

    def add_file(self, fullpath):
        '''Function used with DWARF generation to add a file to the
            line table prologue'''
        (dir, basename) = os.path.split(fullpath)
        dir_idx = self.add_directory(dir)
        for (i, file) in enumerate(self.files):
            if file.dir_idx == dir_idx and file.name == basename:
                return i+1
        file = File.create_file_with_path(fullpath, self)
        file.name = basename
        file.dir_idx = dir_idx
        file.mod_time = 0
        file.length = 0
        self.files.append(file)
        return len(self.files)

    def is_valid(self):
        return (self.total_length > 0 and self.version <= 5 and
                self.prologue_length > 0 and len(self.files) > 0)

    def dump(self, verbose, f=sys.stdout):
        idx_adjust = 1 if self.version < 5 else 0
        if verbose:
            f.write('prologue.total_length      = 0x%8.8x\n' % (
                    self.total_length))
            f.write('prologue.version           = 0x%4.4x\n' % (
                    self.version))
            if self.address_size is not None:
                f.write('prologue.address_size      = 0x%2.2x\n' % (
                        self.address_size))
            if self.seg_selector_size is not None:
                f.write('prologue.seg_selector_size = 0x%2.2x\n' % (
                        self.seg_selector_size))
            f.write('prologue.prologue_length   = 0x%8.8x\n' % (
                    self.prologue_length))
            f.write('prologue.min_inst_length   = %i\n' % (
                    self.min_inst_length))
            if self.max_ops_per_inst is not None:
                f.write('prologue.max_ops_per_inst  = %i\n' % (
                        self.max_ops_per_inst))
            f.write('prologue.default_is_stmt   = %i\n' % (
                    self.default_is_stmt))
            f.write('prologue.line_base         = %i\n' % (
                    self.line_base))
            f.write('prologue.line_range        = %u\n' % (
                    self.line_range))
            f.write('prologue.opcode_base       = %u\n' % (
                    self.opcode_base))
            max_len = DW_LNS.max_width()
            for (i, op_len) in enumerate(self.opcode_lengths):
                dw_lns = DW_LNS(i+1)
                f.write('prologue.opcode_lengths[%-*s] = %u\n' % (
                        max_len, dw_lns, op_len))

            if self.dir_entry_format is not None:
                f.write('prologue.dir_entry_format = %s\n' % (self.dir_entry_format))
                f.write('prologue.dir_count   = %i\n' % (self.dir_count))
            for (i, directory) in enumerate(self.directories):
                f.write('prologue.directories[%u] = ' % (i+idx_adjust))
                directory.dump(verbose, f=f)
                f.write('\n')
            if self.file_entry_format:
                f.write('prologue.file_entry_format = %s\n' % (self.file_entry_format))
                f.write('prologue.file_count   = %i\n' % (self.file_count))
            for (i, file) in enumerate(self.files):
                f.write('prologue.file[%u] = ' % (i+idx_adjust))
                file.dump(verbose, f=f)
                f.write('\n')
        else:
            for (i, directory) in enumerate(self.directories):
                f.write('prologue.directories[%u] = ' % (i+idx_adjust))
                directory.dump(verbose, f=f)
                f.write('\n')
            for (i, file) in enumerate(self.files):
                f.write('prologue.file[%u] = ' % (i+idx_adjust))
                file.dump(verbose, f=f)
                f.write('\n')

    def get_file(self, file_num):
        idx_adjust = 1 if self.version < 5 else 0
        file_idx = file_num - idx_adjust
        if file_idx >= 0 and file_idx < len(self.files):
            return self.files[file_idx].get_path()
        return None

    def get_file_paths(self):
        files = []
        if self.files is not None:
            for f in self.files:
                files.append(f.get_path(self))
        return files

    def get_rows_offset(self):
        return self.rows_offset

    def get_rows_end_offset(self):
        return self.offset + self.total_length + 4

    def __str__(self):
        output = io.StringIO()
        self.dump(True, output)
        return output.getvalue()

    def encode(self, debug_line):
        self.offset = debug_line.tell()
        # We will need to fixup total_length later
        debug_line.put_uint32(0)
        debug_line.put_uint16(self.version)
        prologue_length_off = debug_line.tell()
        # We will need to fixup prologue_length later
        debug_line.put_uint32(0)
        debug_line.put_uint8(self.min_inst_length)
        debug_line.put_uint8(self.default_is_stmt)
        debug_line.put_sint8(self.line_base)
        debug_line.put_uint8(self.line_range)
        debug_line.put_uint8(self.opcode_base)
        for opcode_length in self.opcode_lengths:
            debug_line.put_uint8(opcode_length)
        for directory in self.directories:
            debug_line.put_c_string(directory)
        # Terminate directories
        debug_line.put_uint8(0)
        for file in self.files:
            file.encode(self.version, debug_line)
        # Terminate files
        debug_line.put_uint8(0)
        end_header_offset = debug_line.tell()
        # Fix up the
        prologue_length = end_header_offset - (prologue_length_off + 4)
        debug_line.fixup_uint_size(4, prologue_length, prologue_length_off)

    def unpack(self, dwarf, data):
        self.offset = data.tell()
        self.total_length = data.get_uint32()
        self.version = data.get_uint16()
        if self.version >= 5:
            self.address_size = data.get_uint8()
            self.seg_selector_size = data.get_uint8()
        else:
            self.address_size = None
            self.seg_selector_size = None
        self.prologue_length = data.get_uint32()
        end_prologue_offset = self.prologue_length + data.tell()
        self.min_inst_length = data.get_uint8()
        if self.version >= 4:
            self.max_ops_per_inst = data.get_uint8()
        else:
            self.max_ops_per_inst = None
        self.default_is_stmt = data.get_uint8() != 0
        self.line_base = data.get_sint8()
        self.line_range = data.get_uint8()
        self.opcode_base = data.get_uint8()
        self.opcode_lengths = []
        self.directories = []
        self.files = []
        self.file_entry_format = None
        self.dir_entry_format = None
        for _i in range(1, self.opcode_base):
            self.opcode_lengths.append(data.get_uint8())

        if self.version >= 5:
            dir_entry_format_count = data.get_uint8()
            self.dir_entry_format = []
            for i in range(dir_entry_format_count):
                content_type = data.get_uleb128()
                form = data.get_uleb128()
                ef = FileAttribute(content_type, form)
                self.dir_entry_format.append(ef)
            self.dir_count = data.get_uleb128()
            for i in range(self.dir_count):
                self.directories.append(File.create_dir(dwarf, data, self))
            file_entry_format_count = data.get_uint8()
            self.file_entry_format = []
            for i in range(file_entry_format_count):
                content_type = data.get_uleb128()
                form = data.get_uleb128()
                ef = FileAttribute(content_type, form)
                self.file_entry_format.append(ef)
            self.file_count = data.get_uleb128()
            for i in range(self.file_count):
                self.files.append(File.create_file(dwarf, data, self))

        else:
            self.dir_count = None
            while True:
                dir = File.create_dir(dwarf, data, self)
                if dir is None:
                    break
                self.directories.append(dir)
            while True:
                f = File.create_file(dwarf, data, self)
                if f is None:
                    break
                self.files.append(f)
        self.rows_offset = data.tell()
        if self.rows_offset != end_prologue_offset:
            sys.stdout.write('error: error parsing prologue, end offset '
                             '0x%8.8x != actual offset 0x%8.8x' %
                             (end_prologue_offset, self.rows_offset))
            print(str(self))
        return self.is_valid()


class SequenceRange(AddressRange):
    def __init__(self, lo, hi, start_idx, end_idx):
        AddressRange.__init__(self, lo, hi)
        self.start_idx = start_idx
        self.end_idx = end_idx

    def __str__(self):
        return '[0x%16.16x - 0x%16.16x) start_idx=%u, end_idx=%u' % (
                self.lo, self.hi, self.start_idx, self.end_idx)
