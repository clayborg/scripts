#! /usr/bin/env python3

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import binascii
import io
import re
import string
import struct
import sys

SEEK_SET = 0
SEEK_CUR = 1
SEEK_END = 2

# Constants used to decode GNU encoded pointers
DW_EH_PE_omit = 0xff
# Encodings
DW_EH_PE_absptr = 0x00
DW_EH_PE_leb128 = 0x01
DW_EH_PE_data2 = 0x02
DW_EH_PE_data4 = 0x03
DW_EH_PE_data8 = 0x04
# Relative Types
DW_EH_PE_pcrel = 0x10
DW_EH_PE_textrel = 0x20
DW_EH_PE_datarel = 0x30
DW_EH_PE_funcrel = 0x40
DW_EH_PE_aligned = 0x50
# Masks
DW_EH_PE_MASK_encoding = 0x07
DW_EH_PE_MASK_signed = 0x08
DW_EH_PE_MASK_relative = 0x70
DW_EH_PE_MASK_indirect = 0x80


def DW_EH_PE_to_str(eh_pe):
    encoding = eh_pe & DW_EH_PE_MASK_encoding
    signed = (eh_pe & DW_EH_PE_MASK_signed) != 0
    relative = eh_pe & DW_EH_PE_MASK_relative
    indirect = (eh_pe & DW_EH_PE_MASK_indirect) != 0
    s = ''
    if indirect:
        s += 'DW_EH_PE_MASK_indirect | '

    if relative == DW_EH_PE_pcrel:
        s += 'DW_EH_PE_pcrel | '
    elif relative == DW_EH_PE_textrel:
        s += 'DW_EH_PE_textrel | '
    elif relative == DW_EH_PE_datarel:
        s += 'DW_EH_PE_datarel | '
    elif relative == DW_EH_PE_funcrel:
        s += 'DW_EH_PE_funcrel | '
    elif relative == DW_EH_PE_aligned:
        s += 'DW_EH_PE_aligned | '

    if signed:
        s += 'DW_EH_PE_MASK_signed | '

    if encoding == DW_EH_PE_absptr:
        s += 'DW_EH_PE_absptr'
    elif encoding == DW_EH_PE_leb128:
        s += 'DW_EH_PE_leb128'
    elif encoding == DW_EH_PE_data2:
        s += 'DW_EH_PE_data2'
    elif encoding == DW_EH_PE_data4:
        s += 'DW_EH_PE_data4'
    elif encoding == DW_EH_PE_data8:
        s += 'DW_EH_PE_data8'
    return s


def dump_memory(base_addr, data, num_per_line, outfile):
    data_len = len(data)
    hex_string = binascii.hexlify(data).decode('utf-8')
    addr = base_addr
    ascii_str = ''
    i = 0
    while i < data_len:
        outfile.write('0x%8.8x: ' % (addr + i))
        bytes_left = data_len - i
        if bytes_left >= num_per_line:
            curr_data_len = num_per_line
        else:
            curr_data_len = bytes_left
        hex_start_idx = i * 2
        hex_end_idx = hex_start_idx + curr_data_len * 2
        curr_hex_str = hex_string[hex_start_idx:hex_end_idx]
        # 'curr_hex_str' now contains the hex byte string for the
        # current line with no spaces between bytes
        t = iter(curr_hex_str)
        # Print hex bytes separated by space
        outfile.write(' '.join(a + b for a, b in zip(t, t)))
        # Print two spaces
        outfile.write('  ')
        # Calculate ASCII string for bytes into 'ascii_str'
        ascii_str = ''
        for j in range(i, i + curr_data_len):
            ch = chr(data[j])
            if ch in string.printable and ch not in string.whitespace:
                ascii_str += '%c' % (ch)
            else:
                ascii_str += '.'
        # Print ASCII representation and newline
        outfile.write(ascii_str)
        i = i + curr_data_len
        outfile.write('\n')


def dump_hex(addr, data, outfile):
    if addr is not None:
        outfile.write('0x%8.8x: ' % (addr))
    hex_string = binascii.hexlify(data)
    s = ' '.join(hex_string[i:i+2] for i in range(0, len(hex_string), 2))
    outfile.write(s)


def last_char_is_newline(s):
    if s:
        return s[-1] == '\n'
    return False


def hex_escape(s):
    return ''.join(escape(c) for c in s)


def escape(c):
    if c in string.printable:
        if c == '\n':
            return '\\n'
        if c == '\t':
            return '\\t'
        if c == '\r':
            return '\\r'
        return c
    c = ord(c)
    if c <= 0xff:
        return '\\x' + '%02.2x' % (c)
    elif c <= '\uffff':
        return '\\u' + '%04.4x' % (c)
    else:
        return '\\U' + '%08.8x' % (c)


class UnpackHelper(object):
    # Integer size characters start with upper case.
    S8 = str('b')
    U8 = str('B')
    S16 = str('h')
    U16 = str('H')
    S32 = str('i')
    U32 = str('I')
    S64 = str('q')
    U64 = str('Q')

    def __init__(self, b):
        if b == 'big':
            byte_order = '>'
        elif b == 'little':
            byte_order = '<'
        elif b == 'swap':
            # swap what ever the current byte order is
            if struct.pack('H', 1).startswith("\x00"):
                byte_order = '<'
            else:
                byte_order = '>'
        elif b == 'native':
            byte_order = '='
        elif b == '<' or b == '>' or b == '@' or b == '=':
            byte_order = b
        else:
            raise ValueError("Invalid byte order specified: '%s'" % (b))
        # Byte order + size start with lower case.
        self.s8 = str(byte_order + self.S8)
        self.u8 = str(byte_order + self.U8)
        self.s16 = str(byte_order + self.S16)
        self.u16 = str(byte_order + self.U16)
        self.s32 = str(byte_order + self.S32)
        self.u32 = str(byte_order + self.U32)
        self.s64 = str(byte_order + self.S64)
        self.u64 = str(byte_order + self.U64)
        self.byte_order = byte_order

    def is_little_endian(self):
        if self.byte_order == '<':
            return True
        if self.byte_order in ['@', '=']:
            return sys.byteorder == 'little'
        return False

    def get_swapped(self):
        byte_order = self.byte_order
        if byte_order == '=':
            return UnpackHelper('swap')
        elif byte_order == '>':
            return UnpackHelper('<')
        elif byte_order == '<':
            return UnpackHelper('>')
        raise ValueError('invalid byte order %s' % (byte_order))

    def get_n_s8(self, n):
        return str(self.byte_order + '%i' % (n) + self.S8)

    def get_n_u8(self, n):
        return str(self.byte_order + '%i' % (n) + self.U8)

    def get_n_s16(self, n):
        return str(self.byte_order + '%i' % (n) + self.S16)

    def get_n_u16(self, n):
        return str(self.byte_order + '%i' % (n) + self.U16)

    def get_n_s32(self, n):
        return str(self.byte_order + '%i' % (n) + self.S32)

    def get_n_u32(self, n):
        return str(self.byte_order + '%i' % (n) + self.U32)

    def get_n_s64(self, n):
        return str(self.byte_order + '%i' % (n) + self.S64)

    def get_n_u64(self, n):
        return str(self.byte_order + '%i' % (n) + self.U64)


class FileEncode:
    '''Encode binary data to a file'''

    def __init__(self, f=None, byte_order='=', addr_size=0, offset_size=4):
        '''Initialize with an open binary file and optional byte order and
           address byte size.
        '''
        if f is None:
            self.file = io.BytesIO()
        else:
            self.file = f

        self.addr_size = addr_size
        self.offset_size = offset_size
        self.set_byte_order(byte_order)

    def getvalue(self):
        if isinstance(self.file, io.BytesIO):
            return self.file.getvalue()
        raise ValueError("can't get the value of non io.BytesIO file")

    def dump(self, f=sys.stdout):
        dump_memory(0, self.getvalue(), 16, f)

    def align_to(self, align):
        curr_pos = self.file.tell()
        delta = curr_pos % align
        if delta:
            pad = align - delta
            if pad != 0:
                self.seek(pad, SEEK_CUR)

    def seek(self, offset, whence=SEEK_SET):
        if self.file:
            return self.file.seek(offset, whence)
        raise ValueError

    def tell(self):
        if self.file:
            return self.file.tell()
        raise ValueError

    def get_addr_size(self):
        return self.addr_size

    def set_addr_size(self, addr_size):
        self.addr_size = addr_size

    def get_byte_order(self):
        return self.unpack_helper.byte_order

    def set_byte_order(self, b):
        self.unpack_helper = UnpackHelper(b)

    def swap_byte_order(self):
        '''Toggle the byte order from big to little or little to big endian.'''
        self.unpack_helper = self.unpack_helper.get_swapped()

    def put_c_string(self, value, null_terminate=True):
        self.file.write(value.encode('utf-8'))
        if null_terminate:
            self.put_sint8(0)

    def put_sint8(self, value):
        '''Encode a int8_t into the file at the current file position'''
        self.file.write(struct.pack(self.unpack_helper.s8, value))

    def put_uint8(self, value):
        '''Encode a uint8_t into the file at the current file position'''
        self.file.write(struct.pack(self.unpack_helper.u8, value))

    def put_sint16(self, value):
        '''Encode a int16_t into the file at the current file position'''
        self.file.write(struct.pack(self.unpack_helper.s16, value))

    def put_uint16(self, value):
        '''Encode a uint16_t into the file at the current file position'''
        self.file.write(struct.pack(self.unpack_helper.u16, value))

    def put_uint24(self, value):
        '''Encode a uint24_t into the file at the current file position'''
        bytes = []
        bytes.append((value >> 16) & 0xff)
        bytes.append((value >>  8) & 0xff)
        bytes.append((value >>  0) & 0xff)
        if self.unpack_helper.is_little_endian():
            bytes.reverse()
        for byte in bytes:
            self.put_uint8(byte)

    def put_sint32(self, value):
        '''Encode a int32_t into the file at the current file position'''
        self.file.write(struct.pack(self.unpack_helper.s32, value))

    def put_uint32(self, value):
        '''Encode a uint32_t into the file at the current file position'''
        self.file.write(struct.pack(self.unpack_helper.u32, value))

    def put_sint64(self, value):
        '''Encode a int64_t into the file at the current file position'''
        self.file.write(struct.pack(self.unpack_helper.s64, value))

    def put_uint64(self, value):
        '''Encode a uint64_t into the file at the current file position'''
        self.file.write(struct.pack(self.unpack_helper.u64, value))

    def put_uleb128(self, value):
        '''Encode a ULEB128 into the file at the current file position'''
        while value >= 0x80:
            self.put_uint8(0x80 | (value & 0x7f))
            value >>= 7
        self.put_uint8(value)

    def put_midi_vlq(self, value):
        '''Encodes an integer into a MIDI variable-length quantity (VLQ) byte sequence.'''
        if value < 0:
            raise ValueError("can't encode an negative number as a into a MIDI variable-length quantity (VLQ) byte sequence")

        # Encode as a single byte for performance
        if value < 127:
            self.put_uint8(value)
            return

        bytes = []
        msbit = 0x00  # low-order byte has high bit cleared.
        while value > 0:
            bytes.append(((value & 0x7f) | msbit) & 0xff)
            value >>= 7
            msbit = 0x80
        bytes.reverse()  # put most-significant byte first, least significant last
        # Save the bytes out in reverse order.
        for byte in bytes:
            self.put_uint8(byte)

    def put_sleb128(self, value):
        if value < 0:
            uvalue = (1 - value) * 2
        else:
            uvalue = value * 2
        while True:
            byte = value & 0x7F
            value >>= 7
            uvalue >>= 7
            if uvalue != 0:
                byte = byte | 0x80
            self.put_uint8(byte)
            if uvalue == 0:
                break

    def put_address(self, value):
        if self.addr_size == 0:
            raise ValueError('must set address size before writing address')
        self.put_uint_size(self.addr_size, value)

    def put_uint_size(self, size, value):
        '''Encode a unsigned integer into the file at the current file
        position as an integer whose byte size is "size".'''
        if size == 1:
            return self.put_uint8(value)
        if size == 2:
            return self.put_uint16(value)
        if size == 4:
            return self.put_uint32(value)
        if size == 8:
            return self.put_uint64(value)
        print("error: integers of size %u are not supported" % (size))

    def fixup_uint_size(self, size, value, offset):
        '''Fixup one unsigned integer in the file at "offset" bytes from
        the start of the file. The current file position will be saved and
        restored.'''
        saved_offset = self.file.tell()
        self.file.seek(offset)
        self.put_uint_size(size, value)
        self.file.seek(saved_offset)

    def fixup_uints_size(self, size, values, offset):
        '''Fixup an array of unsigned integers in the file at "offset" bytes
        from the start of the file. The current file position will be saved and
        restored.'''
        saved_offset = self.file.tell()
        self.file.seek(offset)
        for value in values:
            self.put_uint_size(size, value)
        self.file.seek(saved_offset)


class FileExtract:
    '''Decode binary data from a file'''

    def __init__(self, f, byte_order='=', addr_size=0, offset_size=4,
                 gnu_pcrel=None, gnu_textrel=None, gnu_datarel=None,
                 gnu_funcrel=None):
        '''Initialize with an open binary file and optional byte order and
           address byte size
        '''
        self.file = f
        self.offsets = []
        self.addr_size = addr_size
        self.offset_size = offset_size
        self.set_byte_order(byte_order)
        self.pcrel = gnu_pcrel  # get_gnu_pointer(DW_EH_PE_pcrel)
        self.textrel = gnu_textrel  # get_gnu_pointer(DW_EH_PE_textrel)
        self.datarel = gnu_datarel  # get_gnu_pointer(DW_EH_PE_datarel)
        self.funcrel = gnu_funcrel  # get_gnu_pointer(DW_EH_PE_funcrel)

    def get_size(self):
        pos = self.file.tell()
        self.file.seek(0, SEEK_END)
        len = self.file.tell()
        self.file.seek(pos, SEEK_SET)
        return len

    def align_to(self, align):
        curr_pos = self.file.tell()
        delta = curr_pos % align
        if delta:
            pad = align - delta
            if pad != 0:
                self.seek(pad, SEEK_CUR)

    def get_addr_size(self):
        return self.addr_size

    def set_addr_size(self, addr_size):
        self.addr_size = addr_size

    def get_byte_order(self):
        return self.unpack_helper.byte_order

    def set_byte_order(self, b):
        self.unpack_helper = UnpackHelper(b)

    def seek(self, offset, whence=SEEK_SET):
        if self.file:
            return self.file.seek(offset, whence)
        raise ValueError

    def tell(self):
        if self.file:
            return self.file.tell()
        raise ValueError

    def read_data(self, byte_size):
        if (self.pcrel is not None or self.textrel is not None or
                self.datarel is not None or self.funcrel is not None):
            offset = self.tell()
        bytes = self.read_size(byte_size)
        if len(bytes) == byte_size:
            # If we have GNU PC, text, data or function relative data, then
            # track the correct relative offset when handing out data that is
            # a subset of this data
            pcrel = None if self.pcrel is None else self.pcrel + offset
            textrel = None if self.textrel is None else self.textrel + offset
            datarel = None if self.datarel is None else self.datarel + offset
            funcrel = None if self.funcrel is None else self.funcrel + offset
            return FileExtract(io.BytesIO(bytes),
                               byte_order=self.unpack_helper.byte_order,
                               addr_size=self.addr_size,
                               offset_size=self.offset_size,
                               gnu_pcrel=pcrel,
                               gnu_textrel=textrel,
                               gnu_datarel=datarel,
                               gnu_funcrel=funcrel)
        return None

    def read_size(self, byte_size):
        s = self.file.read(byte_size)
        if len(s) != byte_size:
            return None
        return s

    def get_all_bytes(self):
        save_pos = self.file.tell()
        self.file.seek(0, SEEK_END)
        len = self.file.tell()
        self.file.seek(0, SEEK_SET)
        bytes = self.read_size(len)
        self.file.seek(save_pos, SEEK_SET)
        return bytes

    def push_offset_and_seek(self, offset, whence=SEEK_SET):
        '''Push the current file offset and seek to "offset"'''
        self.offsets.append(self.file.tell())
        self.file.seek(offset, whence)

    def pop_offset_and_seek(self):
        '''Pop a previously pushed file offset and set the file position.'''
        if len(self.offsets) > 0:
            self.file.seek(self.offsets.pop(), SEEK_SET)

    def get_sint8(self, fail_value=0):
        '''Extract a int8_t from the current file position.'''
        s = self.read_size(1)
        if s:
            v, = struct.unpack(self.unpack_helper.s8, s)
            return v
        else:
            return fail_value

    def get_uint8(self, fail_value=0):
        '''Extract and return a uint8_t from the current file position.'''
        s = self.read_size(1)
        if s:
            v, = struct.unpack(self.unpack_helper.u8, s)
            return v
        else:
            return fail_value

    def get_sint16(self, fail_value=0):
        '''Extract a int16_t from the current file position.'''
        s = self.read_size(2)
        if s:
            v, = struct.unpack(self.unpack_helper.s16, s)
            return v
        else:
            return fail_value

    def get_uint16(self, fail_value=0):
        '''Extract a uint16_t from the current file position.'''
        s = self.read_size(2)
        if s:
            v, = struct.unpack(self.unpack_helper.u16, s)
            return v
        else:
            return fail_value

    def get_sint32(self, fail_value=0):
        '''Extract a int32_t from the current file position.'''
        s = self.read_size(4)
        if s:
            v, = struct.unpack(self.unpack_helper.s32, s)
            return v
        else:
            return fail_value

    def get_uint32(self, fail_value=0):
        '''Extract a uint32_t from the current file position.'''
        s = self.read_size(4)
        if s:
            v, = struct.unpack(self.unpack_helper.u32, s)
            return v
        else:
            return fail_value

    def get_uint24(self, fail_value=0):
        '''Extract a uint24_t from the current file position.'''
        bytes = []
        bytes.append(self.get_uint8(None))
        bytes.append(self.get_uint8(None))
        bytes.append(self.get_uint8(None))
        if None in bytes:
            return fail_value
        if not self.unpack_helper.is_little_endian():
            bytes.reverse()
        return bytes[2] << 16 | bytes[1] << 8 | bytes[0]

    def get_sint64(self, fail_value=0):
        '''Extract a int64_t from the current file position.'''
        s = self.read_size(8)
        if s:
            v, = struct.unpack(self.unpack_helper.s64, s)
            return v
        else:
            return fail_value

    def get_uint64(self, fail_value=0):
        '''Extract a uint64_t from the current file position.'''
        s = self.read_size(8)
        if s:
            v, = struct.unpack(self.unpack_helper.u64, s)
            return v
        else:
            return fail_value

    def get_uint128(self, fail_value=0):
        '''Extract a uint128_t from the current file position.'''
        values = self.get_n_uint64(2, None)
        if None in values:
            return fail_value
        if self.unpack_helper.is_little_endian():
            return values[0] | values[1] << 64
        else:
            return values[0] << 64 | values[1]

    def set_gnu_pcrel(self, pcrel):
        self.pcrel = pcrel

    def set_gnu_textrel(self, textrel):
        self.textrel = textrel

    def set_gnu_datarel(self, datarel):
        self.datarel = datarel

    def set_gnu_funcrel(self, funcrel):
        self.funcrel = funcrel

    def get_gnu_pointer(self, ptr_encoding):
        if ptr_encoding == DW_EH_PE_omit:
            return None

        if ptr_encoding is None:
            ptr_encoding = DW_EH_PE_absptr

        addr = 0
        relative = ptr_encoding & DW_EH_PE_MASK_relative
        if relative == DW_EH_PE_pcrel:
            if self.pcrel is None:
                raise ValueError('DW_EH_PE_pcrel addresses require the PC '
                                 'relative base address that matches the '
                                 'start of this buffer be set by calling '
                                 'self.set_gnu_pcrel(addr)')
            addr = self.pcrel + self.tell()
        elif relative == DW_EH_PE_textrel:
            if self.textrel is None:
                raise ValueError('DW_EH_PE_textrel addresses require the text '
                                 'relative base address that matches the '
                                 'start of this buffer be set by calling '
                                 'self.set_gnu_textrel(addr)')
            addr = self.textrel
        elif relative == DW_EH_PE_datarel:
            if self.datarel is None:
                raise ValueError('DW_EH_PE_datarel addresses require the data '
                                 'relative base address that matches the '
                                 'start of this buffer be set by calling '
                                 'self.set_gnu_datarel(addr)')
            addr = self.datarel
        elif relative == DW_EH_PE_funcrel:
            if self.funcrel is None:
                raise ValueError('DW_EH_PE_funcrel addresses require the '
                                 'function relative base address that matches '
                                 'the start of this buffer be set by calling '
                                 'self.set_gnu_funcrel(addr)')
            addr = self.funcrel
        elif relative == DW_EH_PE_aligned:
            self.align_to(self.get_addr_size())

        encoding = ptr_encoding & DW_EH_PE_MASK_encoding
        signed = (ptr_encoding & DW_EH_PE_MASK_signed) != 0
        if encoding == DW_EH_PE_absptr:
            addr += self.get_address()
        elif encoding == DW_EH_PE_leb128:
            if signed:
                addr += self.get_sleb128()
            else:
                addr += self.get_uleb128()
        elif encoding == DW_EH_PE_data2:
            if signed:
                addr += self.get_sint16()
            else:
                addr += self.get_uint16()
        elif encoding == DW_EH_PE_data4:
            if signed:
                addr += self.get_sint32()
            else:
                addr += self.get_uint32()
        elif encoding == DW_EH_PE_data8:
            if signed:
                addr += self.get_sint64()
            else:
                addr += self.get_uint64()
        else:
            raise ValueError('invalid DW_EH_PE encoding %#x' % (encoding))

        # Since python support integers of any size, we need to mask off any
        # bits above bit 64 and higher due to overflows during signed or
        # unsigned math
        return addr & self.get_address_mask()

    def get_address_mask(self):
        return (1 << self.get_addr_size() * 8) - 1

    def get_address(self, fail_value=0):
        if self.addr_size == 0:
            raise ValueError('error: invalid addr size...')
        else:
            return self.get_uint_size(self.addr_size, fail_value)

    def get_offset(self, fail_value=0):
        if self.offset_size == 0:
            raise ValueError('error: invalid offset size...')
        else:
            return self.get_uint_size(self.offset_size, fail_value)

    def get_sint_size(self, size, fail_value=0):
        '''Extract a signed integer from the current file position whose
        size is "size" bytes long.'''
        if size == 1:
            return self.get_sint8(fail_value)
        if size == 2:
            return self.get_sint16(fail_value)
        if size == 4:
            return self.get_sint32(fail_value)
        if size == 8:
            return self.get_sint64(fail_value)
        if size == 0:
            return fail_value
        print("error: integer of size %u is not supported" % (size))
        return fail_value

    def get_uint_size(self, size, fail_value=0):
        '''Extract a unsigned integer from the current file position whose
        size is "size" bytes long.'''
        if size == 1:
            return self.get_uint8(fail_value)
        if size == 2:
            return self.get_uint16(fail_value)
        if size == 4:
            return self.get_uint32(fail_value)
        if size == 8:
            return self.get_uint64(fail_value)
        if size == 0:
            return fail_value
        print("error: integer of size %u is not supported" % (size))
        return fail_value

    def get_fixed_length_c_string(self, n, skip_trailing_chars='\0'):
        '''Extract a fixed length C string from the current file position.'''
        cstr = ''
        for i in range(n):
            byte = self.get_uint8()
            if chr(byte) in skip_trailing_chars:
                continue
            cstr += "%c" % byte
        return cstr.encode('utf8').decode("utf-8")

    def get_c_string(self):
        '''Extract a NULL terminated C string from the current position.'''
        cstr = ''
        byte = self.get_uint8()
        while byte != 0:
            cstr += "%c" % byte
            byte = self.get_uint8()
        return cstr.encode('utf8').decode("utf-8")
    # def get_c_string(self):
    #     '''Extract a NULL terminated C string from the current position.'''
    #     chars = []
    #     byte = self.get_uint8()
    #     while byte != 0:
    #         chars.append(byte)
    #         byte = self.get_uint8()
    #     return bytes(chars).decode('utf-8')


    def get_n_sint8(self, n, fail_value=0):
        '''Extract "n" int8_t values from the current position as a list.'''
        s = self.read_size(n)
        if s:
            return struct.unpack(self.unpack_helper.get_n_s8(n), s)
        else:
            return (fail_value,) * n

    def get_n_uint8(self, n, fail_value=0):
        '''Extract "n" uint8_t values from the current position as a list.'''
        sys.stdout.flush()
        s = self.read_size(n)
        if s:
            return struct.unpack(self.unpack_helper.get_n_u8(n), s)
        else:
            return (fail_value,) * n

    def get_n_sint16(self, n, fail_value=0):
        '''Extract "n" int16_t values from the current position as a list.'''
        s = self.read_size(2 * n)
        if s:
            return struct.unpack(self.unpack_helper.get_n_s16(n), s)
        else:
            return (fail_value,) * n

    def get_n_uint16(self, n, fail_value=0):
        '''Extract "n" uint16_t values from the current position as a list.'''
        s = self.read_size(2 * n)
        if s:
            return struct.unpack(self.unpack_helper.get_n_u16(n), s)
        else:
            return (fail_value,) * n

    def get_n_sint32(self, n, fail_value=0):
        '''Extract "n" int32_t values from the current position as a list.'''
        s = self.read_size(4 * n)
        if s:
            return struct.unpack(self.unpack_helper.get_n_s32(n), s)
        else:
            return (fail_value,) * n

    def get_n_uint32(self, n, fail_value=0):
        '''Extract "n" uint32_t values from the current position as a list.'''
        s = self.read_size(4 * n)
        if s:
            return struct.unpack(self.unpack_helper.get_n_u32(n), s)
        else:
            return (fail_value,) * n

    def get_n_sint64(self, n, fail_value=0):
        '''Extract "n" int64_t values from the current position as a list.'''
        s = self.read_size(8 * n)
        if s:
            return struct.unpack(self.unpack_helper.get_n_s64(n), s)
        else:
            return (fail_value,) * n

    def get_n_uint64(self, n, fail_value=0):
        '''Extract "n" uint64_t values from the current position as a list.'''
        s = self.read_size(8 * n)
        if s:
            return struct.unpack(self.unpack_helper.get_n_u64(n), s)
        else:
            return (fail_value,) * n

    def get_uleb128p1(self, fail_value=0):
        return self.get_uleb128(fail_value) - 1

    def get_uleb128(self, fail_value=0):
        '''Extract a ULEB128 number'''
        byte = self.get_uint8(None)
        if byte is None:
            return fail_value
        # Quick test for single byte ULEB
        if (byte & 0x80) == 0:
            return byte
        result = byte & 0x7f
        shift = 7
        while byte & 0x80:
            byte = self.get_uint8(None)
            if byte is None:
                return fail_value
            result |= (byte & 0x7f) << shift
            shift += 7
        return result

    def get_midi_vlq(self, fail_value=0):
        """Decodes a MIDI variable-length quantity (VLQ) from a sequence of bytes."""
        value = 0
        while True:
            byte = self.get_uint8(None)
            if byte is None:
                return fail_value
            # Shift the current value 7 bits to the left to make space for the next 7 bits
            value = (value << 7) | (byte & 0x7F)
            # Check if the most significant bit (MSB) is set.
            # If it's not set (byte & 0x80 == 0), this is the last byte.
            if not (byte & 0x80):
                break
        return value

    def get_sleb128(self, fail_value=0):
        result = 0
        shift = 0
        size = 64
        byte = 0
        bytecount = 0
        while 1:
            bytecount += 1
            byte = self.get_uint8(None)
            if byte is None:
                return fail_value
            result |= (byte & 0x7f) << shift
            shift += 7
            if (byte & 0x80) == 0:
                break
        # Sign bit of byte is 2nd high order bit (0x40)
        if (shift < size and (byte & 0x40)):
            result |= - (1 << shift)
        return result

    def dump(self, start=0, end=-1, num_per_line=32, f=sys.stdout):
        self.push_offset_and_seek(self.tell())
        if end == -1:
            self.seek(0, SEEK_END)  # Seek to end to get size
            n = self.tell() - start
        else:
            n = end - start
        self.seek(start, SEEK_SET)
        bytes = self.read_size(n)
        dump_memory(0, bytes, num_per_line, f)
        self.pop_offset_and_seek()

    def dump_hex(self, start=0, end=-1, f=sys.stdout):
        self.push_offset_and_seek(self.tell())
        if end == -1:
            self.seek(0, SEEK_END)  # Seek to end to get size
            n = self.tell() - start
        else:
            n = end - start
        self.seek(start, SEEK_SET)
        bytes = self.read_size(n)
        dump_hex(start, bytes, f)
        self.pop_offset_and_seek()


def main():
    uleb_tests = [(struct.pack("B", 0x02), 2),
                  (struct.pack("B", 0x7f), 127),
                  (struct.pack("2B", 0x80, 0x01), 128),
                  (struct.pack("2B", 0x81, 0x01), 129),
                  (struct.pack("2B", 0x82, 0x01), 130),
                  (struct.pack("2B", 0xb9, 0x64), 12857)]

    sleb_tests = [(struct.pack("B", 0x02), 2),
                  (struct.pack("B", 0x7e), -2),
                  (struct.pack("2B", 0xff, 0x00), 127),
                  (struct.pack("2B", 0x81, 0x7f), -127),
                  (struct.pack("2B", 0x80, 0x01), 128),
                  (struct.pack("2B", 0x80, 0x7f), -128),
                  (struct.pack("2B", 0x81, 0x01), 129),
                  (struct.pack("2B", 0xff, 0x7e), -129)]
    num_errors = 0
    print('Running unit tests...', end="")
    for (s, check_n) in sleb_tests:
        e = FileExtract(io.BytesIO(s))
        n = e.get_sleb128()
        if n != check_n:
            num_errors += 1
            print('\nerror: sleb128 extraction failed for %i (got %i)' % (
                    check_n, n))
            dump_memory(0, s, 32, sys.stdout)
    for (s, check_n) in uleb_tests:
        e = FileExtract(io.BytesIO(s))
        n = e.get_uleb128()
        if n != check_n:
            num_errors += 1
            print('\nerror: uleb128 extraction failed for %i (got %i)' % (
                    check_n, n))
            dump_memory(0, s, 32, sys.stdout)
    if num_errors == 0:
        print('ok')
    else:
        print('%u errors' % (num_errors))
    print


if __name__ == '__main__':
    main()


class AutoParser:
    '''A class that enables easy parsing of binary files.

    This class is designed to be sublcassed and clients must provide a list of
    items in the constructor. Each item in the items list is a dictionary that
    describes each attribute that should be added to the class when it is
    decoded. A quick example for a C structure:

        struct load_command {
                uint32_t cmd;		/* type of load command */
                uint32_t cmdsize;	/* total size of command in bytes */
        };

    The python code would look like:

        class load_command(file_extract.AutoParser):
            items = [
                { 'name':'cmd', 'type':'u32' },
                { 'name':'cmdsize', 'type':'u32'},
            ]
            def __init__(self, data):
                AutoParser.__init__(self, self.items, data)

    Decoding a single load_command from a file involves opening a file and
    creating a FileExtract object, and then decoding the load_command object:

        file = open(path)
        data = file_extract.FileExtract(file, '=', 4)
        lc = load_command(data)

    The 'lc' object now has two properties:

        lc.cmd
        lc.cmdsize

    Item dictionaries are very easy to define and have quite a many options
    to ensure it is very easy to parse a binary file by defining many
    subclasses of file_extract.AutoParser and combining them together.

    Item dictionaries can contain the following keys:
    KEY NAME       DESCRIPTION
    ============== ============================================================
    'name'         A string name of the attribute to add to this class when
                   decoding. If an item has no name, it will not be added to
                   this object when it is being decoded. Omitting the name is
                   handy when you have padding where you might need to decode
                   some bytes that are part of the on disk representation of
                   the binary object, but don't need the value represented
                   in the object itself.
    'type'         A string name for the type of the data to decode. See
                   "Builin Types" table below for valid typename values. Either
    'class'        An AutoParser sublcass class that will be used to decode
                   this item by constructing it with the data at the current
                   offset. This allows you to compose a AutoParser object
                   that is contained within another AutoParser object.
    'condition'    A function that takes two arguments: the current AutoParser
                   object that is in the process of being decoded and the
                   FileExtract object. The function returns True if this item
                   is present and should be decoded, and False if it should be
                   skipped. The condition is evaluated before the value is
                   decoded and stops the type/class/decode from decoding the
                   object. This can be used to only decode a value if a
                   previous attribute is a specific value. If a 'default' key
                   is present in the item dictionary, then the 'default' value
                   will be set as the the value for this item, otherwise the
                   attribute will not be added to this object:
                       condition_passed = item['condition'](AutoParser,
                                                            FileExtract)
    'default'      The default value for the current item that will be set if
                   the 'condition' callback function returns False.
    'decode'       A function that take a single file_extract.FileExtract
                   object argument and returns the value for this item.
                       value = item['decode'](FileExtract)
    'align'        An integer that gives the file offset alignment for this
                   item. This alignment can be any number and the file
                   position will be advanced to the next aligned offset if
                   needed prior to reading the value
    'attr_count'   A string that specifies the name of an attribute that has
                   already been decoded in this object. This indicates that the
                   value for this item is a list whose size is the integer
                   value of the attribute that was already decoded in a
                   previous item in this object.
    'attr_offset'  An integer that this item's value is contained within the
                   file at the specified offset. A seek will be performed on
                   the file before reading the value of this object. The file
                   position will be pushed onto a stack, a seek will be
                   performed, the item's value will be read, and then the file
                   position will be restored.
    'attr_offset_size' A string name of an existing attribute that contains
                   the end offset of the data for this object. This is useful
                   when a list of items is contained in the file and the count
                   of the items is not specified, just the end offset. This is
                   often used with the 'attr_offset' key/value pair. The
                   type/class/decode will be continually called until the file
                   offset exceeds the offset + 'attr_offset_size'. String
                   tables are good example of when this is used as they string
                   table offset and size are often specified, but no the
                   number of strings in the string table.
    'attr_offset_whence' A string name that specifies the type of seek to
                   perform on the 'attr_offset' value. This can be one of
                   "item", "file", "eof", "curr". "item" specifies the offset
                   is relative to the starting offset of this object. "file"
                   specifies that the offset is relative to the start of the
                   file. "eof" specifies that the offset is relative to the
                   end of tile. "curr" specifies that the offset is relative
                   to the current file position.
    'validate'     A function pointer that will be called after the value has
                   been extracted. The function is called with the extracted
                   value and should return None if the value is valid, or
                   return an error string if the value is not valid:
                       error = item['validate'](value)
                       if error:
                           raise ValueError(error)
    'value_fixup'  A function pointer that will be called after the item's
                   value has been decoded. The function will be called with one
                   argument, the decoded value, and returns the fixed value:
                       value = item['value_fixup'](value)
    'debug'        A string value that is printed prior to decoding the item's
                   value. The printed string value is prefixed by the current
                   file offset and allows debugging of where a value is being
                   decoded within the file. This helps debug the decoding of
                   items.
    'switch'       The string name of an attribute that was already decoded in
                   this object. The attribute value will be used as a key into
                   the 'cases' item key/value pair in the items supplied to the
                   AutoParser object. If the attribute value is not found in
                   the 'cases' dictionary, then 'default' will be used as the
                   key into the 'cases' dictionary. See 'cases' below. See
                   "Switch Example" below for more information.
    'cases'        A dictionary of values to items arrays. The 'switch' key
                   above specifies the name of an attribute in this object that
                   will be used as the key into the dictionary specified in
                   this key/value pair. The items that are found during the
                   lookup will then be decoded into this object. See
                   "Switch Example" below for more information.
    'dump'         A function pointer that is called to dump the value. The
                   function gets called with the value and the file:
                        def dump(value, file):
                            ...
    'dump_list'    A function pointer that is called to dump a list of values.
                   The function gets called with the value and the file:
                        def dump_list(value, prefix, flat, file):
                            ...
    EXAMPLE 1

    If you have a structure that has a count followed by an array of items
    whose size is the value of count:

        struct NumberArray {
            uint32_t count;
            uint32_t numbers[];
        };

    This would be respresented by the following items:

    class NumberArray(AutoParser):
        items = [
            {'type':'u32', 'name':'count'},
            {'type':'u32', 'name':'numbers', 'attr_count' : 'count'},
        ]
        def __init__(self, data):
            AutoParser.__init__(self, self.items, data)

    The second item named 'numbers' will be decoded as a list of 'obj.count'
    u32 values as the 'attr_count' specifies the name of an attribute that
    has already been decoded into the object 'obj' and contains the count.

    EXAMPLE 2

    Sometimes a structure contains an offset and a count of objects. In the
    example below SymtabInfo contains the offset and count of Symbol objects
    that appear later in the file:
        struct SymtabInfo {
            uint32_t symtab_offset;
            uint32_t num_symbols;
        }
        struct Symbol {
            ...;
        };

    The symbol table can be decoded by combinging the two things together
    into the same object when decoding:

       class Symbol(AutoParser):
           ...
       class SymtabInfo(AutoParser):
           items = [
                {'type' : 'u32', 'name' : 'symtab_offset'},
                {'type' : 'u32', 'name' : 'num_symbols' },
                {'class' : Symbol,
                 'name' : 'symbols',
                 'attr_offset' : 'symtab_offset',
                 'attr_count' : 'num_symbols' }
            ]
            def __init__(self, data):
                AutoParser.__init__(self, self.items, data)

    '''
    type_regex = re.compile(r'([^\[]+)\[([0-9]+)\]')
    default_formats = {
        'u8': '%#2.2x',
        'u16': '%#4.4x',
        'u32': '%#8.8x',
        'u64': '%#16.16x',
        'addr': '%#16.16x',
        'cstr': '"%s"',
    }
    read_value_callbacks = {
        'u8': lambda data: data.get_uint8(),
        'u16': lambda data: data.get_uint16(),
        'u32': lambda data: data.get_uint32(),
        'u64': lambda data: data.get_uint64(),
        's8': lambda data: data.get_sint8(),
        's16': lambda data: data.get_sint16(),
        's32': lambda data: data.get_sint32(),
        's64': lambda data: data.get_sint64(),
        'addr': lambda data: data.get_address(),
        'uleb': lambda data: data.get_uleb128(),
        'sleb': lambda data: data.get_sleb128(),
        'ulebp1': lambda data: data.get_uleb128p1(),
    }

    def __init__(self, items, data, context=None):
        self.__offset = data.tell()
        self.items = items
        self.context = context  # Any object you want to store for future usage
        self.max_name_len = 0
        self.extract_items(items, data)

    def get_list_header_lines(self):
        '''When an object of this type is in a list, print out this string
           before printing out any items'''
        return None

    def get_dump_header(self):
        '''Override in subclasses to print this string out before any items
           are dumped. This is a good place to put a description of the item
           represented by this class and possible to print out a table header
           in case the items are a list'''
        return None

    def get_dump_prefix(self):
        '''Override in subclasses to print out a string before each item in
           this class'''
        return None

    def get_dump_flat(self):
        return False

    def get_offset(self):
        return self.__offset

    def extract_items(self, items, data):
        for item in items:
            offset_pushed = False
            if 'attr_offset' in item:
                offset = getattr(self, item['attr_offset'])
                if 'attr_offset_whence' in item:
                    offset_base = item['attr_offset_whence']
                    if offset_base == 'item':
                        # Offset from the start of this item
                        data.push_offset_and_seek(offset + self.get_offset())
                        offset_pushed = True
                    elif offset_base == 'file':
                        # Offset from the start of the file
                        data.push_offset_and_seek(offset, SEEK_SET)
                        offset_pushed = True
                    elif offset_base == 'eof':
                        # Offset from the end of the file
                        data.push_offset_and_seek(offset, SEEK_END)
                        offset_pushed = True
                    elif offset_base == 'curr':
                        # Offset from the current file position
                        data.push_offset_and_seek(offset, SEEK_CUR)
                        offset_pushed = True
                    else:
                        raise ValueError(
                            '"attr_offset_whence" can be one of "item", '
                            '"file", "eof", "curr" (defaults to "file")')
                else:
                    # Default to offset from the start of the file
                    data.push_offset_and_seek(offset, SEEK_SET)
                    offset_pushed = True
            if 'debug' in item:
                print('%#8.8x: %s' % (self.__offset, item['debug']))
                continue
            if 'switch' in item:
                if 'cases' not in item:
                    raise ValueError('items with a "switch" key/value pair, '
                                     'must have a "cases" key/value pair')
                cases = item['cases']
                switch_value = getattr(self, item['switch'])
                if switch_value in cases:
                    case_items = cases[switch_value]
                elif 'default' in cases:
                    case_items = cases['default']
                else:
                    raise ValueError('unhandled switch value %s' %
                                     (str(switch_value)))
                self.extract_items(case_items, data)
                continue

            # Check if this item is just an alignment directive?
            condition_passed = True
            if 'condition' in item:
                condition_passed = item['condition'](self, data)
            if 'align' in item:
                if condition_passed:
                    data.align_to(item['align'])
            count = self.read_count_from_item(item)
            value_fixup = None
            # If there is a value fixup key, then call the function with the
            # data and the value. The return value will be a fixed up value
            # and the function also has the ability to modify the data stream
            # (set the byte order, address byte size, etc).
            if 'value_fixup' in item:
                value_fixup = item['value_fixup']

            if 'attr_offset_size' in item:
                # the number of items is inferred by parsing up until
                # attr_offset + attr_offset_size, so we create a new
                # FileExtract object that only contains the data we need and
                # extract using that data.
                attr_offset_size = getattr(self, item['attr_offset_size'])
                item_data = data.read_data(attr_offset_size)
                if item_data is None:
                    raise ValueError('failed to get item data')
                value = self.decode_value(
                    item_data, item, condition_passed, value_fixup)
            else:
                if count is None:
                    value = self.decode_value(
                        data, item, condition_passed, value_fixup)
                else:
                    value = []
                    for _i in range(count):
                        value.append(self.decode_value(
                            data, item, condition_passed, value_fixup))

            if 'validate' in item:
                error = item['validate'](value)
                if error is not None:
                    raise ValueError('error: %s' % (error))
            if 'name' in item and value is not None:
                name = item['name']
                setattr(self, name, value)
                name_len = len(name)
                if self.max_name_len < name_len:
                    self.max_name_len = name_len
            if offset_pushed:
                data.pop_offset_and_seek()

    def decode_value(self, data, item, condition_passed, value_fixup):
        # If the item has a 'condition' key, then this is a function
        # that we pass "self" to in order to determine if this value
        # is available. If the callback returns False, then we set the
        # value to the default value
        read_value = True
        if not condition_passed:
            if 'default' in item:
                v = item['default']
            else:
                v = None
            read_value = False

        if read_value:
            if 'type' in item:
                v = self.read_type(data, item)
            elif 'class' in item:
                v = item['class'](data)
            elif 'decode' in item:
                v = item['decode'](data)
            else:
                raise ValueError('item definitions must have a "type" or '
                                 '"class" or "decode" field')
            # Let the item fixup each value if needed and possibly
            # adjust the byte size or byte order.
            if value_fixup is not None:
                v = value_fixup(data, v)
        return v

    def dump_item(self, prefix, f, item, print_name, parent_path, flat):
        if 'switch' in item:
            cases = item['cases']
            switch_value = getattr(self, item['switch'])
            if switch_value in cases:
                case_items = cases[switch_value]
            elif 'default' in cases:
                case_items = cases['default']
            for case_item in case_items:
                self.dump_item(prefix, f, case_item, print_name, parent_path,
                               flat)
            return
        # We skip printing an item if any of the following are true:
        # - If there is no name (padding)
        # - If there is a 'dump' value key/value pair with False as the value
        if 'name' not in item or 'dump' in item and item['dump'] is False:
            return
        name = item['name']
        if not hasattr(self, name):
            return
        value = getattr(self, name)
        value_is_list = type(value) is list
        # If flat is None set its value automatically
        if flat is None:
            flat = self.get_dump_flat()
            if value_is_list:
                if 'table_header' in item:
                    table_header = item['table_header']
                    f.write(table_header)
                    if not last_char_is_newline(table_header):
                        f.write('\n')
                    print_name = False
                    flat = True
        if prefix is None:
            prefix = self.get_dump_prefix()
        flat_list = value_is_list and 'flat' in item and item['flat']
        if prefix and flat_list is False:
            f.write(prefix)
        if print_name:
            if not flat_list:
                if flat:
                    f.write(name)
                    f.write('=')
                else:
                    f.write('%-*s' % (self.max_name_len, name))
                    f.write(' = ')
        if 'dump' in item:
            item['dump'](value, f)
            return
        elif 'dump_list' in item:
            item['dump_list'](value, prefix, flat, f)
            return
        else:
            if value_is_list:
                if parent_path is None:
                    item_path = name
                else:
                    item_path = parent_path + '.' + name
                self.dump_values(f, item, value, print_name, item_path, prefix)
            else:
                if 'dump_width' in item:
                    dump_width = item['dump_width']
                    strm = io.BytesIO()
                    self.dump_value(strm, item, value, print_name, parent_path)
                    s = strm.getvalue()
                    f.write(s)
                    s_len = len(s)
                    if s_len < dump_width:
                        f.write(' ' * (dump_width - s_len))
                else:
                    self.dump_value(f, item, value, print_name, parent_path)
        if not flat_list:
            if flat:
                f.write(' ')
            else:
                f.write('\n')

    def dump_value(self, f, item, value, print_name, parent_path):
        if value is None:
            f.write('<NULL>')
            return
        if 'stringify' in item:
            f.write('%s' % item['stringify'](value))
            return
        if 'type' in item:
            itemtype = item['type']
            if 'format' in item:
                format = item['format']
            elif itemtype in self.default_formats:
                format = self.default_formats[itemtype]
            else:
                format = None
            if format:
                f.write(format % (value))
            else:
                if itemtype.startswith('cstr'):
                    f.write('"')
                    f.write(hex_escape(value))
                    f.write('"')
                else:
                    f.write(str(value))
        elif 'class' in item:
            value.dump(prefix=None, print_name=print_name,
                       f=f, parent_path=parent_path)
        else:
            raise ValueError("item's with names must have a 'type' or "
                             "'class' key/value pair")

    def dump_values(self, f, item, values, print_name, parent_path, prefix):
        if len(values) == 0:
            if 'flat' in item and item['flat']:
                if prefix:
                    f.write(prefix)
                if parent_path:
                    f.write(parent_path)
            f.write('[]\n')
            return
        flat = self.get_dump_flat()
        if flat is False and 'flat' in item:
            flat = item['flat']
        count = len(values)
        if count > 0:
            index_width = 1
            w = count
            while w > 10:
                index_width += 1
                w /= 10
            if isinstance(values[0], AutoParser):
                first = values[0]
                table_header_lines = first.get_list_header_lines()
                if table_header_lines:
                    f.write('\n')
                    print_name = False
                    flat = True
                    for line in table_header_lines:
                        f.write(' ' * (index_width + 3))
                        f.write(line)
            index_format = '[%%%uu]' % (index_width)
            if prefix is None:
                prefix = ''
            for (i, value) in enumerate(values):
                if flat:
                    if prefix:
                        f.write(prefix)
                    if parent_path:
                        f.write(parent_path)
                    f.write(index_format % (i))
                    f.write(' = ')
                else:
                    format = '\n%s%s' + index_format + '\n'
                    f.write(format % (prefix, parent_path, i))
                self.dump_value(f, item, value, print_name, parent_path)
                f.write('\n')

    def dump(self, prefix=None, f=sys.stdout, print_name=True,
             parent_path=None, flat=None):
        header = self.get_dump_header()
        if header:
            f.write(header)
            if not last_char_is_newline(header):
                f.write('\n')
        for item in self.items:
            self.dump_item(prefix, f, item, print_name, parent_path, flat)

    def read_count_from_item(self, item):
        if 'attr_count' in item:
            # If 'attr_count' is in the dictionary. If so, it means that
            # there is already an attribute in this object that has the
            # count in it and we should ready that many of the type
            count = getattr(self, item['attr_count'])
            # If there is an 'attr_count_fixup' key, it is a function that
            # will fixup the count value
            if 'attr_count_fixup' in item:
                count = item['attr_count_fixup'](count)
            return count
        elif 'count' in item:
            return item['count']
        return None

    def read_builtin_type(self, data, typename, item):
        if typename in self.read_value_callbacks:
            return self.read_value_callbacks[typename](data)
        if typename == 'cstr':
            count = self.read_count_from_item(item)
            if count is None:
                return data.get_c_string()
            else:
                return data.get_fixed_length_c_string(count)
        if typename == 'bytes':
            if 'attr_size' in item:
                size = getattr(self, item['attr_size'])
                return data.read_size(size)
            else:
                raise ValueError("'bytes' must have either a 'count' or a "
                                 "'attr_count' key/value pair")
        raise ValueError("invalid 'type' value %s" % (typename))

    def read_type(self, data, item):
        typename = item['type']
        if '[' in typename:
            match = self.type_regex.match(typename)
            if not match:
                raise ValueError('item type array must be a valid type '
                                 'followed by [] with a decimal number '
                                 'as the size')
            basetype = match.group(1)
            count = int(match.group(2))
            if basetype == 'cstr':
                return data.get_fixed_length_c_string(count)
            result = []
            for _i in range(count):
                result.append(self.read_builtin_type(data, basetype, item))
            return result
        else:
            return self.read_builtin_type(data, typename, item)


def is_string(value):
    return isinstance(value, str)


class StringTable:
    '''A string table  that uniques strings into unique offsets.'''
    def __init__(self):
        self.offset = 0
        self.strings = None
        self.lookup_offset = None
        self.lookup_string = None
        self.reset()
        self.insert('')

    def reset(self):
        self.offset = 0
        self.strings = []
        self.lookup_offset = {}
        self.lookup_string = {}

    def insert(self, s):
        if s in self.lookup_offset:
            return self.lookup_offset[s]
        else:
            offset = self.offset
            self.lookup_offset[s] = offset
            self.lookup_string[offset] = s
            self.strings.append(s)
            self.offset += len(s) + 1
            return offset

    def dump(self, f=sys.stdout):
        for s in self.strings:
            offset = self.lookup_offset[s]
            f.write('%#8.8x: "%s"\n' % (offset, s))

    def get(self, s):
        '''This function expects the string to already be in the table and
        will throw an ValueError excpetion of it the string isn't in the
        table'''
        if is_string(s):
            if s in self.lookup_offset:
                return self.lookup_offset[s]
        else:
            if s in self.lookup_string:
                return self.lookup_string[s]
        error = 'string "%s" must exist in the string table' % (s)
        raise ValueError(error)

    def decode(self, data):
        # Reset our member variables for decoding
        self.reset()
        size = data.get_size()
        while data.tell() < size:
            s = data.get_c_string()
            self.insert(s)
        return size

    def encode(self, strm):
        # Write out the string table strings
        for s in self.strings:
            strm.put_c_string(s)
