#!/usr/bin/python

from enum import IntEnum

def get_uleb128_byte_size(value):
    byte_size = 1
    while value >= 0x80:
        byte_size += 1
        value >>= 7
    return byte_size

fixed_sizes = [
    None,   # [0]
    None,   # [1] DW_FORM_addr = 0x01
    None,   # [2]
    None,   # [3] DW_FORM_block2 = 0x03
    None,   # [4] DW_FORM_block4 = 0x04
    (2, 2), # [5] DW_FORM_data2 = 0x05
    (4, 4), # [6] DW_FORM_data4 = 0x06
    (8, 8), # [7] DW_FORM_data8 = 0x07
    None,   # [8] DW_FORM_string = 0x08
    None,   # [9] DW_FORM_block = 0x09
    None,   # [10] DW_FORM_block1 = 0x0A
    (1, 1), # [11] DW_FORM_data1 = 0x0B
    (1, 1), # [12] DW_FORM_flag = 0x0C
    None,   # [13] DW_FORM_sdata = 0x0D
    (4, 8), # [14] DW_FORM_strp = 0x0E
    None,   # [15] DW_FORM_udata = 0x0F
    (4, 8), # [16] DW_FORM_ref_addr = 0x10
    (1, 1), # [17] DW_FORM_ref1 = 0x11
    (2, 2), # [18] DW_FORM_ref2 = 0x12
    (4, 4), # [19] DW_FORM_ref4 = 0x13
    (8, 8), # [20] DW_FORM_ref8 = 0x14
    None,   # [21] DW_FORM_ref_udata = 0x15
    None,   # [22] DW_FORM_indirect = 0x16
    (4, 8), # [23] DW_FORM_sec_offset = 0x17
    None,   # [24] DW_FORM_exprloc = 0x18
    (0, 0), # [25] DW_FORM_flag_present = 0x19
    None,   # [26] DW_FORM_strx = 0x1a           # DWARF5
    None,   # [27] DW_FORM_addrx = 0x1b          # DWARF5
    (4, 4), # [28] DW_FORM_ref_sup4 = 0x1c       # DWARF5
    (4, 8), # [29] DW_FORM_strp_sup = 0x1d       # DWARF5
    (16,16),# [30] DW_FORM_data16 = 0x1e         # DWARF5
    (4, 8), # [31] DW_FORM_line_strp = 0x1f      # DWARF5
    (8, 8), # [32] DW_FORM_ref_sig8 = 0x20
    (0, 0), # [33] DW_FORM_implicit_const = 0x21 # DWARF5
    None,   # [34] DW_FORM_loclistx = 0x22       # DWARF5
    None,   # [35] DW_FORM_rnglistx = 0x23       # DWARF5
    (8, 8), # [36] DW_FORM_ref_sup8 = 0x24       # DWARF5
    (1, 1), # [37] DW_FORM_strx1 = 0x25          # DWARF5
    (2, 2), # [38] DW_FORM_strx2 = 0x26          # DWARF5
    (3, 3), # [39] DW_FORM_strx3 = 0x27          # DWARF5
    (4, 4), # [40] DW_FORM_strx4 = 0x28          # DWARF5
    (1, 1), # [41] DW_FORM_addrx1 = 0x29         # DWARF5
    (2, 2), # [42] DW_FORM_addrx2 = 0x2a         # DWARF5
    (3, 3), # [43] DW_FORM_addrx3 = 0x2b         # DWARF5
    (4, 4), # [44] DW_FORM_addrx4 = 0x2c         # DWARF5
]

class DW_FORM(IntEnum):
    null = 0x00
    addr = 0x01
    block2 = 0x03
    block4 = 0x04
    data2 = 0x05
    data4 = 0x06
    data8 = 0x07
    string = 0x08
    block = 0x09
    block1 = 0x0A
    data1 = 0x0B
    flag = 0x0C
    sdata = 0x0D
    strp = 0x0E
    udata = 0x0F
    ref_addr = 0x10
    ref1 = 0x11
    ref2 = 0x12
    ref4 = 0x13
    ref8 = 0x14
    ref_udata = 0x15
    indirect = 0x16
    sec_offset = 0x17
    exprloc = 0x18
    flag_present = 0x19
    strx = 0x1a           # DWARF5
    addrx = 0x1b          # DWARF5
    ref_sup4 = 0x1c       # DWARF5
    strp_sup = 0x1d       # DWARF5
    data16 = 0x1e         # DWARF5
    line_strp = 0x1f      # DWARF5
    ref_sig8 = 0x20
    implicit_const = 0x21 # DWARF5
    loclistx = 0x22       # DWARF5
    rnglistx = 0x23       # DWARF5
    ref_sup8 = 0x24       # DWARF5
    strx1 = 0x25          # DWARF5
    strx2 = 0x26          # DWARF5
    strx3 = 0x27          # DWARF5
    strx4 = 0x28          # DWARF5
    addrx1 = 0x29         # DWARF5
    addrx2 = 0x2a         # DWARF5
    addrx3 = 0x2b         # DWARF5
    addrx4 = 0x2c         # DWARF5
    GNU_addr_index = 0x1f01
    GNU_str_index = 0x1f02
    GNU_ref_alt = 0x1f20
    GNU_strp_alt = 0x1f21

    # # If a DW_FORM has a fixed byte size, it is specified here as a tuple
    # # that represents the size in DWARF32 and DWARF64 respectively.
    # fixed_sizes = {
    #     # Attributes that are 0 bytes in DWARF32 and DWARF64
    #     flag_present: (0, 0),
    #     implicit_const: (0, 0),

    #     # Attributes that are 1 byte in DWARF32 and DWARF64
    #     addrx1: (1, 1),
    #     strx1: (1, 1),
    #     ref1: (1, 1),
    #     data1: (1, 1),
    #     flag: (1, 1),

    #     # Attributes that are 2 bytes in DWARF32 and DWARF64
    #     data2: (2, 2),
    #     addrx2: (2, 2),
    #     strx2: (2, 2),
    #     ref2: (2, 2),

    #     # Attributes that are 3 bytes in DWARF32 and DWARF64
    #     strx3: (3, 3),
    #     addrx3: (3, 3),

    #     # Attributes that are 4 bytes in DWARF32 and DWARF64
    #     data4: (4, 4),
    #     addrx4: (4, 4),
    #     strx4: (4, 4),
    #     ref4: (4, 4),

    #     # Attributes that are 8 bytes in DWARF32 and DWARF64
    #     data8: (8, 8),
    #     ref8: (8, 8),
    #     ref_sig8: (8, 8),

    #     # Attributes that are 16 byets in DWARF32 and DWARF64
    #     data16: (16,16),

    #     # Attributes that are 4 bytes in DWARF32 and 8 bytes in DWARF64
    #     strp: (4, 8),
    #     GNU_strp_alt: (4, 8),
    #     line_strp: (4, 8),
    #     sec_offset: (4, 8),
    #     ref_addr: (4, 8),
    #     GNU_ref_alt: (4, 8),
    # }

    @classmethod
    def max_width(cls):
        return 24
        # max_key_len = 0
        # for key in cls.enum:
        #     key_len = len(key)
        #     if key_len > max_key_len:
        #         max_key_len = key_len
        # return max_key_len

    def __str__(self):
        return 'DW_FORM_' + self.name

    def is_block(self):
        return self in [DW_FORM.block1,
                        DW_FORM.block2,
                        DW_FORM.block4,
                        DW_FORM.block,
                        DW_FORM.exprloc]

    def is_indexed_string(self):
        return self in [DW_FORM.strx,
                        DW_FORM.strx1,
                        DW_FORM.strx2,
                        DW_FORM.strx3,
                        DW_FORM.strx4,
                        DW_FORM.GNU_str_index]

    def get_block_length_size(self):
        '''Get the fixed byte size of a DW_FORM_block* length.

        This allows the attribute value dumping code to display the length
        with the correct hex width.
        '''
        if self == DW_FORM.block1:
            return 1
        elif self == DW_FORM.block2:
            return 2
        elif self == DW_FORM.block4:
            return 4
        return -1  # Not fixed size

    def is_data(self):
        return self in [DW_FORM.data1,
                        DW_FORM.data2,
                        DW_FORM.data4,
                        DW_FORM.data8,
                        DW_FORM.data16,
                        DW_FORM.sdata,
                        DW_FORM.udata]

    def is_indexed_address(self):
        return self in [DW_FORM.addrx,
                        DW_FORM.addrx1,
                        DW_FORM.addrx2,
                        DW_FORM.addrx3,
                        DW_FORM.addrx4]

    def is_section_offset(self):
        # Older DWARF specification specified sections offsets as data, newer
        # DWARF uses DW_FORM_sec_offset.
        return self == DW_FORM.sec_offset

    def is_flag(self):
        return self == DW_FORM.flag or self == DW_FORM.flag_present

    def is_address(self):
        return self == DW_FORM.addr

    def is_reference(self):
        return self in [DW_FORM.ref4,
                        DW_FORM.ref8,
                        DW_FORM.ref1,
                        DW_FORM.ref2,
                        DW_FORM.ref_udata,
                        DW_FORM.ref_addr,
                        DW_FORM.GNU_ref_alt]

    def get_fixed_size(self, dwarf_info=None):
        '''Get the fixed byte size of this form.

        If the returned value is >= 0, then this form has a fixed byte size
        when encoded into a section. If the returned value is < 0, then this
        form has a variable byte size, like LEB128 numbers, inlined C
        strings or blocks of data.
        '''
        if self.value < len(fixed_sizes):
            sizes = fixed_sizes[self.value]
            if sizes is not None:
                if dwarf_info:
                    return sizes[0] if dwarf_info.isDWARF32() else sizes[1]
                if sizes[0] == sizes[1]:
                    return sizes[0]
        if self.value == DW_FORM.addr:
            if dwarf_info:
                return dwarf_info.addr_size
        if self.value in [DW_FORM.GNU_ref_alt, DW_FORM.GNU_strp_alt]:
            if dwarf_info:
                return dwarf_info.dwarf_size
        return -1

    def get_byte_size(self, die, value):
        size = self.get_fixed_size(die.cu.dwarf_info)
        if size >= 0:
            return size
        if self in [DW_FORM.addrx,
                    DW_FORM.loclistx,
                    DW_FORM.rnglistx,
                    DW_FORM.strx,
                    DW_FORM.udata,
                    DW_FORM.ref_udata,
                    DW_FORM.GNU_str_index,
                    DW_FORM.GNU_addr_index]:
            return get_uleb128_byte_size(value)
        elif self == DW_FORM.sdata:
            return get_uleb128_byte_size(value)
        elif self == DW_FORM.string:
            return len(value) + 1
        elif self == DW_FORM.indirect:
            raise ValueError("DW_FORM_indirect not handled yet")
        elif self == DW_FORM.block1:
            return 1 + len(value)
        elif self == DW_FORM.block2:
            return 2 + len(value)
        elif self == DW_FORM.block4:
            return 4 + len(value)
        elif self == DW_FORM.block:
            return get_uleb128_byte_size(len(value)) + len(value)
        elif self == DW_FORM.exprloc:
            return get_uleb128_byte_size(len(value)) + len(value)
        print('error: failed to get byte size of form %s' % (self))
        raise ValueError

    def skip(self, die, data):
        size = self.get_fixed_size(die.cu.dwarf_info)
        if size == 0:
            return True
        if size < 0:
            if self in [DW_FORM.addrx,
                        DW_FORM.loclistx,
                        DW_FORM.rnglistx,
                        DW_FORM.strx,
                        DW_FORM.udata,
                        DW_FORM.ref_udata,
                        DW_FORM.GNU_str_index,
                        DW_FORM.GNU_addr_index]:
                data.get_uleb128()
                return True
            elif self == DW_FORM.sdata:
                data.get_sleb128()
                return True
            elif self == DW_FORM.string:
                data.get_c_string()
                return True
            elif self == DW_FORM.indirect:
                indirect_form = Form(data.get_uleb128())
                return indirect_form.skip(die, data)
            elif self == DW_FORM.block1:
                size = data.get_uint8()
            elif self == DW_FORM.block2:
                size = data.get_uint16()
            elif self == DW_FORM.block4:
                size = data.get_uint32()
            elif self == DW_FORM.block:
                size = data.get_uleb128()
            elif self == DW_FORM.exprloc:
                size = data.get_uleb128()
            else:
                print('error: failed to skip form %s' % (self))
                return False
        if size > 0:
            data.seek(data.tell()+size)
        return True

    def extract_value(self, data, die=None, dwarf=None, dw_sect=None, attr_spec=None):
        block_len = -1
        addr_idx = None
        if self == DW_FORM.strp:
            strp = data.get_offset()
            if dwarf is None and die is not None:
                dwarf = die.cu.debug_info.dwarf
            return (dwarf.get_string(strp), strp)
        elif self == DW_FORM.line_strp:
            strp = data.get_offset()
            if dwarf is None and die is not None:
                dwarf = die.cu.debug_info.dwarf
            return (dwarf.get_line_string(strp), strp)
        elif self == DW_FORM.strx or self == DW_FORM.GNU_str_index:
            str_idx = data.get_uleb128(None)
            if dwarf is None and die is not None:
                dwarf = die.cu.debug_info.dwarf
            return (die.cu.get_string_at_index(str_idx), str_idx)
        elif self == DW_FORM.strx1:
            str_idx = data.get_uint8()
            if dwarf is None and die is not None:
                dwarf = die.cu.debug_info.dwarf
            return (die.cu.get_string_at_index(str_idx), str_idx)
        elif self == DW_FORM.strx2:
            str_idx = data.get_uint16()
            if dwarf is None and die is not None:
                dwarf = die.cu.debug_info.dwarf
            return (die.cu.get_string_at_index(str_idx), str_idx)
        elif self == DW_FORM.strx3:
            str_idx = data.get_uint24()
            if dwarf is None and die is not None:
                dwarf = die.cu.debug_info.dwarf
            return (die.cu.get_string_at_index(str_idx), str_idx)
        elif self == DW_FORM.strx4:
            str_idx = data.get_uint32()
            if dwarf is None and die is not None:
                dwarf = die.cu.debug_info.dwarf
            return (die.cu.get_string_at_index(str_idx), str_idx)
        elif self == DW_FORM.addr:
            return (data.get_address(), None)
        elif self in [DW_FORM.data1, DW_FORM.flag]:
            return (data.get_uint8(), None)
        elif self in [DW_FORM.data2]:
            return (data.get_uint16(), None)
        elif self in [DW_FORM.data4]:
            return (data.get_uint32(), None)
        elif self == DW_FORM.data8:
            return (data.get_uint64(), None)
        elif self == DW_FORM.data16:
            return (data.get_uint128(), None)
        elif self == DW_FORM.addrx:
            addr_idx = data.get_uleb128()
        elif self == DW_FORM.addrx1:
            addr_idx = data.get_uint8()
        elif self == DW_FORM.addrx2:
            addr_idx = data.get_uint16()
        elif self == DW_FORM.addrx3:
            addr_idx = data.get_uint24()
        elif self == DW_FORM.addrx4:
            addr_idx = data.get_uint32()
        elif self in [DW_FORM.loclistx,
                      DW_FORM.rnglistx,
                      DW_FORM.udata,
                      DW_FORM.GNU_addr_index]:
            return (data.get_uleb128(), None)
        elif self == DW_FORM.sdata:
            return (data.get_sleb128(), None)
        elif self == DW_FORM.string:
            return (data.get_c_string(), None)
        elif self == DW_FORM.block1:
            block_len = data.get_uint8()
        elif self == DW_FORM.block2:
            block_len = data.get_uint16()
        elif self == DW_FORM.block4:
            block_len = data.get_uint32()
        elif self == DW_FORM.block:
            block_len = data.get_uleb128()
        elif self == DW_FORM.exprloc:
            block_len = data.get_uleb128()
        elif self == DW_FORM.ref1:
            cu_rel_offset = data.get_uint8()
            return (die.cu.offset + cu_rel_offset, cu_rel_offset)
        elif self == DW_FORM.ref2:
            cu_rel_offset = data.get_uint16()
            return (die.cu.offset + cu_rel_offset, cu_rel_offset)
        elif self == DW_FORM.ref4:
            cu_rel_offset = data.get_uint32()
            if die:
                return (die.cu.offset + cu_rel_offset, cu_rel_offset)
            else:
                return (cu_rel_offset, None)
        elif self == DW_FORM.ref8:
            cu_rel_offset = data.get_uint64()
            return (die.cu.offset + cu_rel_offset, cu_rel_offset)
        elif self == DW_FORM.ref_udata:
            cu_rel_offset = data.get_uleb128()
            return (die.cu.offset + cu_rel_offset, cu_rel_offset)
        elif self == DW_FORM.GNU_ref_alt:
            fixed_size = self.get_fixed_size(die.cu.dwarf_info)
            return (data.get_uint_size(fixed_size, 0), None)
        elif self == DW_FORM.GNU_strp_alt:
            fixed_size = self.get_fixed_size(die.cu.dwarf_info)
            return (data.get_uint_size(fixed_size, 0), None)
        elif self == DW_FORM.sec_offset:
            fixed_size = self.get_fixed_size(die.cu.dwarf_info)
            value = data.get_uint_size(fixed_size, 0)
            if dw_sect is not None:
                return (die.cu.relocate_offset(value, dw_sect), value)
            return (value, None)
        elif self == DW_FORM.flag_present:
            return (1, None)
        elif self == DW_FORM.ref_sig8:
            return (data.get_uint64(), None)
        elif self == DW_FORM.ref_addr:
            fixed_size = self.get_fixed_size(die.cu.dwarf_info)
            return (data.get_uint_size(fixed_size, 0), None)
        elif self == DW_FORM.indirect:
            indirect_form = DW_FORM(data.get_uleb128())
            return indirect_form.extract_value(data, die=die)
        elif self == DW_FORM.implicit_const:
            if attr_spec is None:
                raise ValueError("DW_FORM.implicit_const requires attr_spec")
            return (attr_spec.implicit_const, None)
        # Extract a block of data
        if block_len >= 0:
            return (data.read_size(block_len), None)
        # Extract an indexed address
        if addr_idx is not None:
            addr = die.cu.get_indexed_address(addr_idx)
            if addr is None:
                return (addr_idx, None)
            else:
                return (addr, addr_idx)
        raise ValueError('unhandled DW_FORM: %s' % (self))

    def encode_dwarfdb(self, die, data, value):
        print(' -> %s (%s) %s' % (self, type(value), value))
        if self == DW_FORM.strp:
            data.put_c_string(value)
        elif self == DW_FORM.addr:
            data.put_address(value)
        elif self == DW_FORM.data1:
            data.put_uint8(value)
        elif self == DW_FORM.data2:
            data.put_uint16(value)
        elif self == DW_FORM.data4:
            data.put_uint32(value)
        elif self == DW_FORM.data8:
            data.put_uint64(value)
        elif self == DW_FORM.udata:
            data.put_uleb128(value)
        elif self == DW_FORM.sdata:
            data.put_sleb128(value)
        elif self == DW_FORM.string:
            data.put_c_string(value)
        elif self == DW_FORM.block1:
            data.put_uint8(len(value))
            data.file.write(value)
        elif self == DW_FORM.block2:
            data.put_uint16(len(value))
            data.file.write(value)
        elif self == DW_FORM.block4:
            data.put_uint32(len(value))
            data.file.write(value)
        elif self == DW_FORM.block:
            data.put_uleb128(len(value))
            data.file.write(value)
        elif self == DW_FORM.exprloc:
            data.put_uleb128(len(value))
            data.file.write(value)
        elif self == DW_FORM.flag:
            if value:
                data.put_uint8(1)
            else:
                data.put_uint8(0)
        elif self == DW_FORM.ref1:
            data.put_uint8(value - die.cu.offset)
        elif self == DW_FORM.ref2:
            data.put_uint16(value - die.cu.offset)
        elif self == DW_FORM.ref4:
            data.put_uint32(value - die.cu.offset)
        elif self == DW_FORM.ref8:
            data.put_uint64(value - die.cu.offset)
        elif self == DW_FORM.ref_udata:
            data.put_uleb128(value - die.cu.offset)
        elif self == DW_FORM.sec_offset:
            int_size = self.get_fixed_size(die.cu.dwarf_info)
            data.put_uint_size(int_size, value)
        elif self == DW_FORM.flag_present:
            pass
        elif self == DW_FORM.ref_sig8:
            data.put_uint64(value)
        elif self == DW_FORM.ref_addr:
            int_size = self.get_fixed_size(die.cu.dwarf_info)
            data.put_uint_size(int_size, value)
        elif self == DW_FORM.indirect:
            raise ValueError("DW_FORM_indirect isn't handled")
        else:
            ValueError("DW_FORM 0x%4.4x isn't handled" % (self))

    def fixed_str(self):
        return "%-*s" % (self.max_width(), str(self))

    # We might parse DWARF with user defined attributes. We need to support
    # displaying these unknown attributes.
    @classmethod
    def _missing_(cls, value):
        if isinstance(value, int):
            return cls.create_pseudo_member_(value)
        return None # will raise the ValueError in Enum.__new__

    @classmethod
    def create_pseudo_member_(cls, value):
        pseudo_member = cls._value2member_map_.get(value, None)
        if pseudo_member is None:
            new_member = int.__new__(cls, value)
            new_member._name_ = '_unknown_%4.4x' % value
            new_member._value_ = value
            pseudo_member = cls._value2member_map_.setdefault(value, new_member)
        return pseudo_member
