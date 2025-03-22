#!/usr/bin/python


class Info:
    '''DWARF parse information.

    This information continas the DWARF version, address byte size,
    and DWARF32/DWARF64, and byte order.
    '''
    def __init__(self, version, addr_size, dwarf_size, byte_order='='):
        self.version = version  # DWARF version number
        self.addr_size = addr_size  # Size in bytes of an address
        self.dwarf_size = dwarf_size  # 4 for DWARF32 or 8 for DWARF64
        self.byte_order = byte_order

    def isDWARF32(self):
        return self.dwarf_size == 4
