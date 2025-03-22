#!/usr/bin/python

from enum import IntEnum

class DW_ATE(IntEnum):
    address = 0x01
    boolean = 0x02
    complex_float = 0x03
    float = 0x04
    signed = 0x05
    signed_char = 0x06
    unsigned = 0x07
    unsigned_char = 0x08
    imaginary_float = 0x09
    packed_decimal = 0x0A
    numeric_string = 0x0B
    edited = 0x0C
    signed_fixed = 0x0D
    unsigned_fixed = 0x0E
    decimal_float = 0x0F
    UTF = 0x10
    lo_user = 0x80
    hi_user = 0xFF

    def __str__(self):
        return 'DW_ATE_' + self.name
