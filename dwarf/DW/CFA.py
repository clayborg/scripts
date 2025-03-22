#!/usr/bin/python

from enum import IntEnum


class DW_CFA(IntEnum):
    null = 0
    advance_loc = 0x40
    offset = 0x80
    restore = 0xC0
    nop = 0x00
    set_loc = 0x01
    advance_loc1 = 0x02
    advance_loc2 = 0x03
    advance_loc4 = 0x04
    offset_extended = 0x05
    restore_extended = 0x06
    undefined = 0x07
    same_value = 0x08
    register = 0x09
    remember_state = 0x0A
    restore_state = 0x0B
    def_cfa = 0x0C
    def_cfa_register = 0x0D
    def_cfa_offset = 0x0E
    def_cfa_expression = 0x0F
    expression = 0x10
    offset_extended_sf = 0x11
    def_cfa_sf = 0x12
    def_cfa_offset_sf = 0x13
    val_offset = 0x14
    val_offset_sf = 0x15
    val_expression = 0x16
    GNU_window_save = 0x2D
    GNU_args_size = 0x2E
    GNU_negative_offset_extended = 0x2F
    lo_user = 0x1C
    hi_user = 0x3F

    def is_null(self):
        return self == DW_CFA.null

    @classmethod
    def max_width(cls):
        max_key_len = 0
        for key in cls.enum:
            key_len = len(key)
            if key_len > max_key_len:
                max_key_len = key_len
        return max_key_len
