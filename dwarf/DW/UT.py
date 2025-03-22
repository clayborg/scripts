#!/usr/bin/python

from enum import IntEnum


class DW_UT(IntEnum):
    null = 0x00
    compile = 0x01
    type = 0x02
    partial = 0x03
    skeleton = 0x04
    split_compile = 0x05
    split_type = 0x06
    lo_user = 0x80
    hi_user = 0xff

    def __str__(self):
        return 'DW_UT_' + self.name
