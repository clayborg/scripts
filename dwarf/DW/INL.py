#!/usr/bin/python

from enum import IntEnum


class DW_INL(IntEnum):
    not_inlined = 0x00
    inlined = 0x01
    declared_not_inlined = 0x02
    declared_inlined = 0x03

    def __str__(self):
        return 'DW_INL_' + self.name
