#!/usr/bin/python

from enum import IntEnum


class DW_SECT(IntEnum):
    INFO = 1
    TYPES = 2
    ABBREV = 3
    LINE = 4
    LOC = 5
    STR_OFFSETS = 6
    MACINFO = 7
    MACRO = 8

    def __str__(self):
        return 'DW_SECT_' + self.name
