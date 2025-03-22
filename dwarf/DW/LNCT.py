#!/usr/bin/python

from enum import IntEnum


class DW_LNCT(IntEnum):
    null = 0
    path = 1
    directory_index = 2
    timestamp = 3
    size = 4
    MD5 = 5

    def __str__(self):
        return 'DW_LNCT_' + self.name
