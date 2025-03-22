#!/usr/bin/python

from enum import IntEnum


class DW_ACCESS(IntEnum):
    public = 0x01
    protected = 0x02
    private = 0x03

    def __str__(self):
        return 'DW_ACCESS_' + self.name
