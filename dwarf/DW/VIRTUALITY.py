#!/usr/bin/python

from enum import IntEnum

DW_VIRTUALITY_none = 0x00
DW_VIRTUALITY_virtual = 0x01
DW_VIRTUALITY_pure_virtual = 0x02


class DW_VIRTUALITY(IntEnum):
    none = 0x00
    virtual = 0x01
    pure_virtual = 0x02

    def __str__(self):
        return 'DW_VIRTUALITY_' + self.name
