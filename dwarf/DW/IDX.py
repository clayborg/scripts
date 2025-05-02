#!/usr/bin/python

from enum import IntEnum

class DW_IDX(IntEnum):
    compile_unit = 1
    type_unit = 2
    die_offset = 3
    parent = 4
    type_hash = 5

    @classmethod
    def max_width(cls):
        return 19

    def __str__(self):
        return 'DW_IDX_' + self.name

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
