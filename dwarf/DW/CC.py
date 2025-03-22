#!/usr/bin/python
from enum import IntEnum

class DW_CC(IntEnum):
    normal = 0x01
    program = 0x02
    nocall = 0x03
    pass_by_reference = 0x04
    pass_by_value = 0x05
    lo_user = 0x40
    hi_user = 0xFF

    def __str__(self):
        return self.__class__.__name__ + '_' + self.name

    # We might parse DWARF with user defined attributes. We need to support
    # displaying these unknown attributes.
    @classmethod
    def _missing_(cls, value):
        if isinstance(value, int):
            return cls._create_pseudo_member_(value)
        return None # will raise the ValueError in Enum.__new__

    @classmethod
    def _create_pseudo_member_(cls, value):
        pseudo_member = cls._value2member_map_.get(value, None)
        if pseudo_member is None:
            new_member = int.__new__(cls, value)
            new_member._name_ = '_unknown_%4.4x' % value
            new_member._value_ = value
            pseudo_member = cls._value2member_map_.setdefault(value, new_member)
        return pseudo_member
