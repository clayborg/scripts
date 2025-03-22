#!/usr/bin/python

from enum import IntEnum


class DW_LANG(IntEnum):
    C89 = 0x0001
    C = 0x0002
    Ada83 = 0x0003
    C_plus_plus = 0x0004
    Cobol74 = 0x0005
    Cobol85 = 0x0006
    Fortran77 = 0x0007
    Fortran90 = 0x0008
    Pascal83 = 0x0009
    Modula2 = 0x000A
    Java = 0x000B
    C99 = 0x000C
    Ada95 = 0x000D
    Fortran95 = 0x000E
    PLI = 0x000F
    ObjC = 0x0010
    ObjC_plus_plus = 0x0011
    UPC = 0x0012
    D = 0x0013
    Python = 0x0014
    OpenCL = 0x0015
    Go = 0x0016
    Modula3 = 0x0017
    Haskell = 0x0018
    C_plus_plus_03 = 0x0019
    C_plus_plus_11 = 0x001a
    OCaml = 0x001b
    Rust = 0x001c
    C11 = 0x001d
    Swift = 0x001e
    Julia = 0x001f
    Dylan = 0x0020
    C_plus_plus_14 = 0x0021
    Fortran03 = 0x0022
    Fortran08 = 0x0023
    RenderScript = 0x0024
    BLISS = 0x0025
    lo_user = 0x8000
    hi_user = 0xFFFF

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
