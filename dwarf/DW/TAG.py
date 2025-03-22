#!/usr/bin/python

from enum import IntEnum

# DWARF DW_TAG defines
class DW_TAG(IntEnum):
    null = 0x0000
    array_type = 0x0001
    class_type = 0x0002
    entry_point = 0x0003
    enumeration_type = 0x0004
    formal_parameter = 0x0005
    imported_declaration = 0x0008
    label = 0x000A
    lexical_block = 0x000B
    member = 0x000D
    pointer_type = 0x000F
    reference_type = 0x0010
    compile_unit = 0x0011
    string_type = 0x0012
    structure_type = 0x0013
    subroutine_type = 0x0015
    typedef = 0x0016
    union_type = 0x0017
    unspecified_parameters = 0x0018
    variant = 0x0019
    common_block = 0x001A
    common_inclusion = 0x001B
    inheritance = 0x001C
    inlined_subroutine = 0x001D
    module = 0x001E
    ptr_to_member_type = 0x001F
    set_type = 0x0020
    subrange_type = 0x0021
    with_stmt = 0x0022
    access_declaration = 0x0023
    base_type = 0x0024
    catch_block = 0x0025
    const_type = 0x0026
    constant = 0x0027
    enumerator = 0x0028
    file_type = 0x0029
    friend = 0x002A
    namelist = 0x002B
    namelist_item = 0x002C
    packed_type = 0x002D
    subprogram = 0x002E
    template_type_parameter = 0x002F
    template_value_parameter = 0x0030
    thrown_type = 0x0031
    try_block = 0x0032
    variant_part = 0x0033
    variable = 0x0034
    volatile_type = 0x0035
    dwarf_procedure = 0x0036
    restrict_type = 0x0037
    interface_type = 0x0038
    namespace = 0x0039
    imported_module = 0x003A
    unspecified_type = 0x003B
    partial_unit = 0x003C
    imported_unit = 0x003D
    condition = 0x003F
    shared_type = 0x0040
    type_unit = 0x0041
    rvalue_reference_type = 0x0042
    template_alias = 0x0043
    coarray_type = 0x44
    generic_subrange = 0x45
    dynamic_type = 0x46
    atomic_type = 0x47
    call_site = 0x48
    call_site_parameter = 0x49
    skeleton_unit = 0x4a
    immutable_type = 0x4b
    MIPS_loop = 0x4081
    format_label = 0x4101
    function_template = 0x4102
    class_template = 0x4103
    GNU_template_template_param = 0x4106
    GNU_template_parameter_pack = 0x4107
    GNU_formal_parameter_pack = 0x4108
    GNU_call_site = 0x4109
    GNU_call_site_parameter = 0x410a
    APPLE_Property = 0x4200
    lo_user = 0x4080
    hi_user = 0xFFFF

    def __str__(self):
        return 'DW_TAG_' + self.name

    def is_null(self):
        return self == DW_TAG.null

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

    def is_type(self):
        '''Return true if the tag represents a type'''
        return self.get_enum_value() in [
                DW_TAG.class_type,
                DW_TAG.enumeration_type,
                DW_TAG.string_type,
                DW_TAG.structure_type,
                DW_TAG.union_type,
                DW_TAG.set_type,
                DW_TAG.base_type,
                DW_TAG.packed_type,
                DW_TAG.thrown_type,
                DW_TAG.interface_type,
                DW_TAG.unspecified_type,
                DW_TAG.shared_type]

    def is_decl_context(self):
        return self.get_enum_value() in [
                DW_TAG.class_type,
                DW_TAG.enumeration_type,
                DW_TAG.structure_type,
                DW_TAG.union_type,
                DW_TAG.namespace,
                DW_TAG.subprogram]

    def is_function(self):
        return self == DW_TAG.subprogram

    def has_pointer_size(self):
        return self.get_enum_value() in [
                DW_TAG.pointer_type,
                DW_TAG.reference_type,
                DW_TAG.ptr_to_member_type]

    def get_type_kind(self):
        '''Return a type kind string.'''
        tag = self.get_enum_value()
        if tag == DW_TAG.class_type:
            return 'class'
        if tag == DW_TAG.structure_type:
            return 'struct'
        if tag == DW_TAG.enumeration_type:
            return 'enum'
        if tag == DW_TAG.string_type:
            return 'DW_TAG.string_type'
        if tag == DW_TAG.union_type:
            return 'union'
        if tag == DW_TAG.set_type:
            return 'DW_TAG_set_type'
        if tag == DW_TAG.base_type:
            return 'DW_TAG_base_type'
        if tag == DW_TAG.packed_type:
            return 'DW_TAG_packed_type'
        if tag == DW_TAG.thrown_type:
            return 'DW_TAG_thrown_type'
        if tag == DW_TAG.interface_type:
            return 'DW_TAG_interface_type'
        if tag == DW_TAG.unspecified_type:
            return 'DW_TAG_unspecified_type'
        if tag == DW_TAG.shared_type:
            return 'DW_TAG_shared_type'
        if tag == DW_TAG.namespace:
            return 'namespace'
        return None

    def is_variable(self):
        e = self.get_enum_value()
        return e in [DW_TAG.variable, DW_TAG.formal_parameter]

    @classmethod
    def max_width(cls):
        return 34
