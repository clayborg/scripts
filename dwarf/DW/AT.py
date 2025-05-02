#!/usr/bin/python

from enum import IntEnum

class DW_AT(IntEnum):
    sibling = 0x0001
    location = 0x0002
    name = 0x0003
    ordering = 0x0009
    byte_size = 0x000B
    bit_offset = 0x000C
    bit_size = 0x000D
    stmt_list = 0x0010
    low_pc = 0x0011
    high_pc = 0x0012
    language = 0x0013
    discr = 0x0015
    discr_value = 0x0016
    visibility = 0x0017
    Import = 0x0018  # Uppercase to not interfere with "import" keyboard
    string_length = 0x0019
    common_reference = 0x001A
    comp_dir = 0x001B
    const_value = 0x001C
    containing_type = 0x001D
    default_value = 0x001E
    inline = 0x0020
    is_optional = 0x0021
    lower_bound = 0x0022
    producer = 0x0025
    prototyped = 0x0027
    return_addr = 0x002A
    start_scope = 0x002C
    bit_stride = 0x002E
    upper_bound = 0x002F
    abstract_origin = 0x0031
    accessibility = 0x0032
    address_class = 0x0033
    artificial = 0x0034
    base_types = 0x0035
    calling_convention = 0x0036
    count = 0x0037
    data_member_location = 0x0038
    decl_column = 0x0039
    decl_file = 0x003A
    decl_line = 0x003B
    declaration = 0x003C
    discr_list = 0x003D
    encoding = 0x003E
    external = 0x003F
    frame_base = 0x0040
    friend = 0x0041
    identifier_case = 0x0042
    macro_info = 0x0043
    namelist_item = 0x0044
    priority = 0x0045
    segment = 0x0046
    specification = 0x0047
    static_link = 0x0048
    type = 0x0049
    use_location = 0x004A
    variable_parameter = 0x004B
    virtuality = 0x004C
    vtable_elem_location = 0x004D
    allocated = 0x004E
    associated = 0x004F
    data_location = 0x0050
    byte_stride = 0x0051
    entry_pc = 0x0052
    use_UTF8 = 0x0053
    extension = 0x0054
    ranges = 0x0055
    trampoline = 0x0056
    call_column = 0x0057
    call_file = 0x0058
    call_line = 0x0059
    description = 0x005A
    binary_scale = 0x005B
    decimal_scale = 0x005C
    small = 0x005D
    decimal_sign = 0x005E
    digit_count = 0x005F
    picture_string = 0x0060
    mutable = 0x0061
    threads_scaled = 0x0062
    explicit = 0x0063
    object_pointer = 0x0064
    endianity = 0x0065
    elemental = 0x0066
    pure = 0x0067
    recursive = 0x0068
    signature = 0x0069
    main_subprogram = 0x006a
    data_bit_offset = 0x006b
    const_expr = 0x006c
    enum_class = 0x006d
    linkage_name = 0x006e
    string_length_bit_size = 0x006f
    string_length_byte_size = 0x0070
    rank = 0x0071
    str_offsets_base = 0x0072
    addr_base = 0x0073
    ranges_base = 0x0074
    dwo_id = 0x0075
    dwo_name = 0x0076
    reference = 0x0077
    rvalue_reference = 0x0078
    macros = 0x79
    call_all_calls = 0x7a
    call_all_source_calls = 0x7b
    call_all_tail_calls = 0x7c
    call_return_pc = 0x7d
    call_value = 0x7e
    call_origin = 0x7f
    call_parameter = 0x80
    call_pc = 0x81
    call_tail_call = 0x82
    call_target = 0x83
    call_target_clobbered = 0x84
    call_data_location = 0x85
    call_data_value = 0x86
    noreturn = 0x87
    alignment = 0x88
    export_symbols = 0x89
    deleted = 0x8a
    defaulted = 0x8b
    loclists_base = 0x8c
    lo_user = 0x2000
    hi_user = 0x3FFF
    MIPS_fde = 0x2001
    MIPS_loop_begin = 0x2002
    MIPS_tail_loop_begin = 0x2003
    MIPS_epilog_begin = 0x2004
    MIPS_loop_unroll_factor = 0x2005
    MIPS_software_pipeline_depth = 0x2006
    MIPS_linkage_name = 0x2007
    MIPS_stride = 0x2008
    MIPS_abstract_name = 0x2009
    MIPS_clone_origin = 0x200A
    MIPS_has_inlines = 0x200B
    MIPS_stride_byte = 0x200C
    MIPS_stride_elem = 0x200D
    MIPS_ptr_dopetype = 0x200E
    MIPS_allocatable_dopetype = 0x200F
    MIPS_assumed_shape_dopetype = 0x2010
    MIPS_assumed_size = 0x2011
    sf_names = 0x2101
    src_info = 0x2102
    mac_info = 0x2103
    src_coords = 0x2104
    body_begin = 0x2105
    body_end = 0x2106
    GNU_vector = 0x2107
    GNU_guarded_by = 0x2108
    GNU_pt_guarded_by = 0x2109
    GNU_guarded = 0x210a
    GNU_pt_guarded = 0x210b
    GNU_locks_excluded = 0x210c
    GNU_exclusive_locks_required = 0x210d
    GNU_shared_locks_required = 0x210e
    GNU_odr_signature = 0x210f
    GNU_template_name = 0x2110
    GNU_call_site_value = 0x2111
    GNU_call_site_data_value = 0x2112
    GNU_call_site_target = 0x2113
    GNU_call_site_target_clobbered = 0x2114
    GNU_tail_call = 0x2115
    GNU_all_tail_call_sites = 0x2116
    GNU_all_call_sites = 0x2117
    GNU_all_source_call_sites = 0x2118
    GNU_macros = 0x2119
    GNU_dwo_name = 0x2130
    GNU_dwo_id = 0x2131
    GNU_ranges_base = 0x2132
    GNU_addr_base = 0x2133
    GNU_pubnames = 0x2134
    GNU_pubtypes = 0x2135
    GNU_discriminator = 0x2136
    GNU_numerator = 0x2303
    GNU_denominator = 0x2304
    GNU_bias = 0x2305
    APPLE_repository_file = 0x2501
    APPLE_repository_type = 0x2502
    APPLE_repository_name = 0x2503
    APPLE_repository_specification = 0x2504
    APPLE_repository_import = 0x2505
    APPLE_repository_abstract_origin = 0x2506
    LLVM_sysroot = 0x3E02
    APPLE_optimized = 0x3FE1
    APPLE_flags = 0x3FE2
    APPLE_isa = 0x3FE3
    APPLE_block = 0x3FE4
    APPLE_major_runtime_vers = 0x3FE5
    APPLE_runtime_class = 0x3FE6
    APPLE_omit_frame_ptr = 0x3FE7
    APPLE_property_name = 0x3fe8
    APPLE_property_getter = 0x3fe9
    APPLE_property_setter = 0x3fea
    APPLE_property_attribute = 0x3feb
    APPLE_objc_complete_type = 0x3fec
    APPLE_property = 0x3fed
    APPLE_sdk = 0x3FEF

    def __str__(self):
        return 'DW_AT_' + self.name

    @classmethod
    def max_width(cls):
        return 24

    def fixed_str(self):
        return "%-*s" % (self.max_width(), str(self))

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
