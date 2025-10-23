#!/usr/bin/python3

# import lldb
import optparse
import shlex

from dwarf.generator import *
from dwarf.DW.AT import DW_AT
from dwarf.DW.FORM import DW_FORM
from dwarf.DW.TAG import DW_TAG
from dwarf.DW.ATE import *
from dwarf.ranges import AddressRange, AddressRangeList
import dwarf.parse

program = 'dwarfgen'


def create_options():
    usage = "usage: %prog [options]"
    description = ('A DWARF generator. Edit the code in the main function '
                   'to create the DWARF contents that are desired and run '
                   'this script to generate the DWARF.')

    parser = optparse.OptionParser(
        description=description,
        prog=program,
        usage=usage,
        add_help_option=True)

    parser.add_option(
        '-o', '--out',
        type='string',
        dest='outfile',
        help='The path to the DWARF file to generate',
        default="/tmp/a.out")
    parser.add_option(
        '-v', '--version',
        type='int',
        dest='version',
        help='The DWARF version to generate (default is 4).',
        default=4)
    parser.add_option(
        '-a', '--addr-size',
        type='int',
        dest='addr_size',
        help='The DWARF address byte size (default is 8).',
        default=8)
    parser.add_option(
        '-b', '--byte-order',
        type='string',
        dest='byte_order',
        help=('The byte order whose value is one of "big", "little" or '
              '"native" (default is "native").'),
        default="native")
    parser.add_option(
        '--dwarf-size',
        type='int',
        dest='dwarf_size',
        help='The size if bytes of an offset in DWARF (default is 4).',
        default=4)
    parser.add_option(
        '--debug-aranges',
        action='store_true',
        dest='generate_debug_aranges',
        help='Auto generate a .debug_aranges.',
        default=False)
    parser.add_option(
        '--cu-ranges',
        action='store_true',
        dest='generate_cu_ranges',
        help='Auto generate the DW_AT.ranges for each compile unit.',
        default=False)
    return parser


def generate_dwarf(options, args):

    dwarf_info = dwarf.parse.Info(addr_size=options.addr_size,
                                  version=options.version,
                                  dwarf_size=options.dwarf_size,
                                  byte_order=options.byte_order)

    dwarfgen = DWARF(dwarf_info)

    # cu = dwarfgen.addCompileUnit(DW_TAG.compile_unit)
    # attr_name = cu.die.addAttribute(DW_AT.name, DW_FORM_strp, "main.c")
    # cu = dwarfgen.addCompileUnit(DW_TAG.compile_unit)
    # attr_name = cu.die.addAttribute(DW_AT.name, DW_FORM_strp, "./main.c")
    # cu = dwarfgen.addCompileUnit(DW_TAG.compile_unit)
    # attr_name = cu.die.addAttribute(DW_AT.name, DW_FORM_strp, ".//main.c")
    # infos = [
    #     # Test "." in paths
    #     (".", "main.c", "./main.c"),
    #     ("./", "main.c", "./main.c"),
    #     ("././././.", "main.c", "./main.c"),
    #     ("./././././", "main.c", "./main.c"),
    #     # Test ".." in paths
    #     ("/..", "main.c", "/main.c"),
    #     ("/../..", "main.c", "/main.c"),
    #     ("..", "main.c", "../main.c"),
    #     ("../..", "main.c", "../../main.c"),
    #     ("/foo/..", "main.c", "/main.c"),
    #     ("/foo/../", "main.c", "/main.c"),
    #     ("/foo/bar/..", "main.c", "/foo/main.c"),
    #     ("/foo/bar/../", "main.c", "/foo/main.c"),
    #     ("/foo/bar/../baz/..", "main.c", "/foo/main.c"),
    #     ("/foo/bar/../baz/../", "main.c", "/foo/main.c"),
    #     # Test normal paths
    #     (None, "main.c", "main.c"),
    #     (None, "/main.c", "/main.c"),
    #     # Test relative paths
    #     ("./bbb", "aaa/main.c", "./bbb/aaa/main.c"),
    #     ("./bbb/", "aaa/main.c", "./bbb/aaa/main.c"),
    #     ("bbb", "aaa/main.c", "bbb/aaa/main.c"),
    #     ("bbb/", "aaa/main.c", "bbb/aaa/main.c"),
    #     # Test // at start of path, they must be left untouched
    #     ("//", "usr", "//usr"),
    #     (None, "//usr", "//usr"),
    #     # Test // at middle of path, they can be reduced to a single /
    #     ("/aaa//", "bbb", "/aaa/bbb"),
    #     (None, "/aaa//bbb", "/aaa/bbb"),
    #     ("/aaa//////", "bbb", "/aaa/bbb"),
    #     (None, "/aaa//////bbb", "/aaa/bbb"),
    #     (None, "/aaa//bbb//ccc", "/aaa/bbb/ccc"),
    #     (None, "/aaa//bbb//ccc/", "/aaa/bbb/ccc"),
    #     (None, "/aaa//bbb//ccc//", "/aaa/bbb/ccc"),

    # ]
    # for info in infos:
    #     cu = dwarfgen.addCompileUnit(DW_TAG.compile_unit)
    #     attr_name = cu.die.addAttribute(DW_AT.name, DW_FORM_strp, info[1])
    #     if info[0]:
    #         attr_name = cu.die.addAttribute(DW_AT.comp_dir, DW_FORM_strp,
    #                                         info[0])

    # cu = dwarfgen.addCompileUnit(DW_TAG.compile_unit)
    # attr_name = cu.die.addAttribute(DW_AT.name, DW_FORM_strp, "main.c")
    # attr_name = cu.die.addAttribute(DW_AT.comp_dir, DW_FORM_strp, "/../..")
    #
    # cu = dwarfgen.addCompileUnit(DW_TAG.compile_unit)
    # attr_name = cu.die.addAttribute(DW_AT.name, DW_FORM_strp, ".//bar/main.c")

    # cu2 = dwarfgen.addCompileUnit(DW_TAG.compile_unit)

    cu1 = dwarfgen.addCompileUnit(DW_TAG.compile_unit)
    cu1_path = "main.cpp"
    cu1.die.addAttribute(DW_AT.name, DW_FORM.strp, cu1_path)
    cu1.die.addAttribute(DW_AT.language, DW_FORM.udata, 2)

# 0x00000025:   DW_TAG.base_type
#                 DW_AT.name	("char")
#                 DW_AT.encoding	(DW_ATE.signed_char)
#                 DW_AT.byte_size	(0x01)

    char_type_die = cu1.die.addBaseTypeChild("int", DW_ATE.signed_char, 4)


# 0x00000029:   DW_TAG.base_type
#                 DW_AT.name	("__ARRAY_SIZE_TYPE__")
#                 DW_AT.byte_size	(0x08)
#                 DW_AT.encoding	(DW_ATE.unsigned)

    array_size_type_die = cu1.die.addBaseTypeChild("__ARRAY_SIZE_TYPE__",
                                                   DW_ATE.unsigned,
                                                   8)

# 0x00000065:   DW_TAG.array_type
#                 DW_AT.type	(0x0000000000000025 "char")

# 0x0000006a:     DW_TAG.subrange_type
#                   DW_AT.type	(0x0000000000000029 "__ARRAY_SIZE_TYPE__")
#                   DW_AT.count	(0x20)

# 0x00000070:     NULL

    array_type_die = cu1.die.addChild(DW_TAG.array_type)
    array_type_die.addReferenceAttribute(DW_AT.type, char_type_die)

    union_byte_size = 0x20
    subrange_type_die = array_type_die.addChild(DW_TAG.subrange_type)
    subrange_type_die.addReferenceAttribute(DW_AT.type, array_size_type_die)
    subrange_type_die.addDataAttribute(DW_AT.count, union_byte_size)

    # 0x0000004c:   DW_TAG_union_type
    #                 DW_AT_calling_convention	(DW_CC_pass_by_value)
    #                 DW_AT_name	("UnionType")
    #                 DW_AT_byte_size	(0x20)
    #                 DW_AT_decl_file	("/Users/gclayton/Documents/src/union/main.cpp")
    #                 DW_AT_decl_line	(3)

    # 0x00000052:     DW_TAG_member
    #                   DW_AT_name	("value")
    #                   DW_AT_type	(0x0000000000000048 "int")
    #                   DW_AT_decl_file	("/Users/gclayton/Documents/src/union/main.cpp")
    #                   DW_AT_decl_line	(4)
    #                   DW_AT_data_member_location	(0x00)

    union_type_die = cu1.die.addChild(DW_TAG.union_type)
    union_type_die.addNameAttribute("UnionType")
    union_type_die.addDataAttribute(DW_AT.byte_size, union_byte_size)

    union_member1 = union_type_die.addChild(DW_TAG.member)
    union_member1.addNameAttribute("array")
    union_member1.addReferenceAttribute(DW_AT.type, array_type_die)

    func_die = cu1.die.addChild(DW_TAG.subprogram)
    func_die.addRangeAttributes(0x1000, 0x1050)
    func_die.addAttribute(DW_AT.name, DW_FORM.string, "foo")
    func_die.addReferenceAttribute(DW_AT.type, union_member1)

    # func_die.addAttribute(DW_AT.ranges, DW_FORM_sec_offset, func_ranges)

    # namespace_a_die = cu1.die.addChild(DW_TAG.namespace)
    # namespace_a_die.addAttribute(DW_AT.name, DW_FORM.string, "a")

    # a_foo_die = namespace_a_die.addChild(DW_TAG.structure_type)
    # a_foo_die.addAttribute(DW_AT.name, DW_FORM.string, "struct_t")



    # inline_path = "/tmp/inline.h"
    # cu1.add_line_entry(cu1_path, 10, 0x1000)
    # cu1.add_line_entry(cu1_path, 11, 0x1010)
    # cu1.add_line_entry(inline_path, 20, 0x1100)
    # cu1.add_line_entry(cu1_path, 12, 0x1010)
    # cu1.add_line_entry(cu1_path, 13, 0x1050, True)

    # func_die = cu1.die.addChild(DW_TAG.subprogram)
    # func_die.addAttribute(DW_AT.name, DW_FORM_strp, "bar")
    # # func_die.addAttribute(DW_AT.linkage_name, DW_FORM_strp, "")
    # # func_die.addAttribute(DW_AT.ranges, DW_FORM_sec_offset, func_ranges)
    # func_die.addRangeAttributes(0x1000, 0x1100)

    # inline_ranges = AddressRangeList()
    # inline_ranges.append(AddressRange(0x1010, 0x1040))
    # inline_ranges.append(AddressRange(0x2010, 0x2040))
    # inline_ranges.append(AddressRange(0x3010, 0x3040))


    # inline_die = func_die.addChild(DW_TAG.inlined_subroutine)
    # inline_die.addAttribute(DW_AT.name, DW_FORM_strp, "inline_with_invalid_call_file")
    # inline_die.addRangeAttributes(0x1010, 0x1020)
    # inline_die.addAttribute(DW_AT.call_file, DW_FORM_data4, 10)
    # inline_die.addAttribute(DW_AT.call_line, DW_FORM_data4, 11)

    # inline_die = inline_die.addChild(DW_TAG.inlined_subroutine)
    # inline_die.addAttribute(DW_AT.name, DW_FORM_strp, "inline_inside_parent_with_invalid_call_file")
    # inline_die.addRangeAttributes(0x1010, 0x1015)
    # inline_die.addAttribute(DW_AT.call_file, DW_FORM_data4, 1)
    # inline_die.addAttribute(DW_AT.call_line, DW_FORM_data4, 12)

    # inline_die = func_die.addChild(DW_TAG.inlined_subroutine)
    # inline_die.addAttribute(DW_AT.name, DW_FORM_strp, "inline_with_valid_call_file")
    # inline_die.addRangeAttributes(0x1020, 0x1030)
    # inline_die.addAttribute(DW_AT.call_file, DW_FORM_data4, 1)
    # inline_die.addAttribute(DW_AT.call_line, DW_FORM_data4, 13)

    # inline_die = inline_die.addChild(DW_TAG.inlined_subroutine)
    # inline_die.addAttribute(DW_AT.name, DW_FORM_strp, "inline_inside_parent_with_valid_call_file")
    # inline_die.addRangeAttributes(0x1020, 0x1025)
    # inline_die.addAttribute(DW_AT.call_file, DW_FORM_data4, 1)
    # inline_die.addAttribute(DW_AT.call_line, DW_FORM_data4, 14)

    # func_die = cu1.die.addChild(DW_TAG.subprogram)
    # func_die.addAttribute(DW_AT.name, DW_FORM_strp, "func_with_valid_decl_file")
    # func_die.addDataAttribute(DW_AT.decl_file, 1)
    # func_die.addDataAttribute(DW_AT.decl_line, 20)
    # func_die.addRangeAttributes(0x2000, 0x2050)

    # func_die = cu1.die.addChild(DW_TAG.subprogram)
    # func_die.addAttribute(DW_AT.name, DW_FORM_strp, "func_with_invalid_decl_file")
    # func_die.addDataAttribute(DW_AT.decl_file, 10)
    # func_die.addDataAttribute(DW_AT.decl_line, 20)
    # func_die.addRangeAttributes(0x3000, 0x3050)

    # inline_ranges = AddressRangeList()
    # inline_ranges.append(AddressRange(0x1015, 0x1020))
    # inline_ranges.append(AddressRange(0x2015, 0x2020))
    # # inline_ranges.append(AddressRange(0x3015, 0x3020))

    # inline_die2 = inline_die.addChild(DW_TAG.inlined_subroutine)
    # inline_die2.addAttribute(DW_AT.name, DW_FORM_strp, "inline2")
    # inline_die2.addAttribute(DW_AT.ranges, DW_FORM_sec_offset, inline_ranges)
    # inline_die2.addAttribute(DW_AT.call_file, DW_FORM_data4, 2)
    # inline_die2.addAttribute(DW_AT.call_line, DW_FORM_data4, 21)

    # func_die = cu1.die.addChild(DW_TAG.subprogram)
    # func_die.addAttribute(DW_AT.name, DW_FORM_strp, "bar")
    # func_die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0x2000)
    # func_die.addAttribute(DW_AT.high_pc, DW_FORM_addr, 0x2050)

    # cu2 = dwarfgen.addCompileUnit(DW_TAG.compile_unit)
    # cu2.die.addAttribute(DW_AT.name, DW_FORM_strp, cu1_path)
    # cu2.die.addAttribute(DW_AT.language, DW_FORM_udata, 2)

    # func_die = cu2.die.addChild(DW_TAG.subprogram)
    # func_die.addAttribute(DW_AT.name, DW_FORM_strp, "foo")
    # func_die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0x1000)
    # func_die.addAttribute(DW_AT.high_pc, DW_FORM_addr, 0x1050)

    # func_die = cu2.die.addChild(DW_TAG.subprogram)
    # func_die.addAttribute(DW_AT.name, DW_FORM_strp, "bar")
    # func_die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0x2000)
    # func_die.addAttribute(DW_AT.high_pc, DW_FORM_addr, 0x2050)

    # cu2.add_line_entry(cu1_path, 20, 0x2000)
    # cu2.add_line_entry(cu1_path, 21, 0x2050, True)


    # cu2_path = "/tmp/foo.cpp"

    # func2_die.addRangeAttributes(0x1000, 0x1050)



    # cu_ranges = AddressRangeList()
    # cu_ranges.append(AddressRange(0, 0xa))
    # cu_ranges.append(AddressRange(0, 0x6))
    # cu_ranges.append(AddressRange(0x0000000100003fa0, 0x0000000100003fb6))
    # cu_ranges.append(AddressRange(0, 0x20))
    # cu_ranges.append(AddressRange(0, 0))
    # cu_ranges.append(AddressRange(0, 0))
    # cu_ranges.append(AddressRange(0, 0))
    # cu.get_aranges().address_ranges = cu_ranges
    #cu.die.addAttribute(DW_AT.ranges, DW_FORM_sec_offset, cu_ranges)

    # cu = dwarfgen.addCompileUnit(DW_TAG.compile_unit)
    # cu.dwarf_info.addr_size = 4
    # cu_path = "/tmp/foo.c"
    # # inline_path = "/tmp/inline.h"
    # cu.die.addAttribute(DW_AT.name, DW_FORM_strp, cu_path)
    # # cu.die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0x1000)
    # # cu.die.addAttribute(DW_AT.high_pc, DW_FORM_data4, 0x1000)
    # cu.die.addAttribute(DW_AT.language, DW_FORM_data2, DW_LANG_C)
    # cu_ranges = AddressRangeList()
    # cu_ranges.append(AddressRange(0x2000, 0x2100))
    # cu_ranges.append(AddressRange(0x2300, 0x2400))
    # cu.die.addAttribute(DW_AT.ranges, DW_FORM_sec_offset, cu_ranges)

    # cu.add_line_entry(cu_path, 10, 0x1000)
    # cu.add_line_entry(inline_path, 20, 0x1100)
    # cu.add_line_entry(inline_path, 21, 0x1180)
    # cu.add_line_entry(cu_path, 11, 0x1200)
    # cu.add_line_entry(cu_path, 12, 0x2000, True)

    # 0x00000073:   DW_TAG.structure_type
    #                 DW_AT.containing_type	(0x0000000000000073)
    #                 DW_AT.calling_convention	(DW_CC_pass_by_reference)
    #                 DW_AT.name	("DefaultDtor")
    #                 DW_AT.byte_size	(0x08)
    #                 DW_AT.decl_file	("/tmp/main.cpp")
    #                 DW_AT.decl_line	(1)
    # func_die = cu.die.addChild(DW_TAG.subprogram)
    # func_die.addAttribute(DW_AT.name, DW_FORM_strp, "stripped1")
    # func_die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0)
    # func_die.addAttribute(DW_AT.high_pc, DW_FORM_data4, 0x20)


    # func_die = cu.die.addChild(DW_TAG.subprogram)
    # func_die.addAttribute(DW_AT.name, DW_FORM_strp, "stripped2")
    # func_die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0)
    # func_die.addAttribute(DW_AT.high_pc, DW_FORM_addr, 0x30)

    # int_die = cu1.die.addChild(DW_TAG.base_type)
    # int_die.addNameAttribute("int")
    # int_die.addDataAttribute(DW_AT.encoding, DW_ATE.signed)
    # int_die.addDataAttribute(DW_AT.byte_size, 4)


    # inline_die = func_die.addChild(DW_TAG.inlined_subroutine)
    # inline_die.addAttribute(DW_AT.name, DW_FORM_strp, "inline1")
    # inline_die.addRangeAttributes(0x1100, 0x1200)
    # inline_die.addAttribute(DW_AT.call_file, DW_FORM_data4, 1)
    # inline_die.addAttribute(DW_AT.call_line, DW_FORM_data4, 11)

    # inline_die2 = inline_die.addChild(DW_TAG.inlined_subroutine)
    # inline_die2.addAttribute(DW_AT.name, DW_FORM_strp, "inline2")
    # inline_die2.addRangeAttributes(0x1150, 0x1180)
    # inline_die2.addAttribute(DW_AT.call_file, DW_FORM_data4, 2)
    # inline_die2.addAttribute(DW_AT.call_line, DW_FORM_data4, 21)

    # cu1.add_line_entry(cu1_path, 0, 0, True)

    # cu2.add_line_entry(cu2_path, 10, 0x1000)
    # cu2.add_line_entry(cu2_path, 11, 0x1010)
    # cu2.add_line_entry(cu2_path, 12, 0x1020)
    # cu2.add_line_entry(cu2_path, 12, 1050, True)
    # cu.add_line_entry(inline_path, 20, 0x1100)
    # cu.add_line_entry(inline_path, 21, 0x1110)
    # cu.add_line_entry(inline_path, 22, 0x1120)
    # cu.add_line_entry(inline_path, 120, 0x1150)
    # cu.add_line_entry(inline_path, 121, 0x1160)
    # cu.add_line_entry(inline_path, 122, 0x1170)

    # func_die.addRangeAttributes(0x1000, 0x2000)
    # func_die.addAttribute(DW_AT.decl_file, DW_FORM_strp, "")
    # func_die.addDataAttribute(DW_AT.call_line, 5)

    # inline_die = func_die.addChild(DW_TAG.inlined_subroutine)
    # inline_die.addAttribute(DW_AT.name, DW_FORM_strp, "inline1")
    # inline_die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0x1100)
    # inline_die.addAttribute(DW_AT.high_pc, DW_FORM_data4, 0x100)
    # inline_die.addAttribute(DW_AT.call_file, DW_FORM_strp, "")
    # inline_die.addDataAttribute(DW_AT.call_line, 10)


    # func_die = cu.die.addChild(DW_TAG.subprogram)
    # func_die.addAttribute(DW_AT.name, DW_FORM_strp, "stripped")
    # func_die.addRangeAttributes(0xffffffffffffffff, 0x3000)

    # var_die = func_die.addChild(DW_TAG.variable)
    # var_die.addNameAttribute("foo")
    # var_die.addReferenceAttribute(DW_AT.type, int_die)

    # func_die = cu.die.addChild(DW_TAG.subprogram)
    # func_die.addAttribute(DW_AT.name, DW_FORM_strp, "foo")
    # func_die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0x2000)
    # func_die.addAttribute(DW_AT.high_pc, DW_FORM_data4, 0x1000)


    # type_die = cu1.die.addChild(DW_TAG.base_type)
    # type_die.addNameAttribute("long")
    # type_die.addDataAttribute(DW_AT.encoding, DW_ATE.signed)
    # type_die.addDataAttribute(DW_AT.byte_size, 8)

    # int_die = cu1.die.addChild(DW_TAG.base_type)
    # int_die.addNameAttribute("int")
    # int_die.addDataAttribute(DW_AT.encoding, DW_ATE.signed)
    # int_die.addDataAttribute(DW_AT.byte_size, 4)


    # struct_die = cu.die.addChild(DW_TAG.structure_type)
    # struct_die.addAttribute(DW_AT.name, DW_FORM_strp, "unused_struct")
    # struct_die.addDataAttribute(DW_AT.byte_size, 4)
    # struct_die.addFileAttribute(DW_AT.decl_file, cu_path)
    # struct_die.addDataAttribute(DW_AT.decl_line, 20)

    # member_die = struct_die.addChild(DW_TAG.member)
    # member_die.addNameAttribute("x")
    # member_die.addReferenceAttribute(DW_AT.type, int_die)

    # func_die = cu.die.addChild(DW_TAG.subprogram)
    # func_die.addAttribute(DW_AT.name, DW_FORM_strp, "stripped3")
    # func_die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0x4000)
    # func_die.addAttribute(DW_AT.high_pc, DW_FORM_addr, 0x3fff)

    # cu.add_line_entry(cu_path, 11, 0x1000)
    # cu.add_line_entry(cu_path, 12, 0x1200)
    # cu.add_line_entry(cu_path, 12, 0x2000, True)

    # func_die = cu.die.addChild(DW_TAG.subprogram)
    # func_die.addAttribute(DW_AT.name, DW_FORM_strp, "lines_with_decl")
    # func_die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0x2000)
    # func_die.addAttribute(DW_AT.high_pc, DW_FORM_data4, 0x1000)
    # func_die.addAttribute(DW_AT.decl_file, DW_FORM_data1, 1)
    # func_die.addAttribute(DW_AT.decl_line, DW_FORM_data1, 20)

    # cu.add_line_entry(cu_path, 21, 0x2000)
    # cu.add_line_entry(cu_path, 22, 0x2200)
    # cu.add_line_entry(cu_path, 22, 0x3000, True)

    # func_die = cu.die.addChild(DW_TAG.subprogram)
    # func_die.addAttribute(DW_AT.name, DW_FORM_strp, "no_lines_no_decl")
    # func_die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0x3000)
    # func_die.addAttribute(DW_AT.high_pc, DW_FORM_data4, 0x1000)

    # func_die = cu.die.addChild(DW_TAG.subprogram)
    # func_die.addAttribute(DW_AT.name, DW_FORM_strp, "no_lines_with_decl")
    # func_die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0x4000)
    # func_die.addAttribute(DW_AT.high_pc, DW_FORM_data4, 0x1000)
    # func_die.addAttribute(DW_AT.decl_file, DW_FORM_data1, 1)
    # func_die.addAttribute(DW_AT.decl_line, DW_FORM_data1, 40)


    # inline_die = func_die.addChild(DW_TAG.inlined_subroutine)
    # inline_die.addAttribute(DW_AT.name, DW_FORM_strp, "inline1")
    # inline_die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0x1100)
    # inline_die.addAttribute(DW_AT.high_pc, DW_FORM_data4, 0x100)
    # inline_die.addAttribute(DW_AT.call_file, DW_FORM_data4, 1)
    # inline_die.addAttribute(DW_AT.call_line, DW_FORM_data4, 10)


    # attr_name = cu.die.addAttribute(DW_AT.comp_dir, DW_FORM_strp, ".")
    # cu.die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0x1000)
    # cu.die.addAttribute(DW_AT.high_pc, DW_FORM_addr, 0x2000)

    # cu.add_line_entry(cu_path, 12, 0x1000)
    # cu.add_line_entry(cu_path, 14, 0x1010)
    # cu.add_line_entry(cu_path, 16, 0x1020)
    # cu.add_line_entry(cu_path, 16, 0x1030, True)
    # cu = dwarfgen.addCompileUnit(DW_TAG.compile_unit)
    # attr_name = cu.die.addAttribute(DW_AT.name, DW_FORM_strp, "main.c")
    # attr_name = cu.die.addAttribute(DW_AT.comp_dir, DW_FORM_strp, "./")
    #
    # cu = dwarfgen.addCompileUnit(DW_TAG.compile_unit)
    # attr_name = cu.die.addAttribute(DW_AT.name, DW_FORM_strp, "main.c")
    # attr_name = cu.die.addAttribute(DW_AT.comp_dir, DW_FORM_strp, ".//")
    #
    # cu = dwarfgen.addCompileUnit(DW_TAG.compile_unit)
    # attr_name = cu.die.addAttribute(DW_AT.name, DW_FORM_strp, "main.c")
    # attr_name = cu.die.addAttribute(DW_AT.comp_dir, DW_FORM_strp, ".///")
    #
    # cu = dwarfgen.addCompileUnit(DW_TAG.compile_unit)
    # attr_name = cu.die.addAttribute(DW_AT.name, DW_FORM_strp, "main.c")
    # attr_name = cu.die.addAttribute(DW_AT.comp_dir, DW_FORM_strp, ".///bar")
    #
    # cu = dwarfgen.addCompileUnit(DW_TAG.compile_unit)
    # attr_name = cu.die.addAttribute(DW_AT.name, DW_FORM_strp, "main.c")
    # attr_name = cu.die.addAttribute(DW_AT.comp_dir, DW_FORM_strp, ".///bar/baz")


    # attr_name = cu2.die.addAttribute(DW_AT.name, DW_FORM_strp, cu_filepath2)

    # func_die = cu.die.addChild(DW_TAG.subprogram)
    # func_die.addAttribute(DW_AT.name, DW_FORM_strp, "main")
    # func_die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0x1000)
    # func_die.addAttribute(DW_AT.high_pc, DW_FORM_addr, 0x2000)
    #
    # func_die = cu.die.addChild(DW_TAG.subprogram)
    # func_die.addAttribute(DW_AT.name, DW_FORM_strp, "elided")
    # func_die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0x2000)
    # func_die.addAttribute(DW_AT.high_pc, DW_FORM_addr, 0x2000)

    # block_die = func_die.addChild(DW_TAG.lexical_block)
    # block_die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0x1100)
    # block_die.addAttribute(DW_AT.high_pc, DW_FORM_addr, 0x1300)
    #
    # block_die = func_die.addChild(DW_TAG.lexical_block)
    # block_die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0x12ff)
    # block_die.addAttribute(DW_AT.high_pc, DW_FORM_addr, 0x1300)

    # cu.add_line_entry(cu_filepath, 10, 0x1000)
    # cu.add_line_entry(cu_filepath, 10, 0x1100, True)
    # cu2.die.addAttribute(DW_AT.stmt_list, DW_FORM_sec_offset, 0x0)
    # cu_ranges = AddressRangeList()
    # cu_ranges.append(AddressRange(0x1000, 0x1500))
    # attr_low_pc = cu.die.addAttribute(DW_AT.ranges, DW_FORM_data4, cu_ranges)
    #
    # class_die = cu.die.addChild(DW_TAG.class_type)
    # class_die.addAttribute(DW_AT.name, DW_FORM_strp, "Foo")

    # method_die = class_die.addChild(DW_TAG.subprogram)
    # method_die.addAttribute(DW_AT.name, DW_FORM_strp, "Bar")
    # method_die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0x3000)
    # method_die.addAttribute(DW_AT.high_pc, DW_FORM_addr, 0x4000)

    # method_die = class_die.addChild(DW_TAG.subprogram)
    # method_die.addAttribute(DW_AT.name, DW_FORM_strp, "Baz")
    # method_die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0x4000)
    # method_die.addAttribute(DW_AT.high_pc, DW_FORM_data4, 0x1000)
    #
    #
    # block_die = method_die.addChild(DW_TAG.lexical_block)
    # block_die.addAttribute(DW_AT.low_pc, DW_FORM_addr, 0x2100)
    # block_die.addAttribute(DW_AT.high_pc, DW_FORM_addr, 0x2200)

    # Populate the .debug_aranges
    if options.generate_debug_aranges:
        cu1.generate_debug_aranges()
    if options.generate_cu_ranges:
        cu1.generate_cu_ranges()
    # cu.add_range(0x1000, 0x2000)
    # cu.add_range(0x2000, 0x3000)
    dwarfgen.save(options.outfile)


if __name__ == '__main__':
    parser = create_options()
    (options, args) = parser.parse_args()
    generate_dwarf(options, args)


# class LLDBCommand:

#     def get_short_help(self):
#         return "Generate DWARF and run tests in LLDB using that DWARF"

#     def get_long_help(self):
#         return self.help_string

#     def __init__(self, debugger, unused):
#         self.parser = create_options()
#         self.help_string = self.parser.format_help()

#     def __call__(self, debugger, command, exe_ctx, result):
#         command_args = shlex.split(command)

#         try:
#             (options, args) = self.parser.parse_args(command_args)
#         except:
#             result.SetError("option parsing failed")
#             return

#         dwarf_info = DWARFInfo(addr_size=options.addr_size,
#                                version=options.version,
#                                dwarf_size=options.dwarf_size,
#                                byte_order=options.byte_order)

#         dwarfgen = DWARFGenerator(dwarf_info)

#         # infos = [
#         #     # Test "." in paths
#         #     (".", "main.c", "./main.c"),
#         #     ("./", "main.c", "./main.c"),
#         #     ("././././.", "main.c", "./main.c"),
#         #     ("./././././", "main.c", "./main.c"),
#         #     (None, ".", "."),
#         #     # Test ".." in paths
#         #     ("/..", "main.c", "/main.c"),
#         #     ("/../..", "main.c", "/main.c"),
#         #     ("..", "main.c", "../main.c"),
#         #     ("../..", "main.c", "../../main.c"),
#         #     ("/foo/..", "main.c", "/main.c"),
#         #     ("/foo/../", "main.c", "/main.c"),
#         #     ("/foo/bar/..", "main.c", "/foo/main.c"),
#         #     ("/foo/bar/../", "main.c", "/foo/main.c"),
#         #     ("/foo/bar/../baz/..", "main.c", "/foo/main.c"),
#         #     ("/foo/bar/../baz/../", "main.c", "/foo/main.c"),
#         #     # Test normal paths
#         #     (None, "main.c", "main.c"),
#         #     (None, "/main.c", "/main.c"),
#         #     ("/", "main.c", "/main.c"),
#         #     ("//", "main.c", "//main.c"),
#         #     # Test relative paths
#         #     ("./bbb", "aaa/main.c", "./bbb/aaa/main.c"),
#         #     ("./bbb/", "aaa/main.c", "./bbb/aaa/main.c"),
#         #     ("bbb", "aaa/main.c", "bbb/aaa/main.c"),
#         #     ("bbb/", "aaa/main.c", "bbb/aaa/main.c"),
#         #     # Test // at start of path, they must be left untouched
#         #     ("//", "usr", "//usr"),
#         #     (None, "//usr", "//usr"),
#         #     # Test // at middle of path, they can be reduced to a single /
#         #     ("/aaa//", "bbb", "/aaa/bbb"),
#         #     (None, "/aaa//bbb", "/aaa/bbb"),
#         #     ("/aaa//////", "bbb", "/aaa/bbb"),
#         #     (None, "/aaa//////bbb", "/aaa/bbb"),
#         #     (None, "/aaa//bbb//ccc", "/aaa/bbb/ccc"),
#         #     (None, "/aaa//bbb//ccc/", "/aaa/bbb/ccc"),
#         #     (None, "/aaa//bbb//ccc//", "/aaa/bbb/ccc"),

#         # ]
#         # for info in infos:
#         #     cu = dwarfgen.addCompileUnit(DW_TAG.compile_unit)
#         #     attr_name = cu.die.addAttribute(DW_AT.name, DW_FORM_strp, info[1])
#         #     if info[0]:
#         #         attr_name = cu.die.addAttribute(DW_AT.comp_dir, DW_FORM_strp,
#         #                                         info[0])
#         # Populate the .debug_aranges
#         if options.generate_debug_aranges:
#             cu.generate_debug_aranges()
#         if options.generate_cu_ranges:
#             cu.generate_cu_ranges()
#         # cu.add_range(0x1000, 0x2000)
#         # cu.add_range(0x2000, 0x3000)
#         dwarfgen.save(options.outfile)

#         target = debugger.CreateTarget(options.outfile)

#         module = target.module[options.outfile]

#         nums_cus = module.GetNumCompileUnits()
#         for cu_idx in range(nums_cus):
#             cu = module.GetCompileUnitAtIndex(cu_idx)
#             print "%s %s -->" % (infos[cu_idx][0], infos[cu_idx][1]),
#             print cu.GetFileSpec()
#         print >>result, module


# def __lldb_init_module(debugger, dict):
#     debugger.HandleCommand(
#         'command script add -c %s.LLDBCommand %s' % (__name__, program))
#     print('The "%s" command has been installed, type "help %s" for '
#           'detailed help.' % (program, program))
