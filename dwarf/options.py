#!/usr/bin/python

# Local imports
import term_colors
import file_extract

# Python imports
import io
import sys
import optparse

# Package imports
import dwarf.debug.frame
import dwarf.optimize
import dwarf.typestats

# After options are parsed, clients must set this to the value returned from
# optparse.parse_args()
options = None


def append_dwarf_options(parser):
    '''Add DWARF options to object file options to allow ELF, MachO and any
       other object files to have a consistent command line interface when
       dumping DWARF'''
    group = optparse.OptionGroup(
        parser,
        "DWARF Options",
        "Options for dumping DWARF debug information.")
    # group.add_option("-g", action="store_true", help="Group option.")
    group.add_option(
        '--debug-all',
        action='store_true',
        dest='debug_all',
        help='Dump all .debug_* sections',
        default=False)
    group.add_option(
        '--debug-abbrev',
        action='store_true',
        dest='debug_abbrev',
        help='Dump the .debug_abbrev section',
        default=False)
    group.add_option(
        '--debug-aranges',
        action='store_true',
        dest='debug_aranges',
        help='Dump the .debug_aranges section',
        default=False)
    group.add_option(
        '--debug-info',
        action='store_true',
        dest='debug_info',
        help='Dump the .debug_info section',
        default=False)
    group.add_option(
        '--debug-line',
        action='store_true',
        dest='debug_line',
        help='Dump the .debug_line section',
        default=False)
    group.add_option(
        '--debug-names',
        action='store_true',
        dest='debug_names',
        help='Dump the .debug_names section',
        default=False)
    group.add_option(
        '--debug-map', '--map',
        action='store_true',
        dest='debug_map',
        help='Dump the address map of all DWARF',
        default=False)
    group.add_option(
        '--debug-types',
        action='store_true',
        dest='debug_types',
        help='Dump the .debug_types section',
        default=False)
    group.add_option(
        '--debug-str',
        action='store_true',
        dest='debug_str',
        help='Dump the .debug_str section',
        default=False)
    group.add_option(
        '--debug-line-str',
        action='store_true',
        dest='debug_line_str',
        help='Dump the .debug_line_str section',
        default=False)
    group.add_option(
        '--debug-cu-index',
        action='store_true',
        dest='debug_cu_index',
        help='Dump the .debug_cu_index section',
        default=False)
    group.add_option(
        '--debug-tu-index',
        action='store_true',
        dest='debug_tu_index',
        help='Dump the .debug_tu_index section',
        default=False)
    group.add_option(
        '--dwo',
        action='store_true',
        dest='dump_dwo',
        help='When dumping debug info, if the debug info refers to a .dwo file, dump the .dwo file DWARF as well',
        default=False)
    group.add_option(
        '--dwo-id',
        action='append',
        type='int',
        dest='dwo_ids',
        help='DWO IDs to lookup in .debug_info, .debug_cu_index or .debug_tu_index')
    group.add_option(
        '--offset-debug-types',
        action='store_true',
        dest='offset_debug_types',
        help=('Dump the .debug_types section as if it starts at end of '
              '.debug_info'),
        default=False)
    group.add_option(
        '--eh-frame',
        action='store_true',
        dest='eh_frame',
        help='Dump the .eh_frame section',
        default=False)
    group.add_option(
        '--eh-frame-hdr',
        action='store_true',
        dest='eh_frame_hdr',
        help='Dump the .eh_frame_hdr section',
        default=False)
    group.add_option(
        '--debug-frame',
        action='store_true',
        dest='debug_frame',
        help='Dump the .debug_frame section',
        default=False)
    group.add_option(
        '--unwind-stats',
        action='store_true',
        dest='unwind_stats',
        help=('Dump the unwind register rules statistics for unwind rows that '
              'have the same register rules.'),
        default=False)
    group.add_option(
        '--type-stats',
        action='store_true',
        dest='type_stats',
        help=('Dump statistics on types in the debug info.'),
        default=False)
    group.add_option(
        '--type-stats-sort',
        type='string',
        dest='type_stats_sort',
        help=('Set the type statistics sorting order. Must be "size" to sort '
              'by total byte size, or "count" to sort by max counts. Defaults '
              'to "size".'),
        default='size')
    parser.add_option(
        '--fde',
        type='int',
        dest='fde_addr',
        metavar='ADDR',
        help='Specify an address to lookup in the unwind info and dump.')
    group.add_option(
        '--apple-names',
        action='store_true',
        dest='apple_names',
        help='Dump the .apple_names section',
        default=False)
    group.add_option(
        '--apple-types',
        action='store_true',
        dest='apple_types',
        help='Dump the .apple_types section',
        default=False)
    group.add_option(
        '--compile-unit',
        type='string',
        action='append',
        dest='cu_names',
        help='Dump a compile unit by file basename or full path.')
    group.add_option(
        '-q', '--dwarf-query',
        type='string',
        action='append',
        dest='dwarf_queries',
        help='Create a SQL .')
    group.add_option(
        '--die',
        type='int',
        action='append',
        dest='die_offsets',
        help='Dump the specified DIE by DIE offset.')
    group.add_option(
        '--cu',
        type='int',
        action='append',
        dest='cu_offsets',
        help='Dump the specified DWARF unit by unit header offset.')
    group.add_option(
        '--type-sig',
        type='int',
        action='append',
        dest='type_sigs',
        help='Dump all type units whose type signatures match.')
    group.add_option(
        '--stmt', '--line',
        type='int',
        action='append',
        dest='stmt_offsets',
        help='Dump the specified DWARF line table by DW_AT_stmt_list offset.')
    parser.add_option(
        '--children',
        action='store_true',
        dest='children',
        default=False,
        help=('Dump child DIEs when dumping dies using options that lookup or '
              'dump individual DIEs'))
    parser.add_option(
        '--parent',
        action='store_true',
        dest='parent',
        default=False,
        help=('Dump parent DIEs when dumping dies using options that lookup or '
              'dump individual DIEs'))
    group.add_option(
        '--address',
        action='append',
        type='int',
        dest='lookup_addresses',
        help='Address to lookup')
    group.add_option(
        '--name',
        action='append',
        type='string',
        dest='lookup_names',
        help='Name to lookup in .debug_info or .debug_types or .debug_names.')
    group.add_option(
        '-C', '--color',
        action='store_true',
        dest='color',
        default=False,
        help='Enable colorized output')
    parser.add_option(
        '--indent-width',
        type='int',
        metavar='<integer>',
        dest='indent_width',
        default=4,
        help='Set the indent width when dumping DIEs. Default is 4')
    parser.add_option(
        '-M', '--max-str',
        type='int',
        metavar='<integer>',
        dest='max_strlen',
        default=None,
        help='Set the max string length to display. Default is no limit.')
    parser.add_option(
        '--optimize',
        type='string',
        dest='optimize_path',
        default=None,
        help='Optimize the DWARF to this file.')
    group.add_option(
        '--dwarfdb',
        action='store_true',
        dest='dwarfdb',
        default=False,
        help='Dump DWARF database hashes and info')
    group.add_option(
        '--verify',
        action='store_true',
        dest='verify_dwarf',
        help='If enabled, each DWARF section specified can verify.',
        default=False)

    parser.add_option_group(group)


def have_dwarf_options(options):
    return (options.debug_all
            or options.debug_abbrev
            or options.debug_aranges
            or options.debug_frame
            or options.debug_info
            or options.debug_line
            or options.debug_line_str
            or options.debug_names
            or options.debug_str
            or options.debug_types
            or options.debug_cu_index
            or options.debug_tu_index
            or options.dwo_ids
            or options.lookup_addresses
            or options.lookup_names
            or options.cu_names
            or options.die_offsets
            or options.cu_offsets
            or options.type_sigs
            or options.stmt_offsets
            or options.apple_names
            or options.apple_types
            or options.debug_map
            or options.eh_frame
            or options.eh_frame_hdr
            or options.unwind_stats
            or options.type_stats
            or options.fde_addr
            or options.dwarfdb
            or options.optimize_path is not None)


def get_colorizer():
    if options is None:
        return term_colors.TerminalColors(False)
    else:
        return term_colors.TerminalColors(options.color)


def get_color_offset(offset):
    colorizer = get_colorizer()
    return colorizer.yellow() + "%#8.8x" % (offset) + colorizer.reset()


def get_color_tag(tag):
    colorizer = get_colorizer()
    return colorizer.blue() + str(tag) + colorizer.reset()

def get_color_attr(attr):
    colorizer = get_colorizer()
    return colorizer.cyan() + str(attr) + colorizer.reset()

def get_color_error(s):
    colorizer = get_colorizer()
    return colorizer.red() + s + colorizer.reset()

def get_color_warning(s):
    colorizer = get_colorizer()
    return colorizer.yellow() + s + colorizer.reset()

def colorize_error_or_warning(s):
    if s.startswith('error:'):
        return get_color_error(s)
    elif s.startswith('warning:'):
        return get_color_warning(s)
    else:
        return s

def get_color_form(form):
    colorizer = get_colorizer()
    return colorizer.faint() + str(form) + colorizer.reset()


def get_color_string(s):
    colorizer = get_colorizer()
    return colorizer.green() + s + colorizer.reset()


def get_color_DW_constant(c):
    colorizer = dwarf.options.get_colorizer()
    return colorizer.faint() + str(c) + colorizer.reset()


def get_unwind_info(objfile, is_eh_frame):
    (data, addr) = objfile.get_unwind_data_and_addr(is_eh_frame)
    if data:
        data.set_gnu_pcrel(addr)
        return dwarf.debug.frame.debug_frame(objfile, data, is_eh_frame)
    return None


def dump_eh_frame_hdr(opts, objfile, f=sys.stdout):
    global options
    options = opts
    sect_name = '.eh_frame_hdr'
    (data, addr) = objfile.get_section_data_and_addr(sect_name)
    if data:
        data.set_gnu_pcrel(addr)
        data.set_gnu_datarel(addr)
        eh_frame_hdr = dwarf.debug.frame.eh_frame_hdr(data)
        eh_frame_hdr.dump(f=f)
    else:
        f.write('error: no section named "%s" found in object file' % (
                sect_name))


def dump_unwind_info(opts, objfile, is_eh_frame, f=sys.stdout):
    global options
    options = opts
    frame_info = get_unwind_info(objfile, is_eh_frame)
    if frame_info:
        if options.eh_frame or options.debug_frame:
            frame_info.dump(options.verbose, f=f)
        if options.unwind_stats:
            frame_info.dump_unwind_stats(f=f)
    else:
        if is_eh_frame:
            type = "EH frame info"
        else:
            type = "DWARF .debug_frame"
        f.write('error: no %s found in "%s"\n' % (type, objfile.path))


def dump_dwarfdb(debug_info, verbose=False, f=sys.stdout):
    f.write('DWARF DB Info:\n')
    cus = debug_info.get_dwarf_units()
    for cu in cus:
        byte_order = cu.dwarf_info.byte_order
        addr_size = cu.dwarf_info.addr_size
        for die in cu.get_dies():
            die.dump(f=f)
            data = file_extract.FileEncode(io.BytesIO(), byte_order, addr_size)
            tag = die.get_tag()
            data.put_uleb128(tag)
            if tag.get_enum_value() != 0:
                data.put_uint8(die.has_children())
                attr_values = die.get_attrs(False)
                for attr_value in attr_values:
                    attr_value.encode_dwarfdb(die, data)


def handle_options(opts, objfile, f=sys.stdout):
    global options
    options = opts

    if have_dwarf_options(options):
        if options.debug_all:
            options.apple_names = True
            options.apple_types = True
            options.debug_abbrev = True
            options.debug_aranges = True
            options.debug_frame = True
            options.debug_info = True
            options.debug_line = True
            options.debug_line_str = True
            options.debug_names = True
            options.debug_ranges = True
            options.debug_str = True
            options.debug_types = True
            options.debug_cu_index = True
            options.debug_tu_index = True

        dwarf_ctx = objfile.get_dwarf()
        if dwarf_ctx:
            if options.debug_abbrev:
                debug_abbrev = dwarf_ctx.get_debug_abbrev()
                debug_abbrev.dump(f=f)
            if options.debug_aranges:
                debug_aranges = dwarf_ctx.get_debug_aranges()
                if debug_aranges:
                    debug_aranges.dump(f)
            if options.debug_frame or options.unwind_stats:
                dump_unwind_info(options, objfile, False, f=f)
            if options.fde_addr:
                frame_info = get_unwind_info(objfile, True)
                if frame_info is None:
                    frame_info = get_unwind_info(objfile, False)
                if frame_info:
                    fde = frame_info.get_fde_for_addr(options.fde_addr)
                    if fde:
                        fde.dump(verbose=options.verbose, f=f)
                    else:
                        f.write('error: no unwind info found for %#x\n' % (
                                options.fde_addr))
                else:
                    f.write('error: no unwind info in binary\n')
            debug_info = dwarf_ctx.get_debug_info()
            if debug_info:
                if options.dwarfdb:
                    dump_dwarfdb(debug_info, options.verbose, f=f)
                if options.type_stats:
                    dwarf.typestats.dump_type_stats(options, dwarf_ctx, f=f)
                if options.optimize_path:
                    opt = dwarf.optimize.Optimizer(dwarf_ctx)
                    opt.optimize()
                    opt.save(options.optimize_path)
                if options.lookup_names and options.debug_info:
                    for name in options.lookup_names:
                        dies = debug_info.find_dies_with_name(name)
                        if dies:
                            f.write("DIEs with name '%s':\n" % (name))
                            for die in dies:
                                die.dump_ancestry(verbose=options.verbose,
                                                  show_all_attrs=True, f=f)
                        else:
                            f.write("No DIEs with name '%s'\n" % (name))
                if options.debug_info:
                    debug_info.dump_debug_info(options=options, f=f)
                if options.debug_types:
                    offset_adjust = 0
                    if options.offset_debug_types:
                        offset_adjust = debug_info.debug_info_size
                    debug_info.dump_debug_types(verbose=options.verbose, f=f,
                                                offset_adjust=offset_adjust)
                if options.debug_map:
                    die_ranges = debug_info.get_die_ranges()
                    if die_ranges:
                        die_ranges.dump(f=f)
                        # f.write(str(die_ranges))
                if options.lookup_addresses:
                    for address in options.lookup_addresses:
                        f.write('lookup 0x%8.8x:\n' % (address))
                        debug_info.lookup_address(address)
                if options.cu_names:
                    for cu_name in options.cu_names:
                        cu = debug_info.get_compile_unit_with_path(cu_name)
                        if cu:
                            f.write(str(cu.get_die()))
                            line_table = cu.get_line_table()
                            line_table.dump(verbose=options.verbose)
                if options.debug_line:
                    cus = debug_info.get_dwarf_units()
                    stmt_list_set = set()
                    for cu in cus:
                        line_table = cu.get_line_table()
                        # Don't dump the same line table twice. Some type units
                        # share a line table by using the same DW_AT_stmt_list
                        # attribute value.
                        if line_table is not None:
                            if line_table.offset in stmt_list_set:
                                continue
                            line_table.dump(verbose=options.verbose)
                            stmt_list_set.add(line_table.offset)
                if options.stmt_offsets:
                    for stmt_offset in options.stmt_offsets:
                        cu = debug_info.get_first_dwarf_unit_with_stmt_list(stmt_offset)
                        if cu:
                            line_table = cu.get_line_table()
                            if line_table:
                                # Dump the CU or TU for the line table.
                                if options.verbose:
                                    depth = sys.maxsize if options.children else 0
                                    cu.dump(False, max_depth=depth)
                                line_table.dump(verbose=options.verbose)
                            else:
                                f.write('error: CU failed to extract the line table @ %#8.8x\n' % (stmt_offset))
                        else:
                            f.write('error: No DWARF unit found that has line table @ %#8.8x\n' % (stmt_offset))
                if options.die_offsets:
                    for die_offset in options.die_offsets:
                        die = debug_info.find_die_with_offset(die_offset)
                        if die:
                            if options.children:
                                depth = 1000000
                            else:
                                depth = 0
                            if options.parent:
                                die.dump_ancestry(verbose=options.verbose,
                                                  max_depth=depth,
                                                  show_all_attrs=True, f=f)
                            else:
                                die.dump(max_depth=depth,
                                         verbose=options.verbose,
                                         show_all_attrs=True)
                        else:
                            f.write('error: no DIE for .debug_info offset '
                                    '0x%8.8x\n' % (die_offset))
                if options.cu_offsets:
                    for cu_offset in options.cu_offsets:
                        cu = debug_info.get_dwarf_unit_with_offset(cu_offset)
                        if cu:
                            depth = sys.maxsize if options.children else 0
                            cu.dump(options.verbose, max_depth=depth)
                        else:
                            f.write('error: no CU @ .debug_info[0x%8.8x]\n' % (cu_offset))
                if options.type_sigs and (options.debug_info or not options.debug_tu_index):
                    for type_sig in options.type_sigs:
                        (tu, dwo_cu) = debug_info.get_type_unit_with_signature(type_sig)
                        if tu:
                            depth = sys.maxsize if options.children else 0
                            tu.dump(options.verbose, max_depth=depth)
                        else:
                            f.write('error: no TU for type signature 0x%16.16x]\n' % (type_sig))
            else:
                f.write('error: no .debug_info\n')
            if options.debug_names:
                debug_names = dwarf_ctx.get_debug_names()
                if debug_names:
                    debug_names.handle_options(options, f)
            if options.debug_cu_index:
                cu_index = dwarf_ctx.get_debug_cu_index()
                if cu_index:
                    cu_index.handle_options(options, f)
            if options.debug_tu_index:
                tu_index = dwarf_ctx.get_debug_tu_index()
                if tu_index:
                    tu_index.handle_options(options, f)
            if options.debug_str and dwarf_ctx.debug_str:
                dwarf_ctx.debug_str.dump(f=f)
            if options.debug_line_str and dwarf_ctx.debug_line_str:
                dwarf_ctx.debug_line_str.dump(f=f)
            if options.apple_names:
                apple_names = dwarf_ctx.get_apple_names()
                if apple_names:
                    f.write(str(apple_names))
            if options.apple_types:
                apple_types = dwarf_ctx.get_apple_types()
                if apple_types:
                    f.write(str(apple_types))
        if options.eh_frame_hdr:
            dump_eh_frame_hdr(options, objfile, f=f)

        if options.eh_frame or options.unwind_stats:
            dump_unwind_info(options, objfile, True, f=f)
