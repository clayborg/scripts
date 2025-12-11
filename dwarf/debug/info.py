#!/usr/bin/python

# Python imports
import bisect
import sys

# Package imports
from dwarf.cu import CompileUnit
from dwarf.ranges import DIERanges
from dwarf.tu import TypeUnit
import dwarf.options


class debug_info:
    '''Represents the .debug_info section in DWARF.'''
    def __init__(self, dwarf):
        self.dwarf = dwarf
        self.cus = None
        self.tus = None
        self.die_ranges = None
        self.debug_info_size = 0
        self.dwo_dwarfs = []

    def get_dwarf_units(self):
        if self.cus is None:
            self.cus = []
            data = self.dwarf.debug_info_data
            cu = CompileUnit(self)
            while cu.unpack(data):
                self.cus.append(cu)
                data.seek(cu.get_next_cu_offset())
                cu = CompileUnit(self)
            self.debug_info_size = data.tell()
        return self.cus

    def get_type_units(self):
        if self.tus is None:
            self.tus = []
            data = self.dwarf.debug_types_data
            if data:
                tu = TypeUnit(self)
                while tu.unpack(data):
                    self.tus.append(tu)
                    data.seek(tu.get_next_cu_offset())
                    tu = TypeUnit(self)
        return self.tus

    def get_compile_unit_with_path(self, cu_path):
        cus = self.get_dwarf_units()
        for cu in cus:
            if cu.get_path().endswith(cu_path):
                return cu
        return None

    def get_die_ranges(self):
        if self.die_ranges is None:
            self.die_ranges = DIERanges()
            cus = self.get_dwarf_units()
            for cu in cus:
                cu_die_ranges = cu.get_die_ranges()
                if cu_die_ranges:
                    self.die_ranges.ranges.extend(cu_die_ranges.ranges)
            self.die_ranges.sort()
        return self.die_ranges

    def get_type_unit_with_signature(self, type_sig, skeleton_cu_offset = None):
        if skeleton_cu_offset is not None:
            skeleton_cu = self.get_dwarf_unit_with_offset(skeleton_cu_offset)
            if skeleton_cu:
                dwo = skeleton_cu.get_dwo_or_dwp_dwarf()
                if dwo:
                    return (dwo.get_debug_info().get_type_unit_with_signature(type_sig)[0], skeleton_cu)
            return None
        dwarf_units = self.get_dwarf_units()
        for dwarf_unit in dwarf_units:
            if dwarf_unit.type_sig == type_sig:
                return (dwarf_unit, None)
        return (None, None)

    def get_dwarf_unit_with_offset(self, cu_offset):
        '''Get a DWARF unit whose header is at cu_offset.'''
        cus = self.get_dwarf_units()
        i = bisect.bisect_left(cus, cu_offset)
        if i < len(cus):
            return cus[i]
        else:
            return None

    def get_first_dwarf_unit_with_stmt_list(self, stmt_offset):
        '''Get the first DWARF unit whose DW_AT_stmt_list attribute matches.'''
        cus = self.get_dwarf_units()
        for cu in cus:
            cu_stmt_offset = cu.get_stmt_offset()
            if cu_stmt_offset == stmt_offset:
                return cu
        return None

    def get_dwarf_unit_with_str_offsets_base(self, str_offsets_base):
        '''Get the first DWARF unit whose DW_AT_str_offsets_base attribute matches.'''
        cus = self.get_dwarf_units()
        for cu in cus:
            cu_str_offsets_base = cu.get_str_offsets_base()
            if cu_str_offsets_base == str_offsets_base:
                return cu
        return None

    def lookup_address_in_cu(self, cu, address):
        die = cu.lookup_die_by_address(address)
        if die:
            # find the deepest DIE that contains the address
            die = die.lookup_address(address)
            print('Found DIE 0x%8.8x that contains address 0x%8.8x in %s:' % (
                  die.offset, address, die.get_die_ranges()))
            die.dump_ancestry(show_all_attrs=True)
        row = cu.lookup_row_by_address(address)
        if row:
            print('Found line table entry for 0x%8.8x:' % (
                  address))
            row.dump_lookup_results(cu.get_line_table().prologue)
            print('')
        return die or row

    def lookup_address(self, address):
        debug_aranges = self.dwarf.get_debug_aranges()
        if debug_aranges:
            print("got .debug_aranges")
            cu_offset = debug_aranges.get_cu_offset_for_address(address)
            if cu_offset >= 0:
                cu = self.get_dwarf_unit_with_offset(cu_offset)
                if self.lookup_address_in_cu(cu, address):
                    return True
        # .debug_aranges is only for functions, check again using our deeper
        # checks where we look for ourselves through all functions and globals
        cus = self.get_dwarf_units()
        for cu in cus:
            if self.lookup_address_in_cu(cu, address):
                return True
        return False

    def find_die_with_offset(self, offset):
        cu = self.get_compile_unit_containing_offset(offset)
        if cu:
            return cu.get_die_with_offset(offset)
        return None

    def find_dies_with_name(self, name):
        '''Find all DIEs with a given name by searching the debug info and
           the debug types. Returns a list of DIE objects.'''
        dies = []
        cus = self.get_dwarf_units()
        for cu in cus:
            cu_dies = cu.find_dies_with_name(name)
            if cu_dies:
                dies.extend(cu_dies)
        tus = self.get_type_units()
        for tu in tus:
            tu_dies = tu.find_dies_with_name(name)
            if tu_dies:
                dies.extend(tu_dies)
        return dies

    def get_compile_unit_containing_offset(self, offset):
        cus = self.get_dwarf_units()
        for cu in cus:
            if cu.contains_offset(offset):
                return cu
        return None

    def get_compile_unit_with_dwo_id(self, dwo_id):
        if dwo_id is None:
            return None

        cus = self.get_dwarf_units()
        for cu in cus:
            if cu.dwo_id == dwo_id:
                return cu
        return None

    def dump_debug_info(self, options, f=sys.stdout):
        f.write('.debug_info\n')
        indent = dwarf.options.options.indent_width
        if options.dwo_ids:
            for dwo_id in options.dwo_ids:
                cu = self.get_compile_unit_with_dwo_id(dwo_id)
                if cu:
                    cu.dump(verbose=options.verbose,
                            max_depth=options.recurse_depth,
                            f=f,
                            indent_width=indent)
                    if options.dump_dwo and cu.is_skeleton():
                        dwo_unit = cu.get_dwo_unit()
                        if dwo_unit:
                            dwo_unit.dump(verbose=options.verbose,
                                        max_depth=sys.maxsize, f=f,
                                        indent_width=indent)
                        elif cu.dwo_error:
                            f.write(cu.dwo_error)
                            f.write('\n')
        else:
            cus = self.get_dwarf_units()
            for cu in cus:
                cu.dump(verbose=options.verbose,
                        max_depth=options.recurse_depth,
                        f=f,
                        indent_width=indent)
                if options.dump_dwo and cu.is_skeleton():
                    dwo_unit = cu.get_dwo_unit()
                    if dwo_unit:
                        dwo_unit.dump(verbose=options.verbose,
                                      max_depth=options.recurse_depth, f=f,
                                      indent_width=indent)
                    elif cu.dwo_error:
                        f.write(cu.dwo_error)
                        f.write('\n')


    def dump_debug_types(self, verbose=False, f=sys.stdout, offset_adjust=0):
        tus = self.get_type_units()
        if tus:
            f.write('.debug_types\n')
            for tu in tus:
                tu.dump(verbose=verbose, max_depth=options.recurse_depth, f=f,
                        offset_adjust=offset_adjust)

    def __str__(self):
        s = '.debug_info\n'
        for cu in self.cus:
            s += str(cu) + '\n'
        return s


def dump_die_variables(die):
    total_byte_size = 0
    if die.get_tag().is_variable():
        type_die = die.get_attr_as_die(DW_AT_type)
        if type_die:
            byte_size = die.get_byte_size()
            if byte_size > 0:
                print('0x%8.8x: <%5u> %s' % (die.get_offset(), byte_size,
                                             die.get_name()))
                total_byte_size += byte_size
    child = die.get_child()
    while child:
        total_byte_size += dump_die_variables(child)
        child = child.get_sibling()
    return total_byte_size
