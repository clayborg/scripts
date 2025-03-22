#!/usr/bin/python

import sys
import pprint
from dwarf.DW.AT import DW_AT


def dump_type_stats(options, dwarf_ctx, f=sys.stdout):
    type_stats = TypeStats()
    debug_info = dwarf_ctx.get_debug_info()
    cus = debug_info.get_dwarf_units()
    for cu in cus:
        type_stats.handle_unit(cu)
        cu.free_memory()
    type_stats.dump(options, f)


class TypeStats():
    def __init__(self):
        self.type_infos = {}

    def handle_unit(self, unit):
        '''Handle a DWARF unit (compile unit or type unit).'''
        self.handle_die(unit.get_die())

    def handle_die(self, die):
        '''Handle a DIE from a DWARF unit.

        We must be careful when showing statistics on types to not report a
        type that is contained within a type.
        '''
        type_id = get_type_identifier(die)
        if type_id:
            if type_id not in self.type_infos:
                self.type_infos[type_id] = {
                    'size': die.get_encoding_size(),
                    'count': 1,
                    'id': type_id,
                    'dies': [die.get_offset()]
                }
            else:
                self.type_infos[type_id]['size'] += die.get_encoding_size()
                self.type_infos[type_id]['count'] += 1
                self.type_infos[type_id]['dies'].append(die.get_offset())
        else:
            child_die = die.get_child()
            while child_die:
                self.handle_die(child_die)
                child_die = child_die.get_sibling()

    def dump(self, options, f):
        sort_key_to_type_infos = {}
        for type_id in self.type_infos:
            sort_key = self.type_infos[type_id][options.type_stats_sort]
            if sort_key in sort_key_to_type_infos:
                sort_key_to_type_infos[sort_key].append(self.type_infos[type_id])
            else:
                sort_key_to_type_infos[sort_key] = [self.type_infos[type_id]]
        for key in sorted(sort_key_to_type_infos.keys(), reverse=True):
            for ti in sort_key_to_type_infos[key]:
                f.write("%8u %8u %s" % (ti['size'], ti['count'], ti['id']))
                if options.verbose:
                    f.write(' [')
                    for die_offset in ti['dies']:
                        f.write(' %#8.8x' % (die_offset))
                    f.write(' ]')
                f.write('\n')


def get_type_identifier(die):
    '''Return an type identifier string that uniquely identifies a type.

    The information contains the full qualified name of the type, the byte
    size, and the decl file and line if available.
    '''
    tag = die.get_tag()
    if not tag.is_type() or die.get_attr_as_int(DW_AT_declaration):
        return None
    typename = die.get_type_name()
    byte_size = die.get_byte_size()
    decl_file = die.get_attr_as_file(DW_AT_decl_file)
    if decl_file:
        decl_line = die.get_attr_as_int(DW_AT_decl_line)
        return "%s <%u> %s:%u" % (typename, byte_size, decl_file,
                                    decl_line)
    else:
        return "%s <%u>" % (typename, byte_size)
