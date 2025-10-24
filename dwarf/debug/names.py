# Python imports
import sys
import io

# Package imports
from dwarf.DW.AT import DW_AT
from dwarf.DW.FORM import DW_FORM
from dwarf.DW.IDX import *
from dwarf.DW.TAG import DW_TAG
from dwarf.options import get_color_attr, get_color_form, get_color_tag
from dwarf.options import colorize_error_or_warning
# Package imports
from dwarf.defines import UINT32_MAX, UINT64_MAX


def case_folding_djb_hash(s):
    h = 5381
    for c in s.casefold():
        h = ((h << 5) + h) + ord(c)
    return h & UINT32_MAX


class IdxSpec:
    '''An attribute specification with the DWARF .debug_names attribute and form.'''
    def __init__(self, attr, form):
        self.attr = DW_IDX(attr)
        self.form = DW_FORM(form)

    def get_attr(self):
        '''Get the form as a dwarf.AT.Attribute() object.'''
        return self.attr

    def get_form(self):
        return self.form

    def dump(self, verbose=False, f=sys.stdout):
        f.write('%-*s %s' % (DW_IDX.max_width(),
                             get_color_attr(self.get_attr()),
                             get_color_form(self.get_form())))

    def __str__(self):
        return '%-*s %s' % (DW_IDX.max_width(),
                            get_color_attr(self.get_attr()),
                            get_color_form(self.get_form()))

    def __eq__(self, rhs):
        if rhs is None:
            return False
        return self.attr == rhs.attr and self.form == rhs.form

    def __ne__(self, rhs):
        if rhs is None:
            return True
        return self.attr != rhs.attr or self.form != rhs.form


class Abbrev:
    '''Represents a .debug_names abbreviation entry.'''
    def __init__(self, header, offset, code, tag, idx_specs):
        self.header = header  # .debug_names header
        self.offset = offset
        self.code = code
        self.tag = DW_TAG(tag)
        self.idx_specs = idx_specs

    def get_tag(self):
        return self.tag

    @classmethod
    def unpack(cls, header, data):
        offset = data.tell()
        code = data.get_uleb128()
        if code == 0:
            return None
        tag = data.get_uleb128()
        if tag == 0:
            return None
        idx_specs = []
        while True:
            dw_idx = data.get_uleb128()
            dw_form = data.get_uleb128()
            if dw_idx == 0 and dw_form == 0:
                break
            idx_specs.append(IdxSpec(dw_idx, dw_form))
        return Abbrev(header, offset, code, tag, idx_specs)

    def dump(self, verbose=False, f=sys.stdout):
        f.write('  [%u]: %-*s\n' % (self.code, DW_TAG.max_width(),
                                    get_color_tag(self.get_tag())))

        for attr_spec in self.idx_specs:
            f.write('        ')
            f.write(str(attr_spec))
            f.write('\n')


class AbbrevSet:
    '''Represents a collection of .debug_names abbreviation entries.'''
    def __init__(self, header, data):
        self.abbrevs = {}
        while True:
            abbrev = Abbrev.unpack(header, data)
            if abbrev is None:
                break
            self.abbrevs[abbrev.code] = abbrev

    def get_abbrev(self, code):
        if code in self.abbrevs:
            return self.abbrevs[code]
        return None

    def dump(self, verbose=False, f=sys.stdout):
        for key in self.abbrevs:
            self.abbrevs[key].dump(verbose, f)


class AttrValue:
    '''An attribute value object.

    This object contains the offset in the .debug_names section for the data
    for this attribute, the attribute specification and the value will be
    fetched on demand.'''
    def __init__(self, attr_spec, data):
        self.offset = data.tell()
        self.attr_spec = attr_spec
        (self.value, self.value_raw) = self.attr_spec.get_form().extract_value(data, None)

    def get_attr(self):
        '''Get the form as a DW_IDX.Attribute() object.'''
        return self.attr_spec.get_attr()

    def get_form(self):
        '''Get the form as a dwarf.FORM.DW_FORM() object.'''
        return self.attr_spec.get_form()

    def dump(self, options, f=sys.stdout):
        if options and options.verbose:
            f.write("%#8.8x: " % (self.offset))
            self.attr_spec.dump(options, f=f)
        else:
            f.write(get_color_attr(self.attr_spec.get_attr()))
        if self.attr_spec.attr in [DW_IDX.compile_unit, DW_IDX.type_unit]:
            f.write('(%u)' % (self.value))
        else:
            f.write('(%#x)' % (self.value))


class ResolvedEntry:
    '''Represents all of the components that match for a given entry'''
    def __init__(self, entry, cu, skeleton_cu, die, error=None, warning=None):
        self.entry = entry
        self.cu = cu
        self.skeleton_cu = skeleton_cu
        self.die = die
        self.error = error
        self.warning = warning

    def matches(self, expected_context=None) -> bool:
        if self.die is None or self.error is not None:
            return False
        if expected_context:
            actual_context = self.die.get_decl_context_as_string()
            if expected_context != actual_context:
                self.error = f'''error: context mistmatch\nExpect: "{expected_context}"\nActual: "{actual_context}"'''
                return False
        return True

    def dump(self, options, f=sys.stdout):
        f.write('Entry @ ')
        self.entry.dump(options, f=f)
        f.write('\n')
        if self.error:
            f.write(colorize_error_or_warning(self.error))
            f.write('\n')
        if self.warning:
            f.write(colorize_error_or_warning(self.warning))
            f.write('\n')
        die = self.die
        if die:
            if self.skeleton_cu:
                f.write('Skeleton CU:\n')
                self.skeleton_cu.dump(verbose=False, f=f, max_depth=0)
            if die.get_attr_as_int(DW_AT.declaration):
                f.write(colorize_error_or_warning("error: DIE in name table is a declaration and shouldn't be in the name lookup"))
                f.write('\n')
            die.dump_ancestry(f=f, dump_unit_info=True, show_all_attrs=True)
        else:
            if self.skeleton_cu:
                f.write('Skeleton CU:\n')
                self.skeleton_cu.dump(verbose=False, f=f, max_depth=0)
            if self.cu:
                f.write('CU:\n')
                self.cu.dump(verbose=False, f=f, max_depth=0)
            debug_info = self.entry.abbrev.header.debug_names.dwarf_ctx.get_debug_info()
            tu_offset = self.entry.get_tu_offset()
            if tu_offset is not None:
                f.write('tu @ %#8.8x\n' % (tu_offset))
                tu = debug_info.get_dwarf_unit_with_offset(tu_offset)
                if tu is None:
                    f.write('error: no TU found @ .debug_info[%#8.8x]\n' % (tu_offset))
                else:
                    tu.dump(verbose=False, f=f)
            type_sig = self.entry.get_tu_type_signature()
            if type_sig is not None:
                #f.write('type_sig = %#16.16x\n' % (type_sig))
                (foreign_tu, dwo_cu) = debug_info.get_type_unit_with_signature(type_sig, self.entry.get_cu_offset(False))
                if foreign_tu is None:
                    f.write('error: no TU found that matches the type signature %#16.16x\n' % (type_sig))
            cu_offset = self.entry.get_cu_offset()
            if cu_offset is not None:
                f.write('cu @ %#8.8x\n' % (cu_offset))
                cu = debug_info.get_dwarf_unit_with_offset(cu_offset)
                if cu is None:
                    f.write('error: no CU found @ .debug_info[%#8.8x]\n' % (cu_offset))
                else:
                    cu.dump(verbose=False, f=f)
                die_offset = cu.offset + self.entry.rel_die_offset
                f.write("die @ %#8.8x\n" % (die_offset))
                next_cu_offset = cu.get_next_cu_offset()
                if die_offset <= cu.offset or die_offset >= next_cu_offset:
                    f.write('error: relative die offset %#8.8x is larger than the CU info range [%#8.8x-%#8.8x)\n' % (die_offset, cu.offset, next_cu_offset))



class Entry:
    '''Represents a single accelerator table entry.'''
    def __init__(self, offset, abbrev, values):
        self.offset = offset
        self.name_idx = None  # Set after this is unpacked
        self.abbrev = abbrev
        self.values = values
        self.cu_idx = None
        self.tu_idx = None
        self.rel_die_offset = None
        self.parent_idx = None  # Entry index for parent of this item
        self.type_hash = None
        for value in self.values:
            if value.attr_spec.attr == DW_IDX.compile_unit:
                self.cu_idx = value.value
            elif value.attr_spec.attr == DW_IDX.type_unit:
                self.tu_idx = value.value
            elif value.attr_spec.attr == DW_IDX.die_offset:
                self.rel_die_offset = value.value
            elif value.attr_spec.attr == DW_IDX.parent:
                self.parent_idx = value.value
            elif value.attr_spec.attr == DW_IDX.type_hash:
                self.type_hash = value.value

    @classmethod
    def unpack(cls, data, abbrev_set):
        offset = data.tell()
        code = data.get_uleb128()
        if code == 0:
            return None
        abbrev = abbrev_set.get_abbrev(code)
        if abbrev is None:
            return None
        values = []
        for idx_spec in abbrev.idx_specs:
            values.append(AttrValue(idx_spec, data))
        return Entry(offset, abbrev, values)

    def get_attribute_value(self, dw_idx):
        for value in self.values:
            if value.attr_spec.attr == dw_idx:
                return value.value
        return None

    def get_cu_offset(self, only_if_no_tu = True):
        if only_if_no_tu and self.tu_idx is not None:
            return None
        cu_idx = self.cu_idx
        # If there is no CU index in this entry, return the first CU offset if
        # there is only one CU
        if cu_idx is None and self.abbrev.header.get_cu_offset(1) is None:
            cu_idx = 0
        return self.abbrev.header.get_cu_offset(cu_idx)

    def get_foreign_tu_skeleton_cu_offset(self):
        return

    def get_tu_offset(self):
        return self.abbrev.header.get_tu_offset(self.tu_idx)

    def get_tu_type_signature(self):
        return self.abbrev.header.get_foreign_type_signature(self.tu_idx);

    def resolve(self) -> ResolvedEntry:
        '''
            Given the entry, find the DWARF DIE for this entry.

            If this entry is for a foreign type unit, then only return the type
            DIE if the skeleton CU DIE for the .dwo file that originally
            contained the type unit. The type unit will have a DW_AT_dwo_name
            attribute that needs to match the DWO name of the returned DIE, or
            we must ignore this entry.
        '''
        debug_info = self.abbrev.header.debug_names.dwarf_ctx.get_debug_info()
        cu = None
        foreign_tu = None
        skeleton_cu = None
        if self.tu_idx is not None:
            type_sig = self.abbrev.header.get_foreign_type_signature(self.tu_idx)
            if type_sig is not None:
                cu_offset = self.get_cu_offset(False)
                (foreign_tu, skeleton_cu) = debug_info.get_type_unit_with_signature(type_sig, cu_offset)
                cu = foreign_tu
            else:
                cu = debug_info.get_dwarf_unit_with_offset(self.abbrev.header.get_tu_offset(self.tu_idx))
        elif self.cu_idx is not None:
            cu = debug_info.get_dwarf_unit_with_offset(self.abbrev.header.get_cu_offset(self.cu_idx))
        elif self.abbrev.header.get_cu_offset(1) is None:
            cu = debug_info.get_dwarf_unit_with_offset(self.abbrev.header.get_cu_offset(0))
        if cu is not None:
            if cu.is_skeleton():
                dwo_unit = cu.get_dwo_unit()
                if not dwo_unit:
                    return ResolvedEntry(
                        entry=self,
                        cu=None,
                        skeleton_cu=cu,
                        die=None,
                        error="error: can't find DWO with ID %#16.16x" % (cu.dwo_id))
                skeleton_cu = cu
                cu = dwo_unit
            die = cu.get_die_with_offset(cu.offset + self.rel_die_offset)
            if foreign_tu and skeleton_cu:
                skeleton_dwo_name = skeleton_cu.get_dwo_path()
                foreign_tu_dwo_name = cu.get_dwo_path()
                # print('skeleton_dwo_name: "%s"' % (skeleton_dwo_name))
                # print('foreign_tu_dwo_name: "%s"' % (foreign_tu_dwo_name))
                if skeleton_dwo_name != foreign_tu_dwo_name:
                    if skeleton_dwo_name and foreign_tu_dwo_name and skeleton_dwo_name.startswith(foreign_tu_dwo_name):
                        return ResolvedEntry(
                            entry=self,
                            cu=cu,
                            skeleton_cu=skeleton_cu,
                            die=die,
                            warning="error: can't find DWO with ID %#16.16x" % (cu.dwo_id))
                    else:
                        # print('Ignoring DWO mismatch for foreign TU:\nForeign TU:')
                        # die.dump_ancestry()
                        # print('Originating skeleton DWO DIE:')
                        # skeleton_cu_die.dump_ancestry()
                        return ResolvedEntry(
                            entry=self,
                            cu=cu,
                            skeleton_cu=skeleton_cu,
                            die=die,
                            error='error: type unit DWO name mismatch\n%s\n%s' % (skeleton_dwo_name, foreign_tu_dwo_name))
            return ResolvedEntry(
                entry=self,
                cu=cu,
                skeleton_cu=skeleton_cu,
                die=die)
        return ResolvedEntry(
            entry=self,
            cu=cu,
            skeleton_cu=skeleton_cu,
            die=None,
            error='error: die not found')

    def get_dwarf_units(self):
        '''
            Return the actual DWARF unit and if the DWARF unit is in a .dwo
            also return the skeleton dwarf unit for the foreign type unit.
        '''
        debug_info = self.abbrev.header.debug_names.dwarf_ctx.get_debug_info()
        tu_offset = self.get_tu_offset()
        if tu_offset is not None:
            tu = debug_info.get_dwarf_unit_with_offset(tu_offset)
            if tu is None:
                raise ValueError('missing TU for %#8.8x' % (tu_offset))
            return (tu, None)
        type_sig = self.get_tu_type_signature()
        if type_sig is not None:
            (foreign_tu, skeleton_cu) = debug_info.get_type_unit_with_signature(type_sig, self.get_cu_offset(False))
            if foreign_tu is None:
                raise ValueError('missing TU with signature  %#16.16x' % (type_sig))
            return (foreign_tu, skeleton_cu)
        cu_offset = self.get_cu_offset()
        if cu_offset is not None:
            cu = debug_info.get_dwarf_unit_with_offset(cu_offset)
            if cu is None:
                raise ValueError('missing CU for %#8.8x' % (cu_offset))
            if cu.is_skeleton:
                return (cu.get_dwo_unit(), cu)
            return (cu, None)
        raise ValueError('missing CU, TU, or foreign TU attributes')

    def get_die_offset(self):
        dwarf_unit = self.get_dwarf_units()[0]
        if dwarf_unit:
            return dwarf_unit.offset + self.rel_die_offset
        return None

    def get_name(self):
        if self.name_idx is not None:
            return self.abbrev.header.get_string(self.name_idx)
        return None

    # def dump_resolved(self, options, f=sys.stdout):
    #     f.write('Entry @ ')
    #     self.dump(options, f=f)
    #     f.write('\n')
    #     resolved_entry = self.resolve()
    #     if resolved_entry.error:
    #         f.write(colorize_error_or_warning(resolved_entry.error))
    #         f.write('\n')
    #     if resolved_entry.warning:
    #         f.write(colorize_error_or_warning(resolved_entry.warning))
    #         f.write('\n')
    #     die = resolved_entry.die
    #     if die:
    #         if resolved_entry.skeleton_cu:
    #             f.write('Skeleton CU:\n')
    #             resolved_entry.skeleton_cu.dump(verbose=False, f=f, max_depth=0)
    #         if die.get_attr_as_int(DW_AT.declaration):
    #             f.write(colorize_error_or_warning("error: DIE in name table is a declaration and shouldn't be in the name lookup"))
    #             f.write('\n')
    #         die.dump_ancestry(f=f, dump_unit_info=True, show_all_attrs=True)
    #     else:
    #         if resolved_entry.skeleton_cu:
    #             f.write('Skeleton CU:\n')
    #             resolved_entry.skeleton_cu.dump(verbose=False, f=f, max_depth=0)
    #         if resolved_entry.cu:
    #             f.write('CU:\n')
    #             resolved_entry.cu.dump(verbose=False, f=f, max_depth=0)
    #         debug_info = self.abbrev.header.debug_names.dwarf_ctx.get_debug_info()
    #         tu_offset = self.get_tu_offset()
    #         if tu_offset is not None:
    #             f.write('tu @ %#8.8x\n' % (tu_offset))
    #             tu = debug_info.get_dwarf_unit_with_offset(tu_offset)
    #             if tu is None:
    #                 f.write('error: no TU found @ .debug_info[%#8.8x]\n' % (tu_offset))
    #             else:
    #                 tu.dump(verbose=False, f=f)
    #         type_sig = self.get_tu_type_signature()
    #         if type_sig is not None:
    #             #f.write('type_sig = %#16.16x\n' % (type_sig))
    #             (foreign_tu, dwo_cu) = debug_info.get_type_unit_with_signature(type_sig, self.get_cu_offset(False))
    #             if foreign_tu is None:
    #                 f.write('error: no TU found that matches the type signature %#16.16x\n' % (type_sig))
    #         cu_offset = self.get_cu_offset()
    #         if cu_offset is not None:
    #             f.write('cu @ %#8.8x\n' % (cu_offset))
    #             cu = debug_info.get_dwarf_unit_with_offset(cu_offset)
    #             if cu is None:
    #                 f.write('error: no CU found @ .debug_info[%#8.8x]\n' % (cu_offset))
    #             else:
    #                 cu.dump(verbose=False, f=f)
    #             die_offset = cu.offset + self.rel_die_offset
    #             f.write("die @ %#8.8x\n" % (die_offset))
    #             next_cu_offset = cu.get_next_cu_offset()
    #             if die_offset <= cu.offset or die_offset >= next_cu_offset:
    #                 f.write('error: relative die offset %#8.8x is larger than the CU info range [%#8.8x-%#8.8x)\n' % (die_offset, cu.offset, next_cu_offset))

    def dump(self, options, f=sys.stdout):
        f.write("%#8.8x: \"%s\" %s " % (self.offset,
                                        self.get_name(),
                                        get_color_tag(self.abbrev.get_tag())))
        if options.verbose:
            for (i, value) in enumerate(self.values):
                if i > 0:
                    f.write(', ')
                f.write('%s=%u' % (get_color_attr(value.get_attr()),
                                   value.value))
            f.write(' (')
        (cu, skeleton_cu) = self.get_dwarf_units()
        if (cu):
            f.write(' cu = %#8.8x' % (cu.offset))
        if skeleton_cu:
            f.write(' skeleton_cu = %#8.8x' % (skeleton_cu.offset))
        f.write(' die = %#8.8x' % (self.get_die_offset()))
        if options.verbose:
            f.write(')')


class VerifyStats:
    def __init__(self):
        self.entry_count = 0
        self.declarations = 0
        self.name_mismatches = 0
        self.type_dwo_mismatch = 0
        self.empty_entries = 0

    def dump(self, f):
        f.write('VerifyStats:\n')
        f.write('      entry_count: %u\n' % (self.entry_count))
        f.write('     declarations: %u\n' % (self.declarations))
        f.write('  name_mismatches: %u\n' % (self.name_mismatches))
        f.write('type_dwo_mismatch: %u\n' % (self.type_dwo_mismatch))
        f.write('    empty_entries: %u\n' % (self.empty_entries))

class Header:
    '''Represents a .debug_names accelerator table header.'''
    def __init__(self, debug_names, data):
        self.debug_names = debug_names
        self.data = data
        self.abbrevs = None
        self.offset_size = 4
        self.offset = data.tell()
        self.unit_length = data.get_uint32()
        if self.unit_length == UINT32_MAX:
            self.offset_size = 8
            self.unit_length = data.get_uint64()
        self.next_offset = self.offset + (data.tell() - self.offset) + self.unit_length
        self.version = data.get_uint16()
        data.get_uint16() # Skip 2 bytes of padding
        self.comp_unit_count = data.get_uint32()
        self.local_type_unit_count = data.get_uint32()
        self.foreign_type_unit_count = data.get_uint32()
        self.bucket_count = data.get_uint32()
        self.name_count = data.get_uint32()
        self.abbrev_table_size = data.get_uint32()
        self.augmentation_string_size = data.get_uint32()
        self.augmentation_string = data.get_fixed_length_c_string(self.augmentation_string_size)
        offset = data.tell()
        self.cus_offset = offset
        offset += self.comp_unit_count * self.offset_size
        self.tus_offset = offset
        offset += self.local_type_unit_count * self.offset_size
        self.foreign_tus_offset = offset
        offset += self.foreign_type_unit_count * 8
        self.buckets_offset = offset
        offset += self.bucket_count * 4
        self.hashes_offset = offset
        if self.bucket_count > 0:
            offset += self.name_count * 4
        self.string_offsets_offset = offset
        offset += self.name_count * self.offset_size
        self.entry_offsets_offset = offset
        offset += self.name_count * self.offset_size
        self.abbrevs_offset = offset
        offset += self.abbrev_table_size
        self.entries_offset = offset
        self.entry_series = None

    def lookup_name(self, name):
        idx, entry_offset = self.lookup_name_index_and_entry_offset(name)
        if entry_offset is None:
            return None
        return self.get_entries_at_offset(idx, entry_offset)

    def get_abbrevs(self):
        if self.abbrevs is None:
            self.data.push_offset_and_seek(self.abbrevs_offset)
            self.abbrevs = AbbrevSet(self, self.data.read_data(self.abbrev_table_size))
            self.data.pop_offset_and_seek()
        return self.abbrevs

    def get_cu_offset(self, idx):
        if idx is not None:
            if 0 <= idx and idx < self.comp_unit_count:
                self.data.seek(self.cus_offset + (idx * self.offset_size))
                return self.data.get_uint32()
        return None

    def get_tu_offset(self, idx):
        if idx is not None:
            if 0 <= idx and idx < self.local_type_unit_count:
                self.data.seek(self.tus_offset + (idx * self.offset_size))
                return self.data.get_uint32()
        return None

    def get_foreign_type_signature(self, unadjusted_idx):
        if unadjusted_idx is not None:
            idx = unadjusted_idx - self.local_type_unit_count
            if 0 <= idx and idx < self.foreign_type_unit_count:
                self.data.seek(self.foreign_tus_offset + (idx * 8))
                return self.data.get_uint64()
        return None

    def get_bucket(self, idx):
        if 0 <= idx and idx < self.bucket_count:
            self.data.seek(self.buckets_offset + (idx * 4))
            return self.data.get_uint32()
        return None

    def get_hash(self, idx):
        if 0 < idx and idx < self.name_count+1:
            self.data.seek(self.hashes_offset + ((idx - 1) * 4))
            return self.data.get_uint32()
        return None

    def get_entry_offset(self, idx):
        if 0 < idx and idx <= self.name_count:
            self.data.seek(self.entry_offsets_offset + ((idx - 1) * self.offset_size))
            return self.data.get_offset() + self.entries_offset
        return None

    def get_string_offset(self, idx):
        if 0 < idx and idx <= self.name_count+1:
            self.data.seek(self.string_offsets_offset + ((idx - 1) * self.offset_size))
            return self.data.get_offset()
        return None

    def get_string(self, idx):
        strp = self.get_string_offset(idx)
        if strp is None:
            return None
        debug_str_data = self.debug_names.dwarf_ctx.debug_str_data
        debug_str_data.push_offset_and_seek(strp)
        s = debug_str_data.get_c_string()
        debug_str_data.pop_offset_and_seek()
        return s

    def get_entries_at_offset(self, name_idx, entry_offset):
        entries = []
        self.data.seek(entry_offset)
        while True:
            entry = Entry.unpack(self.data, self.get_abbrevs())
            if entry is None:
                break
            entry.name_idx = name_idx
            entries.append(entry)
        return entries

    def get_all_entry_series(self):
        if self.entry_series is None:
            self.entry_series = []
            for name_idx in range(1, self.name_count+1):
                offset = self.get_entry_offset(name_idx)
                if offset is None:
                    break
                series = self.get_entries_at_offset(name_idx, offset)
                if not series:
                    break
                self.entry_series.append(series)
        return self.entry_series

    def dump(self, options, f=sys.stdout):
        f.write(".debug_names[%#8.8x]:\n" % (self.offset))
        f.write("  unit_length = %#8.8x (next @ %#8.8x)\n" % (self.unit_length, self.offset + 4 + self.unit_length))
        f.write("  version = %#4.4x\n" % (self.version))
        f.write("  comp_unit_count = %#8.8x\n" % (self.comp_unit_count))
        f.write("  local_type_unit_count = %#8.8x\n" % (self.local_type_unit_count))
        f.write("  foreign_type_unit_count = %#8.8x\n" % (self.foreign_type_unit_count))
        f.write("  bucket_count = %#8.8x (%u)\n" % (self.bucket_count, self.bucket_count))
        f.write("  name_count = %#8.8x (%u)\n" % (self.name_count, self.name_count))
        f.write("  abbrev_table_size = %#8.8x (%u)\n" % (self.abbrev_table_size, self.abbrev_table_size))
        f.write("  augmentation_string_size = %#8.8x (%u)\n" % (self.augmentation_string_size, self.augmentation_string_size))
        f.write("  augmentation_string = \"%s\"\n" % (self.augmentation_string))
        if options.debug:
            # Dump the CU list
            if self.comp_unit_count > 0:
                f.write('CUs @ %#8.8x:\n' % (self.cus_offset))
                for idx in range(self.comp_unit_count):
                    cu_offset = self.get_cu_offset(idx)
                    f.write('  [%u] %#8.8x\n' % (idx, cu_offset))

            # Dump the TU list
            num_tus = self.local_type_unit_count
            if num_tus:
                f.write('TUs @ %#8.8x:\n' % (self.tus_offset))
                for idx in range(num_tus):
                    tu_offset = self.get_tu_offset(idx)
                    f.write('  [%u] %#8.8x\n' % (idx, tu_offset))

            # Dump the foreign TU list
            num_ftus = self.foreign_type_unit_count
            if num_ftus > 0:
                f.write('FTUs @ %#8.8x:\n' % (self.foreign_tus_offset))
                for idx in range(num_tus, num_tus + num_ftus):
                    type_sig = self.get_foreign_type_signature(idx)
                    f.write('  [%u] %#16.16x\n' % (idx, type_sig))

            # Dump the buckets
            f.write('Buckets @ %#8.8x:\n' % (self.buckets_offset))
            for idx in range(self.bucket_count):
                bucket = self.get_bucket(idx)
                f.write('  [%u] %#8.8x\n' % (idx, bucket))

            # Dump the hashes
            f.write('Hashes @ %#8.8x:\n' % (self.hashes_offset))
            f.write('Strps @ %#8.8x:\n' % (self.string_offsets_offset))
            f.write('Entry Offsets @ %#8.8x:\n' % (self.string_offsets_offset))
            f.write('Index    Hash       Strp       Entry Off  Name\n')
            f.write('-------- ---------- ---------- ---------- ========================\n')
            for idx in range(1, self.name_count+1):
                hash = self.get_hash(idx)
                strp = self.get_string_offset(idx)
                s = self.get_string(idx)
                entry_offset = self.get_entry_offset(idx)
                f.write('[%6u] %#8.8x %#8.8x %#8.8x "%s"\n' % (idx, hash, strp, entry_offset, s))

            f.write('Abbrev Header @ %#8.8x:\n' % (self.abbrevs_offset))

        if options.verbose:
            self.get_abbrevs().dump(options.verbose, f)

        for entry_series in self.get_all_entry_series():
            name = entry_series[0].get_name()
            if name is not None:
                f.write('name = "%s":\n' % (name))
            for entry in entry_series:
                entry.dump(options, f=f)
                f.write('\n')
                if name != entry.get_name():
                    f.write('error: entry name mismatch "%s" != "%s"\n'% (name, entry.get_name()))
            f.write('\n')

    def __str__(self):
        output = io.StringIO()
        self.dump(True, output)
        return output.getvalue()

    def lookup_name_index_and_entry_offset(self, name):
        actual_hash = case_folding_djb_hash(name)
        # print('hash of "%s" is %#8.8x' % (name, actual_hash))
        bucket_idx = actual_hash % self.bucket_count
        # print('bucket_idx is %u' % (bucket_idx))
        idx = self.get_bucket(bucket_idx)
        if idx == 0:
            # print('empty bucket_idx')
            return (None, None)
        while idx < self.name_count:
            curr_hash = self.get_hash(idx)
            # print('hash[%u] = %#8.8x' % (idx, curr_hash))
            if actual_hash == curr_hash:
                # print('hash match')
                curr_name = self.get_string(idx)
                if name == curr_name:
                    # print('name match')
                    offset = self.get_entry_offset(idx)
                    # print('Entry @ %#8.8x' % (offset))
                    return (idx, offset)
            if (curr_hash % self.bucket_count) != bucket_idx:
                # print('end of hashes for bucket')
                break
            idx += 1
        return (None, None)

    def verify_name(self, options, f, verify_stats, name):
        f.write('verifying name: "%s"\n' % (name))
        entries = self.lookup_name(name)
        if entries:
            f.write('%u entries\n' % (len(entries)))
            for entry in entries:
                verify_stats.entry_count += 1
                resolved_entry = entry.resolve()
                die = resolved_entry.die
                if die:
                    #die.dump_ancestry(f=f)
                    if die.get_attr_as_int(DW_AT.declaration):
                        verify_stats.declarations += 1
                    # TODO: add linkage name searches too
                    name_matches = False
                    if name.startswith('_Z'):
                        if die.get_mangled_name() == name:
                            name_matches = True
                    if not name_matches:
                        if die.get_name() == name:
                            name_matches = True
                    if not name_matches:
                        f.write('Name mismatch for DIE:\n')
                        die.dump(f=f, show_all_attrs=True)
                        verify_stats.name_mismatches += 1
                else:
                    if 'type unit DWO name mismatch' in resolved_entry.error:
                        verify_stats.type_dwo_mismatch += 1
                    else:
                        if resolved_entry.error:
                            f.write(colorize_error_or_warning(resolved_entry.error))
                            f.write('\n')
                        if resolved_entry.warning:
                            f.write(colorize_error_or_warning(resolved_entry.warning))
                            f.write('\n')

        else:
            verify_stats.empty_entries += 1
            f.write('error: name "%s" has not entries?\n' % (name))
        verify_stats.dump(f)

    def verify(self, options, f, verify_stats):
        if options.lookup_names:
            for name in options.lookup_names:
                self.verify_name(options, f, verify_stats, name)
        for str_idx in range(1, self.name_count+1):
            name = self.get_string(str_idx)
            self.verify_name(options, f, verify_stats, name)


class debug_names:
    '''Represents the .debug_names section in DWARF.'''
    def __init__(self, dwarf_ctx):
        self.dwarf_ctx = dwarf_ctx
        self.data = dwarf_ctx.debug_names_data
        self.headers = []
        self.data.seek(0)
        self.unpack(self.data)
        self.options = None

    def unpack(self, data):
        data_len = self.data.get_size()
        self.data.seek(0)
        while self.data.tell() < data_len:
            self.headers.append(Header(self, data))
            self.data.seek(self.headers[-1].next_offset)

    def handle_options(self, options, f):
        self.options = options
        if options.debug_names:
            dump = True
            if options.verify_dwarf:
                dump = False
                self.verify(f)
            if options.lookup_names:
                dump = False
                for name in options.lookup_names:
                    self.lookup_name(name, options.parent_context)
            if dump:
                self.dump(f=f)

    def lookup_name(self, name, parent_context = None):
        matches = 0
        max_matches = self.options.max_matches
        stop_iterating = False
        for header in self.headers:
            entries = header.lookup_name(name)
            if entries:
                for entry in entries:
                    resolved_entry = entry.resolve()
                    if resolved_entry.matches(parent_context):
                        matches += 1
                    resolved_entry.dump(self.options)
                    print()
                    if max_matches and matches >= max_matches:
                        stop_iterating = True
                        break
            if stop_iterating:
                break
        if matches == 0:
            print('no matches found for "%s" in %u .debug_names tables' % (name, len(self.headers)))

    def dump(self, f=sys.stdout):
        for header in self.headers:
            header.dump(options=self.options, f=f)

    def verify(self, f):
        verify_stats = VerifyStats()
        for header in self.headers:
            header.verify(self.options, f, verify_stats)
        verify_stats.dump(f)

    def __str__(self):
        output = io.StringIO()
        self.dump(verbose=True, f=output)
        return output.getvalue()
