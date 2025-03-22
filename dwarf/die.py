#!/usr/bin/python

# Python imports
import io
import subprocess
import sys

# Package imports
import dwarf.attr
from dwarf.defines import is_string
from dwarf.DW.AT import DW_AT
from dwarf.DW.SECT import DW_SECT
from dwarf.DW.TAG import DW_TAG
from dwarf.ranges import AddressRange, AddressRangeList


class DIE:
    '''A class that represents a debug info entry (DIE) in DWARF.'''
    def __init__(self, cu, die_index, depth, abbrev_set, data):
        self.cu = cu
        self.die_index = die_index
        self.offset = data.tell()
        self.depth = depth
        self.abbrev = None
        self.child = None
        self.name = -1
        self.mangled = -1
        self.demangled = -1
        self.user_visible_name = -1
        self.ranges = None
        self.userdata = None
        abbrev_code = data.get_uleb128()
        if abbrev_code != 0:
            self.abbrev = abbrev_set.get_abbrev_decl(abbrev_code)
            if self.abbrev is None:
                raise ValueError("DIE abbrev code %u not found", abbrev_code)
            elif not self.abbrev.skip(self, data):
                raise ValueError('Failed to skip DIE 0x%8.8x' % (self.offset))

    def search(self, search, depth=sys.maxsize):
        matching_dies = []
        if search.die_matches(self):
            matching_dies.append(self)
        if depth > 0:
            child = self.get_child()
            if child:
                sibling = child.get_sibling()
                while sibling:
                    matching_dies.extend(sibling.search(search, depth-1))
                    sibling = sibling.get_sibling()
        return matching_dies

    def get_tag(self):
        if self.abbrev:
            return DW_TAG(self.abbrev.tag)
        else:
            return DW_TAG(0)

    def __lt__(self, offset):
        return self.offset < offset

    def is_valid(self):
        return self.offset != 0

    def get_base_address(self):
        '''
            Get the base address for a DIE for .debug_loc. This will be the low
            pc of the first parent DW_TAG_subprogram.
        '''
        if self.get_tag().is_function():
            return self.get_attr_as_int(DW_AT.low_pc, None)
        parent = self.get_parent()
        if parent:
            return parent.get_base_address()
        return None

    def lookup_address(self, address):
        '''Find the deepest most child DIE that still contains address'''
        die_ranges = self.get_die_ranges()
        if die_ranges.contains(address):
            for die in self.get_children():
                lookup_die = die.lookup_address(address)
                if lookup_die:
                    return lookup_die
            return self
        else:
            return None

    def get_name(self):
        if self.name == -1:
            self.name = self.get_attr_as_string(DW_AT.name)
        return self.name

    def get_mangled_name(self):
        if self.mangled == -1:
            self.mangled = self.get_first_attribute_value_as_string(
                [DW_AT.MIPS_linkage_name, DW_AT.linkage_name])
        return self.mangled

    def get_demangled_name(self):
        if self.demangled == -1:
            mangled = self.get_mangled_name()
            if mangled:
                self.demangled = subprocess.check_output(['c++filt', '-n',
                                                          mangled]).rstrip()
            else:
                self.demangled = None
        return self.demangled

    def get_mangled_or_qualified_name(self):
        name = self.get_mangled_name()
        if name:
            return name
        return self.get_qualified_name()

    def get_qualified_name(self):
        name = self.get_name()
        if name:
            decl_ctx = self.get_decl_context_as_string()
            if decl_ctx:
                return decl_ctx + '::' + name
        return name

    def get_display_name(self):
        if self.user_visible_name == -1:
            self.user_visible_name = None
            demangled = self.get_demangled_name()
            if demangled:
                self.user_visible_name = demangled
            else:
                self.user_visible_name = self.get_qualified_name()
        return self.user_visible_name

    def get_debug_ranges(self):
        '''Get the DW_AT_ranges address ranges only. Don't check the
        low_pc or high_pc'''
        ranges_offset = self.get_attr_as_int(DW_AT.ranges, -1)
        if ranges_offset >= 0:
            debug_ranges = self.cu.debug_info.dwarf.get_debug_ranges()
            if debug_ranges:
                return debug_ranges.get_debug_ranges_at_offset(self.cu,
                                                               ranges_offset)
        return None

    def get_die_ranges(self):
        '''Get the DIE's address range using DW_AT.ranges, or the
        low_pc/high_pc, or global variable'''
        if self.ranges is None:
            debug_ranges = self.get_debug_ranges()
            if debug_ranges:
                self.ranges = debug_ranges.ranges
            else:
                self.ranges = AddressRangeList()
                # No DW_AT_ranges attribute, look for high/low PC
                low_pc = self.get_attr_as_int(DW_AT.low_pc, -1)
                if low_pc >= 0:
                    high_pc_attr_value = self.get_attr_value(
                        DW_AT.high_pc)
                    if high_pc_attr_value:
                        if high_pc_attr_value.get_form().is_address():
                            high_pc = high_pc_attr_value.value
                        else:
                            high_pc = low_pc + high_pc_attr_value.value
                        if low_pc < high_pc:
                            self.ranges.append(AddressRange(low_pc, high_pc))
                else:
                    global_addr = self.get_global_variable_address()
                    if global_addr >= 0:
                        byte_size = self.get_byte_size()
                        if byte_size > 0:
                            self.ranges.append(
                                AddressRange(global_addr,
                                             global_addr + byte_size))
                self.ranges.finalize()
        return self.ranges

    def get_global_variable_address(self):
        if self.abbrev:
            tag = self.abbrev.tag
            if tag == DW_TAG.variable:
                location_attr_value = self.get_attr_value(DW_AT.location)
                if location_attr_value:
                    location = location_attr_value.get_value(self)
                    if location is None:
                        return -1
                    if location.is_location_list():
                        return -1
                    if location.has_file_address():
                        try:
                            value = location.evaluate()
                        except ValueError:
                            value = None
                        if value:
                            return value.value
        return -1

    def get_array_bounds(self):
        if self.abbrev:
            tag = self.abbrev.tag
            if tag == DW_TAG.array_type:
                return self.get_child().get_array_bounds()
            elif tag == DW_TAG.subrange_type:
                bound = None
                attr_values = self.get_attrs(False)
                if attr_values:
                    lo = 0
                    hi = -1
                    for attr_value in attr_values:
                        attr = attr_value.attr_spec.attr
                        if attr == DW_AT.count:
                            lo = 0
                            hi = attr_value.value
                        elif attr == DW_AT.lower_bound:
                            lo = attr_value.value
                        elif attr == DW_AT.upper_bound:
                            hi = attr_value.value + 1
                    if lo <= hi:
                        bound = (lo, hi)
                child = self.get_child()
                if bound:
                    bounds = [bound]
                    if child:
                        child_bound = self.get_array_bounds()
                        if child_bound:
                            bounds.extend(child_bound)
                    return bounds
        return None

    def get_encoding_size(self):
        '''Get the size in byte of this DIE including all child DIEs.'''
        return self.get_sibling().get_offset() - self.get_offset()

    def get_byte_size(self):
        if self.abbrev:
            byte_size = self.get_attr_as_int(DW_AT.byte_size, -1)
            if byte_size >= 0:
                return byte_size
            tag = self.get_tag()
            if tag.has_pointer_size():
                return self.cu.dwarf_info.addr_size
            elif tag == DW_TAG.array_type:
                type_die_offset = self.get_attr_as_int(DW_AT.type, -1)
                if type_die_offset >= 0:
                    type_die = self.get_referenced_die_with_offset(
                        type_die_offset)
                    if type_die:
                        type_byte_size = type_die.get_byte_size()
                        if type_byte_size >= 0:
                            bounds = self.get_array_bounds()
                            if bounds:
                                array_byte_size = 0
                                for (lo, hi) in bounds:
                                    array_byte_size += type_byte_size * (hi -
                                                                         lo)
                                return array_byte_size
            else:
                type_die = self.get_attr_as_die(DW_AT.type)
                if type_die:
                    type_byte_size = type_die.get_byte_size()
                    if type_byte_size >= 0:
                        return type_byte_size
        return -1

    def append_die_ranges(self, die_ranges):
        arange_list = self.get_die_ranges()
        if arange_list:
            die_ranges.append_die_ranges(self, arange_list)

    def get_parent_decl_context_die(self):
        # Follow specifications first as this leads to the decl context.
        spec_die = self.get_attr_as_die(DW_AT.specification)
        if spec_die:
            result = spec_die.get_parent_decl_context_die()
            if result:
                return result
        # Follow abtract origins next as this leads to the decl context.
        ao_die = self.get_attr_as_die(DW_AT.abstract_origin)
        if ao_die:
            result = ao_die.get_parent_decl_context_die()
            if result:
                return result
        # If we have an inlined function, its decl context is usually in
        # one of the above cases
        if self.abbrev.tag == DW_TAG.inlined_subroutine:
            return None

        # Now get the parent of this DIE and see if it is a decl context die.
        parent_die = self.get_parent()
        if parent_die:
            parent_tag = parent_die.get_tag()
            if parent_tag.is_decl_context():
                return parent_die
            if parent_die.abbrev.tag == DW_TAG.lexical_block:
                return parent_die.get_parent_decl_context_die()
        return None

    def get_decl_context_as_string(self):
        parent_ctx_die = self.get_parent_decl_context_die()
        if parent_ctx_die:
            parent_mangled = parent_ctx_die.get_mangled_name()
            if parent_mangled:
                return parent_ctx_die.get_display_name()
            else:
                parent_name = parent_ctx_die.get_name()
                if parent_name is None:
                    parent_name = parent_ctx_die.get_type_name()
                    if parent_name is None:
                        parent_name = "(anonymous %s)" % (
                                parent_ctx_die.get_tag())
                parent_decl_ctx = parent_ctx_die.get_decl_context_as_string()
                if parent_decl_ctx:
                    return parent_decl_ctx + '::' + parent_name
                else:
                    return parent_name
        return None

    def contains_inline_subroutine(self, depth=0):
        '''Returns True if this die contains a DW_TAG_inlined_subroutine.'''
        tag = self.get_tag()
        if tag == DW_TAG.subprogram:
            if depth > 0:
                return False
        elif tag == DW_TAG.inlined_subroutine:
            return True
        elif tag != DW_TAG.lexical_block:
            # Any children that are not DW_TAG_subprogram,
            # DW_TAG_inlined_subroutine or DW_TAG_lexical_block need not be
            # searched.
            return False
        for child_die in self.get_children():
            if child_die.contains_inline_subroutine(depth+1):
                return True
        return False

    def get_offset(self):
        return self.offset

    def get_first_attribute_value(self, attrs):
        if self.abbrev and self.abbrev.might_have_any_attributes(attrs):
            data = self.cu.data
            data.seek(self.offset)
            data.get_uleb128()  # Skip the abbrev code
            other_die_offsets = []
            for attr_spec in self.abbrev.attribute_specs:
                curr_attr = attr_spec.attr
                if curr_attr in attrs:
                    attr_value = dwarf.attr.Value(attr_spec)
                    if attr_value.extract_value(data, self):
                        return attr_value
                elif (curr_attr == DW_AT.abstract_origin or
                      curr_attr == DW_AT.specification):
                    attr_value = dwarf.attr.Value(attr_spec)
                    if attr_value.extract_value(data, self):
                        other_die_offsets.append(attr_value.value)
                else:
                    if not attr_spec.get_form().skip(self, data):
                        print('error: failed to skip the attribute %s in die '
                              '0x%8.8x' % (attr_spec, self.offset))
                        return None
            for die_offset in other_die_offsets:
                die = self.get_referenced_die_with_offset(die_offset)
                if die:
                    attr_value = die.get_first_attribute_value(
                        attrs)
                    if attr_value:
                        return attr_value
        return None

    def get_first_attribute_value_as_string(self, attrs):
        attr_value = self.get_first_attribute_value(attrs)
        if attr_value and is_string(attr_value.value):
            return attr_value.value
        return None

    def __get_attr_value(self, attr, data):
        '''This function has many returns, so this function allows the
           get_attr_value() function to save and restore the data position
           correctly and this function can do early returns safely.'''
        data.get_uleb128()  # Skip the abbrev code
        other_die_offsets = []
        for attr_spec in self.abbrev.attribute_specs:
            curr_attr = attr_spec.attr
            if curr_attr == attr:
                attr_value = dwarf.attr.Value(attr_spec)
                if attr_value.extract_value(data, self):
                    return attr_value
                else:
                    print('error: failed to extract attribute value...')
                    return None
            elif (curr_attr == DW_AT.abstract_origin or
                    curr_attr == DW_AT.specification):
                attr_value = dwarf.attr.Value(attr_spec)
                if attr_value.extract_value(data, self):
                    other_die_offsets.append(attr_value.value)
            else:
                if not attr_spec.get_form().skip(self, data):
                    print('error: failed to skip the attribute %s in die '
                          '0x%8.8x' % (attr_spec, self.offset))
                    return None
        for die_offset in other_die_offsets:
            die = self.get_referenced_die_with_offset(die_offset)
            if die:
                attr_value = die.get_attr_value(attr)
                if attr_value:
                    return attr_value
        return None

    def get_attr_value(self, attr):
        if self.abbrev and self.abbrev.might_have_attribute(attr):
            data = self.cu.data
            # Make sure we don't change the state of the data position by
            # backing it up and restoring it.
            data.push_offset_and_seek(self.offset)
            result = self.__get_attr_value(attr, data)
            data.pop_offset_and_seek()
            return result
        return None

    def get_attr_as_int(self, attr, fail_value=0):
        attr_value = self.get_attr_value(attr)
        if attr_value:
            if type(attr_value.value) is int:
                return attr_value.value
        return fail_value

    def get_attr_as_string(self, attr, fail_value=None):
        attr_value = self.get_attr_value(attr)
        if attr_value:
            if is_string(attr_value.value):
                return attr_value.value
        return fail_value

    def get_attr_as_die(self, attr):
        attr_value = self.get_attr_value(attr)
        if attr_value:
            if type(attr_value.value) is int:
                return self.get_referenced_die_with_offset(attr_value.value)
        return None

    def get_attr_as_file(self, attr):
        file_idx = self.get_attr_as_int(attr, -1)
        if file_idx >= 0:
            return self.cu.get_file(file_idx)
        return None

    def get_file(self, file_idx):
        return self.cu.get_file(file_idx)

    def get_attrs(self, recurse=False):
        '''Get an array of attribute values from the current DIE.

        If "recurse" is True, then follow any DW_AT_abstract_origin or
        DW_AT_specification attribute values and get the attributes from those
        DIEs as well.

        The returned array contains a collection of dwarf.attr.Value() objects.
        '''
        if self.abbrev:
            attr_values = []
            data = self.cu.data
            data.seek(self.offset)
            data.get_uleb128()  # Skip the abbrev code
            recurse_die_offsets = []
            for attr_spec in self.abbrev.attribute_specs:
                attr_value = dwarf.attr.Value(attr_spec)
                if attr_value.extract_value(data, self):
                    attr_values.append(attr_value)
                    if recurse:
                        if attr_value.attr_spec.attr in [DW_AT.abstract_origin,
                                                         DW_AT.specification]:
                            recurse_die_offsets.append(attr_value.value)
                else:
                    raise ValueError('error: failed to extract a value for %s '
                                     'in die 0x%8.8x' % (attr_spec,
                                                         self.offset))
            for die_offset in recurse_die_offsets:
                die = self.get_referenced_die_with_offset(die_offset)
                if die:
                    spec_values = die.get_attrs(recurse=recurse)
                    if spec_values:
                        attr_values.extend(spec_values)
            return attr_values
        return None

    def get_referenced_die_with_offset(self, die_offset):
        if self.cu.contains_offset(die_offset):
            return self.cu.get_die_with_offset(die_offset)
        else:
            return self.cu.debug_info.find_die_with_offset(die_offset)

    def dump_ancestry(self, verbose=False, show_all_attrs=False, f=sys.stdout,
                      offset_adjust=0, max_depth=0, dump_unit_info=False):
        parent = self.get_parent()
        if parent:
            parent.dump_ancestry(verbose=verbose,
                                 show_all_attrs=show_all_attrs,
                                 f=f, offset_adjust=offset_adjust,
                                 dump_unit_info=dump_unit_info)
        else:
            f.write(self.cu.__repr__())
            f.write('\n')
            # f.write(self.cu.debug_info.dwarf.objfile.description(False) + '\n')

        self.dump(max_depth=max_depth,
                  verbose=verbose,
                  show_all_attrs=show_all_attrs,
                  f=f,
                  offset_adjust=offset_adjust)

    def dump(self, max_depth=0, verbose=False, show_all_attrs=False,
             f=sys.stdout, offset_adjust=0, indent_width=4):
        colorizer = dwarf.options.get_colorizer()
        if self.abbrev:
            f.write('%s:  %*s%s [%u]' % (
                    dwarf.options.get_color_offset(self.get_offset()),
                    self.depth * indent_width, '',
                    dwarf.options.get_color_tag(self.abbrev.get_tag()),
                    self.abbrev.code))
            if verbose:
                f.write(colorizer.faint())
                if self.abbrev.has_children:
                    f.write(' DW_CHILDREN_yes')
                else:
                    f.write(' DW_CHILDREN_no')
                f.write(colorizer.reset())
                f.write('\n')
            else:
                f.write('\n')

            attr_values = self.get_attrs(show_all_attrs)
            for attr_value in attr_values:
                attr_value.dump(die=self, verbose=verbose, f=f,
                                offset_adjust=offset_adjust, indent_width=4)
            f.write('\n')

            if max_depth > 0:
                child = self.get_child()
                if child:
                    child.dump(max_depth=max_depth-1,
                               show_all_attrs=show_all_attrs,
                               verbose=verbose, f=f,
                               offset_adjust=offset_adjust)
                    sibling = child.get_sibling()
                    while sibling:
                        sibling.dump(max_depth=max_depth-1, verbose=verbose,
                                     f=f, offset_adjust=offset_adjust)
                        sibling = sibling.get_sibling()
        else:
            f.write('%s0x%8.8x%s:  %*sNULL\n\n' % (colorizer.yellow(),
                    self.get_offset() + offset_adjust, colorizer.reset(),
                    self.depth * indent_width, ''))

    def __str__(self):
        output = io.BytesIO()
        self.dump(max_depth=0, verbose=False, f=output)
        return output.getvalue()

    def has_children(self):
        if self.abbrev and self.abbrev.has_children:
            return True
        return False

    def get_children(self):
        children = []
        die = self.get_child()
        while die:
            children.append(die)
            die = die.get_sibling()
        return children

    def get_child(self):
        if self.abbrev and self.abbrev.has_children:
            return self.cu.dies[self.die_index+1]
        else:
            return None

    def get_sibling(self):
        for i in range(self.die_index+1, len(self.cu.dies)):
            depth = self.cu.dies[i].depth
            if depth > self.depth:
                continue
            if depth == self.depth:
                return self.cu.dies[i]
            if depth < self.depth:
                return None
        return None

    def get_parent(self):
        if self.die_index > 0:
            parent_depth = self.depth - 1
            for i in range(self.die_index-1, -1, -1):
                depth = self.cu.dies[i].depth
                if depth == parent_depth:
                    return self.cu.dies[i]
        return None

    def get_type_name(self):
        tag = self.get_tag()
        if tag.is_type() or int(tag) == DW_TAG.namespace:
            name = self.get_display_name()
            if name is None:
                type_kind = tag.get_type_kind()
                decl_ctx = self.get_decl_context_as_string()
                if decl_ctx:
                    name = decl_ctx + "::" + "(anonymous %s)" % (type_kind)
                else:
                    name = "(anonymous %s)" % (type_kind)
            return name
        return None

    def __repr__(self):
        return '{%#8.8x}' % (self.offset)
