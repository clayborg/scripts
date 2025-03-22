#!/usr/bin/python

# Python imports
from enum import IntEnum
import sys
import io

# Package imports
from dwarf.DW.FORM import DW_FORM
from dwarf.DW.TAG import DW_TAG


class AppleHash:
    def __init__(self, data, debug_str_data):
        self.data = data
        self.magic = 0
        self.version = 0
        self.hash_enum = 0
        self.bucket_count = 0
        self.prologue_length = 0
        self.prologue = Prologue(debug_str_data)
        self.hash_indexes = None
        self.hashes = None
        self.offsets = None

        # Unpack the header
        self.magic = data.get_uint32()
        self.version = data.get_uint16()
        self.hash_enum = data.get_uint16()
        self.bucket_count = data.get_uint32()
        self.hashes_count = data.get_uint32()
        self.prologue_length = data.get_uint32()
        # Unpack the header
        if self.prologue:
            self.prologue.unpack(data)
        # Unpack the hash indexes, hashes and offsets
        self.hash_indexes = []
        self.hashes = []
        self.offsets = []
        for i in range(self.bucket_count):
            self.hash_indexes.append(data.get_uint32())
        for i in range(self.hashes_count):
            self.hashes.append(data.get_uint32())
        for i in range(self.hashes_count):
            self.offsets.append(data.get_uint32())

    def lookup(self, name):
        actual_hash = AppleHash.hash(name)
        bucket_count = self.bucket_count
        bucket_idx = actual_hash % bucket_count
        idx = self.hash_indexes[bucket_idx]
        while 1:
            curr_hash = self.hashes[idx]
            if actual_hash == curr_hash:
                hash_data_offset = self.offsets[idx]
                self.data.seek(hash_data_offset)
                return self.prologue.extract_data(name, self.data)
            if (curr_hash % bucket_count) != bucket_idx:
                break
            idx += 1
        return None

    def get_all_names(self):
        names = []
        for offset in self.offsets:
            self.prologue.get_names_from_hash_data(self.data, offset, names)
        return names

    def dump(self, f=sys.stdout):
        f.write('          magic = 0x%8.8x\n' % (self.magic))
        f.write('        version = 0x%4.4x\n' % (self.version))
        f.write('      hash_enum = 0x%8.8x\n' % (self.hash_enum))
        f.write('   bucket_count = 0x%8.8x (%u)\n' % (self.bucket_count,
                                                      self.bucket_count))
        f.write('   hashes_count = 0x%8.8x (%u)\n' % (self.hashes_count,
                                                      self.hashes_count))
        f.write('prologue_length = 0x%8.8x\n' % (self.prologue_length))
        f.write('prologue:\n')
        self.prologue.dump(f=f)
        for (i, hash_idx) in enumerate(self.hash_indexes):
            if hash_idx == 4294967295:
                f.write(' bucket[%u] = <EMPTY>\n' % (i))
            else:
                f.write(' bucket[%u] = hashes[%u]\n' % (i, hash_idx))
        for (i, offset) in enumerate(self.offsets):
            f.write(' hashes[%u] = 0x%8.8x\n' % (i, self.hashes[i]))
            f.write('offsets[%u] = 0x%8.8x\n' % (i, offset))
            if self.prologue:
                self.prologue.dump_hash_data(data=self.data, offset=offset,
                                             f=f)

    def __str__(self):
        output = io.StringIO()
        self.dump(output)
        return output.getvalue()

    @classmethod
    def hash(cls, s):
        h = 5381
        for c in s:
            h = ((h << 5) + h) + ord(c)
        return h & UINT32_MAX



class DW_ATOM(IntEnum):
    null = 0  # Marker as the end of a list of atoms.
    die_offset = 1       # DIE offset in the debug_info section.
    cu_offset = 2        # Offset of the compile unit header that contains the item in question.
    die_tag = 3          # A DW_TAG dwarf tag entry.
    type_flags = 4       # Set of flags for a type.
    type_type_flags = 5  # Dsymutil type extension.
    qual_name_hash = 6   # Dsymutil qualified hash extension.

    def __str__(self):
        return 'DW_ATOM_' + self.name

class Atom:
    def __init__(self, type, form):
        self.type = DW_ATOM(type)
        self.form = DW_FORM(form)

    def dump(self, index, f=sys.stdout):
        f.write('atom[%u] type = %s, form = %s\n' % (index, self.type, self.form))

    def __str__(self):
        output = io.StringIO()
        self.dump(output)
        return output.getvalue()


class Data:
    def __init__(self):
        self.offset = 0
        self.name = None
        self.die_infos = None

    def unpack(self, name, prologue, data):
        self.offset = data.tell()
        self.name = None
        self.die_infos = None
        while 1:
            strp = data.get_uint32()
            if strp == 0:
                return True
            count = data.get_uint32()
            curr_name = prologue.get_string(strp)
            if name is None:
                name = curr_name
            if curr_name == name:
                self.name = name
                # We have a full match
                self.die_infos = []
                for i in range(count):
                    die_info = DIEInfo()
                    if die_info.unpack(prologue, data):
                        self.die_infos.append(die_info)
                return True
            else:
                # Skip the entry using the prologue
                for i in range(count):
                    prologue.skip(data)
        return False

    def dump(self, f=sys.stdout):
        if self.name is None:
            f.write('0x%8.8x: <NULL>\n' % (self.offset))
        else:
            f.write('0x%8.8x: "%s"\n' % (self.offset, self.name))
        if self.die_infos:
            for die_info in self.die_infos:
                die_info.dump(f=f)

    def __str__(self):
        output = io.StringIO()
        self.dump(output)
        return output.getvalue()


class DIEInfo:
    def __init__(self):
        self.offset = -1
        self.tag = None
        self.type_flags = -1
        self.qualified_name_hash = -1

    def unpack(self, prologue, data):
        if len(prologue.atoms) == 0:
            return False
        for atom in prologue.atoms:
            (value, value_raw) = atom.form.extract_value(data, None)
            atom_enum = atom.type
            if atom_enum == DW_ATOM.die_offset:
                self.offset = prologue.die_base_offset + value
            elif atom_enum == DW_ATOM.die_tag:
                self.tag = DW_TAG(value)
            elif atom_enum == DW_ATOM.type_type_flags:
                self.type_flags = value
            elif atom_enum == DW_ATOM.qual_name_hash:
                self.qualified_name_hash = value
            else:
                raise ValueError
        return True

    def dump(self, f=sys.stdout):
        f.write('    ')
        if self.offset >= 0:
            f.write('{0x%8.8x}' % (self.offset))
        if self.tag is not None:
            f.write(' %s' % (self.tag))
        if self.type_flags >= 0:
            f.write(' type_flags = 0x%8.8x' % (self.type_flags))
        if self.qualified_name_hash >= 0:
            f.write(' qualified_hash = 0x%8.8x' %
                    (self.qualified_name_hash))
        f.write('\n')

    def __str__(self):
        output = io.StringIO()
        self.dump(output)
        return output.getvalue()


class Prologue:
    def __init__(self, string_data):
        self.die_base_offset = 0
        self.string_data = string_data
        self.atoms = []
        self.fixed_size = 0

    def unpack(self, data):
        self.die_base_offset = data.get_uint32()
        atom_count = data.get_uint32()
        self.fixed_size = 0
        for i in range(atom_count):
            atom = data.get_uint16()
            form = data.get_uint16()
            atom = Atom(atom, form)
            if self.fixed_size >= 0:
                form_size = atom.form.get_fixed_size()
                if form_size >= 0:
                    self.fixed_size += form_size
                else:
                    self.fixed_size = -1
            self.atoms.append(atom)

    def extract_data(self, name, data):
        d = Data()
        if d.unpack(name, self, data):
            return d
        else:
            return None

    def skip(self, data):
        if self.fixed_size >= 0:
            data.seek(data.tell() + self.fixed_size)
        else:
            fixed_size = 0
            for atom in self.atoms:
                size = self.form.get_fixed_size()
                if size == -1:
                    print('error: not a fixed size')
                    raise ValueError
                fixed_size += size
            data.seek(data.tell() + fixed_size)

    def get_names_from_hash_data(self, data, offset, names):
        data.seek(offset)
        while 1:
            hash_data = self.extract_data(None, data)
            if hash_data.name is None:
                break
            names.append(hash_data.name)

    def dump_hash_data(self, data, offset, f=sys.stdout):
        data.seek(offset)
        while 1:
            hash_data = self.extract_data(None, data)
            hash_data.dump(f=f)
            if hash_data.name is None:
                break

    def dump(self, f=sys.stdout):
        f.write('prologue.die_base_offset = 0x%8.8x\n' % (
            self.die_base_offset))
        for (i, atom) in enumerate(self.atoms):
            atom.dump(index=i, f=f)

    def __str__(self):
        output = io.StringIO()
        self.dump(output)
        return output.getvalue()

    def get_string(self, strp):
        self.string_data.seek(strp)
        return self.string_data.get_c_string()
