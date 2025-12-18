#!/usr/bin/env python3

import binascii
import cmd
from collections import defaultdict
import copy
import dict_utils
import dwarf.context
import dwarf.options
from dwarf.ranges import AddressRange, AddressRangeList
from enum import IntEnum
import file_extract
import filecmp
import io
import optparse
import os
import re
import shlex
import struct
import string
import sys
import term_colors
import uuid
# import Tkinter
# from Tkinter import *
# from ttk import *

UINT32_MAX = 4294967295

# Mach header "magic" constants
MH_MAGIC = 0xfeedface
MH_CIGAM = 0xcefaedfe
MH_MAGIC_64 = 0xfeedfacf
MH_CIGAM_64 = 0xcffaedfe
FAT_MAGIC = 0xcafebabe
FAT_CIGAM = 0xbebafeca
FAT_MAGIC_64 = 0xcafebabf
FAT_CIGAM_64 = 0xbfbafeca

# Mach haeder "filetype" constants
MH_OBJECT = 0x00000001
MH_EXECUTE = 0x00000002
MH_FVMLIB = 0x00000003
MH_CORE = 0x00000004
MH_PRELOAD = 0x00000005
MH_DYLIB = 0x00000006
MH_DYLINKER = 0x00000007
MH_BUNDLE = 0x00000008
MH_DYLIB_STUB = 0x00000009
MH_DSYM = 0x0000000a
MH_KEXT_BUNDLE = 0x0000000b

# Mach haeder "flag" constant bits
MH_NOUNDEFS = 0x00000001
MH_INCRLINK = 0x00000002
MH_DYLDLINK = 0x00000004
MH_BINDATLOAD = 0x00000008
MH_PREBOUND = 0x00000010
MH_SPLIT_SEGS = 0x00000020
MH_LAZY_INIT = 0x00000040
MH_TWOLEVEL = 0x00000080
MH_FORCE_FLAT = 0x00000100
MH_NOMULTIDEFS = 0x00000200
MH_NOFIXPREBINDING = 0x00000400
MH_PREBINDABLE = 0x00000800
MH_ALLMODSBOUND = 0x00001000
MH_SUBSECTIONS_VIA_SYMBOLS = 0x00002000
MH_CANONICAL = 0x00004000
MH_WEAK_DEFINES = 0x00008000
MH_BINDS_TO_WEAK = 0x00010000
MH_ALLOW_STACK_EXECUTION = 0x00020000
MH_ROOT_SAFE = 0x00040000
MH_SETUID_SAFE = 0x00080000
MH_NO_REEXPORTED_DYLIBS = 0x00100000
MH_PIE = 0x00200000
MH_DEAD_STRIPPABLE_DYLIB = 0x00400000
MH_HAS_TLV_DESCRIPTORS = 0x00800000
MH_NO_HEAP_EXECUTION = 0x01000000

# Mach load command constants
LC_REQ_DYLD = 0x80000000
LC_SEGMENT = 0x00000001
LC_SYMTAB = 0x00000002
LC_SYMSEG = 0x00000003
LC_THREAD = 0x00000004
LC_UNIXTHREAD = 0x00000005
LC_LOADFVMLIB = 0x00000006
LC_IDFVMLIB = 0x00000007
LC_IDENT = 0x00000008
LC_FVMFILE = 0x00000009
LC_PREPAGE = 0x0000000a
LC_DYSYMTAB = 0x0000000b
LC_LOAD_DYLIB = 0x0000000c
LC_ID_DYLIB = 0x0000000d
LC_LOAD_DYLINKER = 0x0000000e
LC_ID_DYLINKER = 0x0000000f
LC_PREBOUND_DYLIB = 0x00000010
LC_ROUTINES = 0x00000011
LC_SUB_FRAMEWORK = 0x00000012
LC_SUB_UMBRELLA = 0x00000013
LC_SUB_CLIENT = 0x00000014
LC_SUB_LIBRARY = 0x00000015
LC_TWOLEVEL_HINTS = 0x00000016
LC_PREBIND_CKSUM = 0x00000017
LC_LOAD_WEAK_DYLIB = 0x00000018 | LC_REQ_DYLD
LC_SEGMENT_64 = 0x00000019
LC_ROUTINES_64 = 0x0000001a
LC_UUID = 0x0000001b
LC_RPATH = 0x0000001c | LC_REQ_DYLD
LC_CODE_SIGNATURE = 0x0000001d
LC_SEGMENT_SPLIT_INFO = 0x0000001e
LC_REEXPORT_DYLIB = 0x0000001f | LC_REQ_DYLD
LC_LAZY_LOAD_DYLIB = 0x00000020
LC_ENCRYPTION_INFO = 0x00000021
LC_DYLD_INFO = 0x00000022
LC_DYLD_INFO_ONLY = 0x00000022 | LC_REQ_DYLD
LC_LOAD_UPWARD_DYLIB = 0x00000023 | LC_REQ_DYLD
LC_VERSION_MIN_MACOSX = 0x00000024
LC_VERSION_MIN_IPHONEOS = 0x00000025
LC_FUNCTION_STARTS = 0x00000026
LC_DYLD_ENVIRONMENT = 0x00000027
LC_MAIN = 0x00000028 | LC_REQ_DYLD
LC_DATA_IN_CODE = 0x00000029
LC_SOURCE_VERSION = 0x0000002A
LC_DYLIB_CODE_SIGN_DRS = 0x0000002B
LC_ENCRYPTION_INFO_64 = 0x0000002C
LC_LINKER_OPTION = 0x0000002D
LC_LINKER_OPTIMIZATION_HINT = 0x0000002E
LC_VERSION_MIN_TVOS = 0x0000002F
LC_VERSION_MIN_WATCHOS = 0x00000030
LC_NOTE = 0x31
LC_BUILD_VERSION = 0x32
LC_DYLD_EXPORTS_TRIE = (0x33 | LC_REQ_DYLD)
LC_DYLD_CHAINED_FIXUPS = (0x34 | LC_REQ_DYLD)

# Segment flags
SG_HIGHVM = 0x00000001
SG_FVMLIB = 0x00000002
SG_NORELOC = 0x00000004
SG_PROTECTED_VERSION_1 = 0x00000008

# Section flags
SECTION_TYPE = 0x000000ff
SECTION_ATTRIBUTES = 0xffffff00

# Section type constants
S_REGULAR = 0x0
S_ZEROFILL = 0x1
S_CSTRING_LITERALS = 0x2
S_4BYTE_LITERALS = 0x3
S_8BYTE_LITERALS = 0x4
S_LITERAL_POINTERS = 0x5
S_NON_LAZY_SYMBOL_POINTERS = 0x6
S_LAZY_SYMBOL_POINTERS = 0x7
S_SYMBOL_STUBS = 0x8
S_MOD_INIT_FUNC_POINTERS = 0x9
S_MOD_TERM_FUNC_POINTERS = 0xa
S_COALESCED = 0xb
S_GB_ZEROFILL = 0xc
S_INTERPOSING = 0xd
S_16BYTE_LITERALS = 0xe
S_DTRACE_DOF = 0xf
S_LAZY_DYLIB_SYMBOL_POINTERS = 0x10
S_THREAD_LOCAL_REGULAR = 0x11
S_THREAD_LOCAL_ZEROFILL = 0x12
S_THREAD_LOCAL_VARIABLES = 0x13
S_THREAD_LOCAL_VARIABLE_POINTERS = 0x14
S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15

# Section attribute constants
SECTION_ATTRIBUTES_USR = 0xff000000
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_NO_TOC = 0x40000000
S_ATTR_STRIP_STATIC_SYMS = 0x20000000
S_ATTR_NO_DEAD_STRIP = 0x10000000
S_ATTR_LIVE_SUPPORT = 0x08000000
S_ATTR_SELF_MODIFYING_CODE = 0x04000000
S_ATTR_DEBUG = 0x02000000
SECTION_ATTRIBUTES_SYS = 0x00ffff00
S_ATTR_SOME_INSTRUCTIONS = 0x00000400
S_ATTR_EXT_RELOC = 0x00000200
S_ATTR_LOC_RELOC = 0x00000100

# Mach CPU constants
CPU_ARCH_MASK = 0xff000000
CPU_ARCH_ABI64 = 0x01000000
CPU_TYPE_ANY = 0xffffffff
CPU_TYPE_VAX = 1
CPU_TYPE_MC680x0 = 6
CPU_TYPE_I386 = 7
CPU_TYPE_X86_64 = CPU_TYPE_I386 | CPU_ARCH_ABI64
CPU_TYPE_MIPS = 8
CPU_TYPE_MC98000 = 10
CPU_TYPE_HPPA = 11
CPU_TYPE_ARM = 12
CPU_TYPE_MC88000 = 13
CPU_TYPE_SPARC = 14
CPU_TYPE_I860 = 15
CPU_TYPE_ALPHA = 16
CPU_TYPE_POWERPC = 18
CPU_TYPE_POWERPC64 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64
CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_ARCH_ABI64

# VM protection constants
VM_PROT_READ = 1
VM_PROT_WRITE = 2
VM_PROT_EXECUTE = 4

# VM protection constants
N_STAB = 0xe0
N_PEXT = 0x10
N_TYPE = 0x0e
N_EXT = 0x01

# Values for nlist N_TYPE bits of the "Mach.NList.type" field.
N_UNDF = 0x0
N_ABS = 0x2
N_SECT = 0xe
N_PBUD = 0xc
N_INDR = 0xa

# Section indexes for the "Mach.NList.sect_idx" fields
NO_SECT = 0
MAX_SECT = 255


# Stab defines
class Stab(IntEnum):
    N_GSYM = 0x20
    N_FNAME = 0x22
    N_FUN = 0x24
    N_STSYM = 0x26
    N_LCSYM = 0x28
    N_BNSYM = 0x2e
    N_OPT = 0x3c
    N_RSYM = 0x40
    N_SLINE = 0x44
    N_ENSYM = 0x4e
    N_SSYM = 0x60
    N_SO = 0x64
    N_OSO = 0x66
    N_LSYM = 0x80
    N_BINCL = 0x82
    N_SOL = 0x84
    N_PARAMS = 0x86
    N_VERSION = 0x88
    N_OLEVEL = 0x8A
    N_PSYM = 0xa0
    N_EINCL = 0xa2
    N_ENTRY = 0xa4
    N_LBRAC = 0xc0
    N_EXCL = 0xc2
    N_RBRAC = 0xe0
    N_BCOMM = 0xe2
    N_ECOMM = 0xe4
    N_ECOML = 0xe8
    N_LENG = 0xfe

    def __str__(self):
        return self.name


# Platform definitions for LC_BUILD_VERSION
PLATFORM_INVALID = 0
PLATFORM_MACOS = 1
PLATFORM_IOS = 2
PLATFORM_TVOS = 3
PLATFORM_WATCHOS = 4
PLATFORM_BRIDGEOS = 5
PLATFORM_MACCATALYST = 6
PLATFORM_IOSSIMULATOR = 7
PLATFORM_TVOSSIMULATOR = 8
PLATFORM_WATCHOSSIMULATOR = 9
PLATFORM_DRIVERKIT = 10

# Tool definitions for LC_BUILD_VERSION
TOOL_CLANG = 1
TOOL_SWIFT = 2
TOOL_LD	= 3


vm_prot_names = ['---', 'r--', '-w-', 'rw-', '--x', 'r-x', '-wx', 'rwx']


def get_version32_as_string(v):
    return "%u.%u.%u" % (v >> 16, (v >> 8) & 0xff, v & 0xff)


def int_to_hex16(i):
    return '0x%4.4x' % (i)


def int_to_hex32(i):
    return '0x%8.8x' % (i)


def int_to_hex64(i):
    return '0x%16.16x' % (i)


def address_to_str(addr, is_64):
    if is_64:
        return int_to_hex64(addr)
    else:
        return int_to_hex32(addr)


def address_range_to_str(i, j, is_64):
    if is_64:
        return '[%s - %s)' % (int_to_hex64(i), int_to_hex64(j))
    else:
        return '[%s - %s)' % (int_to_hex32(i), int_to_hex32(j))


def sizeof_fmt(num):
    for unit in ['B', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(num) < 1024.0:
            return "%3.1f%s" % (num, unit)
        num /= 1024.0
    return "%.1f%s" % (num, 'Y')


def swap_unpack_char():
    """Returns the unpack prefix that will for non-native endian-ness."""
    if struct.pack('H', 1).startswith("\x00"):
        return '<'
    return '>'


def dump_hex_bytes(addr, s, bytes_per_line=16):
    i = 0
    line = ''
    for ch in s:
        if (i % bytes_per_line) == 0:
            if line:
                print(line)
            line = '%#8.8x: ' % (addr + i)
        line += "%02X " % ord(ch)
        i += 1
    print(line)


def dump_hex_byte_string_diff(addr, a, b, bytes_per_line=16):
    i = 0
    line = ''
    a_len = len(a)
    b_len = len(b)
    if a_len < b_len:
        max_len = b_len
    else:
        max_len = a_len
    tty_colors = term_colors.TerminalColors(True)
    for i in range(max_len):
        ch = None
        if i < a_len:
            ch_a = a[i]
            ch = ch_a
        else:
            ch_a = None
        if i < b_len:
            ch_b = b[i]
            if not ch:
                ch = ch_b
        else:
            ch_b = None
        mismatch = ch_a != ch_b
        if (i % bytes_per_line) == 0:
            if line:
                print(line)
            line = '%#8.8x: ' % (addr + i)
        if mismatch:
            line += tty_colors.red()
        line += "%02X " % ord(ch)
        if mismatch:
            line += tty_colors.default()
        i += 1
    print(line)


def get_mach_files_in_directory(path, options, mach_files, depth=0):
    for dirpath, dirs, files in os.walk(path):
        for file in files:
            fullpath = os.path.join(dirpath, file)
            if options.verbose:
                print('parsing: %s' % (fullpath))
            mach = Mach.load(fullpath)
            if mach:
                mach_files.append(mach)
            elif options.verbose:
                print('not a mach file')


def compare_size_in_directories(a_dir, b_dir):
    a_dir = os.path.normpath(a_dir)
    b_dir = os.path.normpath(b_dir)
    a_machs = []
    b_machs = []
    get_mach_files_in_directory(a_dir, options, a_machs)
    get_mach_files_in_directory(b_dir, options, b_machs)
    handled_files = {}
    for (i, a_mach) in enumerate(a_machs):
        a_relative_path = a_mach.path[len(a_dir)+1:]
        b_mach = None
        if i < len(b_machs) and b_machs[i].path.endswith(a_relative_path):
            b_mach = b_machs[i]
        else:
            for mach in b_machs:
                if mach.path.endswith(a_relative_path):
                    b_mach = mach
                    break
        handled_files[a_relative_path] = True
        if b_mach:
            if filecmp.cmp(a_mach.path, b_mach.path):
                print('"%s" files are the same' % (a_relative_path))
            else:
                a_mach.compare_size(b_mach)
        else:
            print('error: "%s" missing from "%s"' % (a_relative_path, b_dir))
    for mach in b_machs:
        b_relative_path = mach.path[len(b_dir)+1:]
        if b_relative_path in handled_files:
            continue
        else:
            print('error: "%s" missing from "%s"' % (b_relative_path, a_dir))


class OutputHelper:
    def __init__(self, depth=0, file=sys.stdout):
        self.depth = depth
        self.file = file

    def indent_more(self):
        self.depth += 2

    def indent_less(self):
        self.depth -= 2
        if self.depth < 0:
            self.depth = 0

    def indent(self, s=None, newline=True):
        if self.depth:
            self.file.write(' ' * self.depth)
        if s:
            self.file.write(s)
        if newline:
            self.file.write('\n')


class method_t:
    def __init__(self, objc_class, data):
        self.objc_class = objc_class
        self.offset = data.tell()
        self.SEL = data.get_address()
        self.types = data.get_address()
        self.imp = data.get_address()
        self.SEL_str = None
        self.types_str = None

    def get_selector(self):
        if self.SEL_str is None:
            self.SEL_str = self.objc_class.mach.read_c_string_from_addr(
                self.SEL)
        return self.SEL_str

    def get_types(self):
        if self.types_str is None:
            self.types_str = self.objc_class.mach.read_c_string_from_addr(
                self.types)
        return self.types_str

    def dump(self, out, verbose=False):
        if verbose:
            out.indent("method_t @ %#x:" % (self.offset))
            out.indent_more()
            out.indent("SEL: %#x (%s)" % (self.SEL, self.get_selector()))
            out.indent("types: %#x" % (self.types))
            out.indent("imp: %#x" % (self.imp))
            out.indent_less()
        else:
            out.indent("%#16.16x: %s %s" % (self.imp, self.get_selector(),
                                            self.get_types()))


class method_list_t:
    '''Reads a method_list_t type from the mach file at address'''
    def __init__(self, objc_class, addr, name):
        self.objc_class = objc_class
        self.name = name
        data = objc_class.mach.seek_to_addr(addr)
        self.offset = data.tell()
        self.entsize_NEVER_USE = data.get_uint32()
        self.count = data.get_uint32()
        self.methods = []
        for i in range(self.count):
            self.methods.append(method_t(self.objc_class, data))

    def dump(self, out, verbose=False):
        out.indent("%s:" % (self.name))
        out.indent_more()
        for method in self.methods:
            method.dump(out, verbose)
        out.indent_less()


class property_t:
    def __init__(self, objc_class, data):
        self.objc_class = objc_class
        self.name_ptr = data.get_address()
        self.attributes_ptr = data.get_address()
        self.name = None
        self.attributes = None

    def get_name(self):
        if self.name is None:
            self.name = self.objc_class.mach.read_c_string_from_addr(
                self.name_ptr)
        return self.name

    def get_attributes(self):
        if self.attributes is None:
            self.attributes = self.objc_class.mach.read_c_string_from_addr(
                self.attributes_ptr)
        return self.attributes

    def dump(self, out, verbose=False):
        out.indent("%s %s" % (self.get_name(), self.get_attributes()))


class property_list_t:
    '''Reads a property_list_t type from the mach file at address'''
    def __init__(self, objc_class, addr, name):
        self.objc_class = objc_class
        self.name = name
        data = objc_class.mach.seek_to_addr(addr)
        self.offset = data.tell()
        self.entsize = data.get_uint32()
        self.count = data.get_uint32()
        self.properties = []
        for i in range(self.count):
            self.properties.append(property_t(self.objc_class, data))

    def dump(self, out, verbose=False):
        out.indent("%s:" % (self.name))
        out.indent_more()
        for property in self.properties:
            property.dump(out, verbose)
        out.indent_less()


class ivar_t:
    def __init__(self, objc_class, data):
        self.objc_class = objc_class
        self.offset_ptr = data.get_address()
        self.name_ptr = data.get_address()
        self.type_ptr = data.get_address()
        self.alignment = data.get_uint32()
        self.size = data.get_uint32()
        self.name = None
        self.type = None
        self.offset = None

    def get_offset(self):
        if self.offset is None:
            self.offset = self.objc_class.mach.seek_to_addr(
                self.offset_ptr).get_address()
        return self.offset

    def get_name(self):
        if self.name is None:
            self.name = self.objc_class.mach.read_c_string_from_addr(
                self.name_ptr)
        return self.name

    def get_type(self):
        if self.type is None:
            self.type = self.objc_class.mach.read_c_string_from_addr(
                self.type_ptr)
        return self.type

    def dump(self, out, verbose=False):
        out.indent("%s: offset=%i, type=%s, align=%i, size=%i" % (
            self.get_name(), self.get_offset(), self.get_type(),
            self.alignment, self.size))


class ivar_list_t:
    '''Reads a ivar_list_t type from the mach file at address'''
    def __init__(self, objc_class, addr, name):
        self.objc_class = objc_class
        self.name = name
        data = objc_class.mach.seek_to_addr(addr)
        self.offset = data.tell()
        self.entsize = data.get_uint32()
        self.count = data.get_uint32()
        self.ivars = []
        for i in range(self.count):
            self.ivars.append(ivar_t(self.objc_class, data))

    def dump(self, out, verbose=False):
        out.indent("%s:" % (self.name))
        out.indent_more()
        for ivar in self.ivars:
            ivar.dump(out, verbose)
        out.indent_less()


class protocol_t:
    def __init__(self, objc_class, addr):
        data = objc_class.mach.seek_to_addr(addr)
        self.objc_class = objc_class
        self.offset = data.tell()
        self.isa = data.get_address()
        self.name_ptr = data.get_address()
        self.protocols_ptr = data.get_address()
        self.instanceMethods_ptr = data.get_address()
        self.classMethods_ptr = data.get_address()
        self.optionalInstanceMethods_ptr = data.get_address()
        self.optionalClassMethods_ptr = data.get_address()
        self.instanceProperties_ptr = data.get_address()
        self.size = data.get_uint32()  # sizeof(protocol_t)
        self.flags = data.get_uint32()
        self.extendedMethodTypes = data.get_address()
        self.name = None
        self.protocols = None
        self.instanceMethods = None
        self.classMethods = None
        self.optionalInstanceMethods = None
        self.optionalClassMethods = None
        self.instanceProperties = None

    def get_protocols(self):
        if self.protocols is None and self.protocols_ptr != 0:
            self.protocols = protocol_list_t(self.objc_class,
                                             self.protocols_ptr,
                                             "protocols")
        return self.protocols

    def get_instanceMethods(self):
        if self.instanceMethods is None and self.instanceMethods_ptr != 0:
            self.instanceMethods = method_list_t(self.objc_class,
                                                 self.instanceMethods_ptr,
                                                 "instanceMethods")
        return self.instanceMethods

    def get_classMethods(self):
        if self.classMethods is None and self.classMethods_ptr != 0:
            self.classMethods = method_list_t(self.objc_class,
                                              self.classMethods_ptr,
                                              "classMethods")
        return self.classMethods

    def get_optionalInstanceMethods(self):
        if (self.optionalInstanceMethods is None and
                self.optionalInstanceMethods_ptr != 0):
            self.optionalInstanceMethods = method_list_t(
                self.objc_class, self.optionalInstanceMethods_ptr,
                "optionalInstanceMethods")
        return self.optionalInstanceMethods

    def get_optionalClassMethods(self):
        if (self.optionalClassMethods is None and
                self.optionalClassMethods_ptr != 0):
            self.optionalClassMethods = method_list_t(
                self.objc_class, self.optionalClassMethods_ptr,
                "optionalClassMethods")
        return self.optionalClassMethods

    def get_instanceProperties(self):
        if (self.instanceProperties is None and
                self.instanceProperties_ptr != 0):
            self.instanceProperties = property_list_t(
                self.objc_class, self.instanceProperties_ptr,
                "instanceProperties")
        return self.instanceProperties

    def get_name(self):
        if self.name is None:
            self.name = self.objc_class.mach.read_c_string_from_addr(
                self.name_ptr)
        return self.name

    def dump(self, out, verbose=False, brief=False):
        if verbose:
            out.indent("protocol_t @ %#x:" % (self.offset))
            out.indent("isa: %#x" % (self.isa))
            out.indent("name: %#x (%s)" % (self.name_ptr, self.get_name()))
            out.indent("protocols: %#x" % (self.protocols_ptr))
            out.indent("instanceMethods: %#x" % (self.instanceMethods_ptr))
            out.indent("classMethods: %#x" % (self.classMethods_ptr))
            out.indent("optionalInstanceMethods: %#x" % (
                self.optionalInstanceMethods_ptr))
            out.indent("optionalClassMethods: %#x" % (
                self.optionalClassMethods_ptr))
            out.indent("instanceProperties: %#x" % (
                self.instanceProperties_ptr))
            out.indent("size: %#x" % (self.size))
            out.indent("flags: %#x" % (self.flags))
            out.indent("extendedMethodTypes: %#x" % (self.extendedMethodTypes))
        else:
            out.indent("@protocol %s" % (self.get_name()))
            if brief:
                return
        out.indent_more()
        protocols = self.get_protocols()
        if protocols:
            protocols.dump(out, verbose, True)
        methods = self.get_instanceMethods()
        if methods:
            methods.dump(out, verbose)
        methods = self.get_classMethods()
        if methods:
            methods.dump(out, verbose)
        methods = self.get_optionalInstanceMethods()
        if methods:
            methods.dump(out, verbose)
        methods = self.get_optionalClassMethods()
        if methods:
            methods.dump(out, verbose)
        properties = self.get_instanceProperties()
        if properties:
            properties.dump(out, verbose)
        out.indent_less()


class protocol_list_t:
    '''Reads a protocol_list_t type from the mach file at address'''
    def __init__(self, objc_class, addr, name):
        self.objc_class = objc_class
        self.name = name
        data = objc_class.mach.seek_to_addr(addr)
        self.offset = data.tell()
        self.count = data.get_address()
        self.protocol_refs = []
        for i in range(self.count):
            self.protocol_refs.append(data.get_address())
        self.protocols = None

    def get_protocols(self):
        if self.protocols is None:
            self.protocols = []
            for protocol_ref in self.protocol_refs:
                self.protocols.append(protocol_t(self.objc_class,
                                                 protocol_ref))
        return self.protocols

    def dump(self, out, verbose=False, brief=False):
        out.indent("%s:" % (self.name))
        out.indent_more()
        for protocol in self.get_protocols():
            protocol.dump(out, verbose, brief)
        out.indent_less()


class class_ro_t:
    '''Reads a class_ro_t type from the mach file'''
    def __init__(self, objc_class, addr):
        self.objc_class = objc_class
        data = objc_class.mach.seek_to_addr(addr)
        self.offset = data.tell()
        self.flags = data.get_uint32()
        self.instanceStart = data.get_uint32()
        self.instanceSize = data.get_uint32()
        if data.get_addr_size() == 8:
            data.get_uint32()
        self.ivarLayout = data.get_address()
        self.name_ptr = data.get_address()
        self.baseMethods_ptr = data.get_address()
        self.baseProtocols_ptr = data.get_address()
        self.ivars_ptr = data.get_address()
        self.weakIvarLayout = data.get_address()
        self.baseProperties_ptr = data.get_address()
        data = objc_class.mach.seek_to_addr(self.name_ptr)
        self.name = data.get_c_string()
        self.baseMethods = None
        self.baseProtocols = None
        self.ivars = None
        self.baseProperties = None

    def get_class_name(self):
        return self.name

    def get_ivars(self):
        if self.ivars is None and self.ivars_ptr != 0:
            self.ivars = ivar_list_t(self.objc_class, self.ivars_ptr, "ivars")
        return self.ivars

    def get_baseMethods(self):
        if self.baseMethods is None and self.baseMethods_ptr != 0:
            self.baseMethods = method_list_t(self.objc_class,
                                             self.baseMethods_ptr,
                                             "baseMethods")
        return self.baseMethods

    def get_baseProtocols(self):
        if self.baseProtocols is None and self.baseProtocols_ptr != 0:
            self.baseProtocols = protocol_list_t(self.objc_class,
                                                 self.baseProtocols_ptr,
                                                 "baseProtocols")
        return self.baseProtocols

    def get_baseProperties(self):
        if self.baseProperties is None and self.baseProperties_ptr != 0:
            self.baseProperties = property_list_t(self.objc_class,
                                                  self.baseProperties_ptr,
                                                  "baseProperties")
        return self.baseProperties

    def gather_stats(self, objc_stats):
        method_list = self.get_baseMethods()
        if method_list:
            objc_stats.num_methods += method_list.count
        protocols = self.get_baseProtocols()
        if protocols:
            objc_stats.num_protocols += protocols.count
        ivars = self.get_ivars()
        if ivars:
            objc_stats.num_ivars += ivars.count
        properties = self.get_baseProperties()
        if properties:
            objc_stats.num_properties += properties.count

    def dump(self, out, verbose=False):
        if verbose:
            out.indent("class_ro_t @ %#x:" % (self.offset))
            out.indent("  flags: %#x" % (self.flags))
            out.indent("  instanceStart: %#x" % (self.instanceStart))
            out.indent("  instanceSize: %#x" % (self.instanceSize))
            out.indent("  ivarLayout: %#x" % (self.ivarLayout))
            out.indent("  name: %#x (%s)" % (self.name_ptr, self.name))
            out.indent("  baseMethods: %#x" % (self.baseMethods_ptr))
            out.indent("  baseProtocols: %#x" % (self.baseProtocols_ptr))
            out.indent("  ivars: %#x" % (self.ivars_ptr))
            out.indent("  weakIvarLayout: %#x" % (self.weakIvarLayout))
            out.indent("  baseProperties: %#x" % (self.baseProperties_ptr))
        method_list = self.get_baseMethods()
        if method_list:
            method_list.dump(out, verbose)
        protocols = self.get_baseProtocols()
        if protocols:
            protocols.dump(out, verbose)
        ivars = self.get_ivars()
        if ivars:
            ivars.dump(out, verbose)
        properties = self.get_baseProperties()
        if properties:
            properties.dump(out, verbose)


class class_t:
    def __init__(self, isa, mach):
        self.isa = isa
        self.mach = mach
        data = mach.seek_to_addr(isa)
        self.super_isa = data.get_address()
        self.cache = data.get_address()
        self.vtable = data.get_address()
        self.class_rw = data.get_address()
        self.class_ro = data.get_address()
        self.objc_class_ro = None

    def dump(self, out, verbose=False):
        out.indent()
        if verbose:
            out.indent("     isa: %#x" % (self.isa))
            out.indent("   super: %#x" % (self.super_isa))
            out.indent("   cache: %#x" % (self.cache))
            out.indent("  vtable: %#x" % (self.vtable))
            out.indent("class_rw: %#x" % (self.class_rw))
            out.indent("class_ro: %#x" % (self.class_ro))
        else:
            out.indent("@class %s isa=%#x" % (self.get_name(), self.isa))
        out.indent_more()
        class_ro = self.get_class_ro()
        class_ro.dump(out, verbose)
        out.indent_less()

    def gather_stats(self, objc_stats):
        objc_stats.num_classes += 1
        self.get_class_ro().gather_stats(objc_stats)

    def get_name(self):
        return self.get_class_ro().get_class_name()

    def get_class_ro(self):
        if self.objc_class_ro is not None:
            return self.objc_class_ro
        self.objc_class_ro = class_ro_t(self, self.class_ro)
        return self.objc_class_ro


class ObjcStats:
    def __init__(self):
        self.num_classes = 0
        self.num_methods = 0
        self.num_protocols = 0
        self.num_properties = 0
        self.num_ivars = 0

    def aggregate(self, objc_stats):
        self.num_classes += objc_stats.num_classes
        self.num_methods += objc_stats.num_methods
        self.num_protocols += objc_stats.num_protocols
        self.num_properties += objc_stats.num_properties
        self.num_ivars += objc_stats.num_ivars

    def dump(self):
        print('   Classes: %i' % (self.num_classes))
        print('   Methods: %i' % (self.num_methods))
        print(' Protocols: %i' % (self.num_protocols))
        print('Properties: %i' % (self.num_properties))
        print('     IVars: %i' % (self.num_ivars))


UNWIND_IS_NOT_FUNCTION_START = 0x80000000
UNWIND_HAS_LSDA = 0x40000000
UNWIND_PERSONALITY_MASK = 0x30000000
UNWIND_SECOND_LEVEL_REGULAR = 2
UNWIND_SECOND_LEVEL_COMPRESSED = 3


def UNWIND_INFO_COMPRESSED_ENTRY_FUNC_OFFSET(entry):
    return entry & 0x00FFFFFF


def UNWIND_INFO_COMPRESSED_ENTRY_ENCODING_INDEX(entry):
    return ((entry >> 24) & 0xFF)


class unwind_info_regular_second_level_entry:
    '''
        struct unwind_info_regular_second_level_entry {
            uint32_t functionOffset;
            uint32_t encoding;
        };
    '''
    def __init__(self, data):
        self.functionOffset = data.get_uint32()
        self.encoding = data.get_uint32()
        self.in_common = False

    @classmethod
    def dump_header(self, f):
        f.write('INDEX FUNC OFF   ENCODING   COMMON\n')
        f.write('===== ---------- ---------- ======\n')

    def dump(self, f, i):
        f.write('%5u %#8.8x %#8.8x %s\n' % (i, self.functionOffset, self.encoding, self.in_common))


class unwind_info_regular_second_level_page_header:
    '''
        struct unwind_info_regular_second_level_page_header {
            uint32_t kind;    // UNWIND_SECOND_LEVEL_REGULAR
            uint16_t entryPageOffset;
            uint16_t entryCount;
            // entry array
        };

    '''
    def __init__(self, data, common_encodings):
        # We assume "kind" has already been decoded as is 2
        self.entryPageOffset = data.get_uint16()
        self.entryCount = data.get_uint16()
        self.entries = []
        self.uncommon_encodings = 0
        for _i in range(self.entryCount):
            entry = unwind_info_regular_second_level_entry(data)
            entry.in_common = entry.encoding in common_encodings
            if not entry.in_common:
                self.uncommon_encodings += 1
            self.entries.append(entry)

    def dump(self, f):
        f.write('unwind_info_regular_second_level_page_header:\n')
        f.write('  kind = 0x00000002 (UNWIND_SECOND_LEVEL_REGULAR)\n')
        f.write('  entryPageOffset = %#4.4x\n' % (self.entryPageOffset))
        f.write('  entryCount = %#4.4x\n' % (self.entryCount))
        f.write('  uncommon_encodings = %u\n' % (self.uncommon_encodings))
        if self.uncommon_encodings == 0:
            f.write('  warning: this could have been encoded as '
                    'UNWIND_SECOND_LEVEL_COMPRESSED\n')

        unwind_info_regular_second_level_entry.dump_header(f)
        for (i, entry) in enumerate(self.entries):
            entry.dump(f, i)

    def get_address_and_encodings(self, base_addr):
        addr_and_encodings = []
        for entry in self.entries:
            addr_and_encodings.append((base_addr + entry.functionOffset,
                                       entry.encoding))
        return addr_and_encodings


class unwind_info_compressed_second_level_page_header:
    '''
        struct unwind_info_compressed_second_level_page_header {
            uint32_t    kind;    // UNWIND_SECOND_LEVEL_COMPRESSED
            uint16_t    entryPageOffset;
            uint16_t    entryCount;
            uint16_t    encodingsPageOffset;
            uint16_t    encodingsCount;
            // 32-bit entry array
            // encodings array
        };
    '''
    def __init__(self, data, common_encodings):
        # We assume "kind" has already been decoded as is 3
        offset = data.tell()
        self.entryPageOffset = data.get_uint16()
        self.entryCount = data.get_uint16()
        self.encodingsPageOffset = data.get_uint16()
        self.encodingsCount = data.get_uint16()
        self.entries = []
        self.encodings = copy.copy(common_encodings)
        # Decode the entries
        data.push_offset_and_seek(offset - 4 + self.entryPageOffset)
        for i in range(self.entryCount):
            self.entries.append(data.get_uint32())
        data.pop_offset_and_seek()
        data.push_offset_and_seek(offset - 4 + self.encodingsPageOffset)
        for i in range(self.encodingsCount):
            self.encodings.append(data.get_uint32())
        data.pop_offset_and_seek()

    def dump(self, f):
        f.write('unwind_info_compressed_second_level_page_header:\n')
        f.write('  kind = 0x00000003 (UNWIND_SECOND_LEVEL_COMPRESSED)\n')
        f.write('  entryPageOffset = %#4.4x\n' % (self.entryPageOffset))
        f.write('  entryCount = %#4.4x\n' % (self.entryCount))
        f.write('  encodingsPageOffset = %#4.4x\n' % (
                self.encodingsPageOffset))
        f.write('  encodingsCount = %#4.4x\n' % (self.encodingsCount))
        for (i, entry) in enumerate(self.entries):
            func_offset = UNWIND_INFO_COMPRESSED_ENTRY_FUNC_OFFSET(entry)
            enc_idx = UNWIND_INFO_COMPRESSED_ENTRY_ENCODING_INDEX(entry)
            f.write('  entry[%u]: %#2.2x %#6.6x\n' % (i, enc_idx, func_offset))

    def get_function_starts(self, base_addr):
        func_starts = []
        for (i, entry) in enumerate(self.entries):
            func_offset = UNWIND_INFO_COMPRESSED_ENTRY_FUNC_OFFSET(entry)
            func_starts.append(base_addr + func_offset)
        return func_starts

    def get_address_and_encodings(self, base_addr):
        addr_and_encodings = []
        for (i, entry) in enumerate(self.entries):
            func_offset = UNWIND_INFO_COMPRESSED_ENTRY_FUNC_OFFSET(entry)
            enc_idx = UNWIND_INFO_COMPRESSED_ENTRY_ENCODING_INDEX(entry)
            addr_and_encodings.append((base_addr + func_offset,
                                       self.encodings[enc_idx]))
        return addr_and_encodings


class unwind_info_section_header_index_entry:
    '''
        struct unwind_info_section_header_index_entry {
            uint32_t        functionOffset;
            // section offset to start of regular or compress page
            uint32_t        secondLevelPagesSectionOffset;
            // section offset to start of lsda_index array for this range
            uint32_t        lsdaIndexArraySectionOffset;
        };
    '''
    def __init__(self, header, data, text_file_addr):
        self.header = header
        self.data = data
        self.functionOffset = data.get_uint32()
        self.secondLevelPagesSectionOffset = data.get_uint32()
        self.lsdaIndexArraySectionOffset = data.get_uint32()
        self.functionAddr = self.functionOffset + text_file_addr
        self.secondary = None

    @classmethod
    def dump_header(cls, f):
        f.write('INDEX FUNC OFF   2ND OFF    LSDA OFF   FUNC ADDR\n')
        f.write('===== ---------- ---------- ---------- ==================\n')

    def dump_flat(self, index, f):
        f.write("%5u %#8.8x %#8.8x %#8.8x %#16.16x\n" % (index,
                self.functionOffset, self.secondLevelPagesSectionOffset,
                self.lsdaIndexArraySectionOffset, self.functionAddr))

    def dump(self, f):
        f.write("%#16.16x: " % (self.functionAddr))
        f.write("functionOffset = %#8.8x" % (self.functionOffset))
        f.write(", secondLevelPagesSectionOffset = %#8.8x" % (
                self.secondLevelPagesSectionOffset))
        f.write(", lsdaIndexArraySectionOffset = %#8.8x\n" % (
                self.lsdaIndexArraySectionOffset))

    def get_secondary(self):
        if self.secondary is not None:
            return self.secondary
        if self.secondLevelPagesSectionOffset == 0:
            return None
        self.data.push_offset_and_seek(self.secondLevelPagesSectionOffset)
        kind = self.data.get_uint32()
        if kind == UNWIND_SECOND_LEVEL_REGULAR:
            self.secondary = unwind_info_regular_second_level_page_header(
                    self.data, self.header.common_encodings)
        elif kind == UNWIND_SECOND_LEVEL_COMPRESSED:
            self.secondary = unwind_info_compressed_second_level_page_header(
                    self.data, self.header.common_encodings)
        else:
            raise ValueError("invalid kind %#8.8x" % (kind))
        self.data.pop_offset_and_seek()
        return self.secondary

    def dump_secondary(self, f):
        secondary = self.get_secondary()
        if secondary is None:
            f.write('self.secondLevelPagesSectionOffset = <sentinal>\n')
            return
        secondary.dump(f)

    def get_function_starts(self, text_addr):
        secondary = self.get_secondary()
        if secondary is None:
            return []
        return secondary.get_function_starts(text_addr + self.functionOffset)

    def get_address_and_encodings(self, text_addr):
        secondary = self.get_secondary()
        if secondary is None:
            return []
        return secondary.get_address_and_encodings(text_addr +
                                                   self.functionOffset)


class encoding_x86_64:
    UNWIND_X86_64_MODE_MASK = 0x0F000000
    UNWIND_X86_64_MODE_RBP_FRAME = 0x01000000
    UNWIND_X86_64_MODE_STACK_IMMD = 0x02000000
    UNWIND_X86_64_MODE_STACK_IND = 0x03000000
    UNWIND_X86_64_MODE_DWARF = 0x04000000
    UNWIND_X86_64_RBP_FRAME_REGISTERS = 0x00007FFF
    UNWIND_X86_64_RBP_FRAME_OFFSET = 0x00FF0000
    UNWIND_X86_64_FRAMELESS_STACK_SIZE = 0x00FF0000
    UNWIND_X86_64_FRAMELESS_STACK_ADJUST = 0x0000E000
    UNWIND_X86_64_FRAMELESS_STACK_REG_COUNT = 0x00001C00
    UNWIND_X86_64_FRAMELESS_STACK_REG_PERMUTATION = 0x000003FF
    UNWIND_X86_64_DWARF_SECTION_OFFSET = 0x00FFFFFF
    UNWIND_X86_64_REG_NONE = 0
    UNWIND_X86_64_REG_RBX = 1
    UNWIND_X86_64_REG_R12 = 2
    UNWIND_X86_64_REG_R13 = 3
    UNWIND_X86_64_REG_R14 = 4
    UNWIND_X86_64_REG_R15 = 5
    UNWIND_X86_64_REG_RBP = 6

    def __init__(self, encoding):
        self.encoding = encoding

    def get_mode(self):
        return self.encoding & self.UNWIND_X86_64_MODE_MASK

    def get_rbp_frame_offset(self):
        return (self.encoding & self.UNWIND_X86_64_RBP_FRAME_OFFSET) >> 16

    def get_rbp_frame_regs(self):
        return (self.encoding & self.UNWIND_X86_64_RBP_FRAME_REGISTERS)

    def dump(self, f):
        mode = self.get_mode()
        f.write('  %#8.8x (' % (self.encoding))
        if mode == self.UNWIND_X86_64_MODE_RBP_FRAME:
            offset = self.get_rbp_frame_offset()
            regs = self.get_rbp_frame_regs()
            f.write('UNWIND_X86_64_MODE_RBP_FRAME: offset = %2.2x (%u)' % (
                    offset, offset))
            f.write(', regs = %#4.4x' % (regs))
        if mode == self.UNWIND_X86_64_MODE_STACK_IMMD:
            f.write('UNWIND_X86_64_MODE_STACK_IMMD')
        if mode == self.UNWIND_X86_64_MODE_STACK_IND:
            f.write('UNWIND_X86_64_MODE_STACK_IND')
        if mode == self.UNWIND_X86_64_MODE_DWARF:
            f.write('UNWIND_X86_64_MODE_DWARF')
        f.write(')\n')


class unwind_info_section_header:
    '''
        struct unwind_info_section_header {
            uint32_t    version;            // UNWIND_SECTION_VERSION
            uint32_t    commonEncodingsArraySectionOffset;
            uint32_t    commonEncodingsArrayCount;
            uint32_t    personalityArraySectionOffset;
            uint32_t    personalityArrayCount;
            uint32_t    indexSectionOffset;
            uint32_t    indexCount;
            // compact_unwind_encoding_t[]
            // uintptr_t personalities[]
            // unwind_info_section_header_index_entry[]
            // unwind_info_section_header_lsda_index_entry[]
        };
    '''
    def __init__(self, mach):
        self.mach = mach
        self.version = 0
        self.commonEncodingsArraySectionOffset = 0
        self.commonEncodingsArrayCount = 0
        self.personalityArraySectionOffset = 0
        self.personalityArrayCount = 0
        self.indexSectionOffset = 0
        self.indexCount = 0
        self.data = None
        self.common_encodings = []
        self.personalities = []
        self.indexes = []
        self.lsda_entries = []
        self.lsda = {}
        self.data = None

        text_section = mach.get_first_section_with_instructions()
        section = mach.get_section_by_name("__unwind_info")
        if section is None:
            return
        data = section.get_contents_as_extractor(mach)
        if data:
            base_addr = self.mach.get_base_address()

            self.data = data
            self.version = data.get_uint32()
            self.commonEncodingsArraySectionOffset = data.get_uint32()
            self.commonEncodingsArrayCount = data.get_uint32()
            self.personalityArraySectionOffset = data.get_uint32()
            self.personalityArrayCount = data.get_uint32()
            self.indexSectionOffset = data.get_uint32()
            self.indexCount = data.get_uint32()
            data.push_offset_and_seek(
                    self.commonEncodingsArraySectionOffset)
            for _i in range(self.commonEncodingsArrayCount):
                self.common_encodings.append(data.get_uint32())
            data.pop_offset_and_seek()
            data.push_offset_and_seek(self.personalityArraySectionOffset)
            for _i in range(self.personalityArrayCount):
                self.personalities.append(data.get_uint32())
            data.pop_offset_and_seek()
            data.push_offset_and_seek(self.indexSectionOffset)
            for _i in range(self.indexCount):
                self.indexes.append(unwind_info_section_header_index_entry(
                        self, data, text_section.addr))
            data.pop_offset_and_seek()
            if len(self.indexes) > 1:
                min_lsda_offset = self.indexes[0].lsdaIndexArraySectionOffset
                max_lsda_offset = self.indexes[-1].lsdaIndexArraySectionOffset
                if min_lsda_offset < max_lsda_offset:
                    lsda_count = (max_lsda_offset - min_lsda_offset) / 8
                    if lsda_count > 0:
                        data.push_offset_and_seek(min_lsda_offset)
                        for _i in range(lsda_count):
                            func_addr = data.get_uint32() + base_addr
                            lsda_addr = data.get_uint32() + base_addr
                            self.lsda_entries.append((func_addr, lsda_addr))
                            self.lsda[func_addr] = lsda_addr
                        data.pop_offset_and_seek()

    def is_valid(self):
        return self.version > 0 and self.indexCount > 0

    def dump(self, f):
        f.write("header:")
        f.write("  version = %#8.8x\n  " % (self.version))
        f.write("commonEncodingsArray: offset=%#8.8x, count=%#8.8x (%u)\n" % (
                self.commonEncodingsArraySectionOffset,
                self.commonEncodingsArrayCount,
                self.commonEncodingsArrayCount))
        for (i, enc) in enumerate(self.common_encodings):
            f.write("    encoding[%2u] = " % (i))
            encoding_x86_64(enc).dump(f)
        f.write("  personalityArray: offset=%#8.8x, count=%#8.8x (%u)\n" % (
                self.personalityArraySectionOffset, self.personalityArrayCount,
                self.personalityArrayCount))
        for (i, personality) in enumerate(self.personalities):
            f.write('    [%i]=%#8.8x\n' % (i+1, personality))
        f.write("  index: offset=%#8.8x, count=%#8.8x (%u)\n" % (
                self.indexSectionOffset, self.indexCount, self.indexCount))
        unwind_info_section_header_index_entry.dump_header(f=f)
        for (i, index_entry) in enumerate(self.indexes):
            index_entry.dump_flat(i, f)
        if self.lsda_entries:
            f.write("  LSDA table: offset=%#8.8x, count=%u\n" % (
                    self.indexes[0].lsdaIndexArraySectionOffset,
                    len(self.lsda_entries)))
            for (i, (func_addr, ldsa_addr)) in enumerate(self.lsda_entries):
                f.write('    [%i] %#16.16x: lsda=%#16.16x\n' % (i, func_addr,
                        ldsa_addr))
        for (i, index_entry) in enumerate(self.indexes):
            index_entry.dump(f)
            index_entry.dump_secondary(f)

    def get_personality(self, encoding):
        personality = (encoding & UNWIND_PERSONALITY_MASK) >> 28
        if personality == 0:
            return None
        return (self.personalities[personality - 1] +
                self.mach.get_base_address())

    def get_lsda_addr(self, func_addr):
        if func_addr in self.lsda:
            return self.lsda[func_addr]
        return None

    def get_rows(self):
        base_addr = self.mach.get_base_address()
        rows = []
        for index in self.indexes:
            addr_encoding_array = index.get_address_and_encodings(base_addr)
            for (addr, encoding) in addr_encoding_array:
                personality_addr = self.get_personality(encoding)
                lsda_addr = self.get_lsda_addr(addr)
                row = CompactUnwind.Row(func_addr=addr,
                                        encoding=encoding,
                                        personality_addr=personality_addr,
                                        lsda_addr=lsda_addr)
                rows.append(row)
        return rows


class CompactUnwind:
    class Row:
        '''
            A completely decoded version of a Apple compact unwind row with
            all function offsets converted into virtual file addresses.
        '''
        def __init__(self, func_addr=None, encoding=None,
                     personality_addr=None, lsda_addr=None):
            self.func_addr = func_addr
            self.encoding = encoding
            self.personality_addr = personality_addr
            self.lsda_addr = lsda_addr

        def dump(self, f=sys.stdout):
            f.write("%#16.16x: encoding=%#8.8x" % (self.func_addr,
                    self.encoding))
            if self.personality_addr is not None:
                f.write(", personality=%#16.16x" % (self.personality_addr))
            if self.lsda_addr is not None:
                f.write(", lsda=%#16.16x" % (self.lsda_addr))
            f.write('\n')

    def __init__(self, mach):
        self.header = unwind_info_section_header(mach)

    def dump(self, f=sys.stdout):
        self.header.dump(f=f)

    def get_rows(self):
        return self.header.get_rows()

    def get_function_starts(self):
        return self.header.get_function_starts()


g_objc_stats = ObjcStats()


class Mach:
    """Class that does everything mach-o related"""

    class Arch:
        """Class that implements mach-o architectures"""

        def __init__(self, c=0, s=0):
            self.cpu = c
            self.sub = s

        def set_cpu_type(self, c):
            self.cpu = c

        def set_cpu_subtype(self, s):
            self.sub = s

        def set_arch(self, c, s):
            self.cpu = c
            self.sub = s

        def is_64_bit(self):
            return (self.cpu & CPU_ARCH_ABI64) != 0

        def get_address_mask(self):
            '''Return an integer that will act as a mask for any addresses.

            ARM binaries usually have bit zero set if the function is a thumb
            function, so this will need to be masked off of any addresses.
            '''
            if self.cpu == CPU_TYPE_ARM:
                return 0xFFFFFFFE
            return None

        cpu_infos = [
            ["arm", CPU_TYPE_ARM, CPU_TYPE_ANY],
            ["arm", CPU_TYPE_ARM, 0],
            ["armv4", CPU_TYPE_ARM, 5],
            ["armv6", CPU_TYPE_ARM, 6],
            ["armv5", CPU_TYPE_ARM, 7],
            ["xscale", CPU_TYPE_ARM, 8],
            ["armv7", CPU_TYPE_ARM, 9],
            ["armv7f", CPU_TYPE_ARM, 10],
            ["armv7k", CPU_TYPE_ARM, 12],
            ["armv7s", CPU_TYPE_ARM, 11],
            ["arm64", CPU_TYPE_ARM64, 0],
            ["arm64e", CPU_TYPE_ARM64, 2],
            ["ppc", CPU_TYPE_POWERPC, CPU_TYPE_ANY],
            ["ppc", CPU_TYPE_POWERPC, 0],
            ["ppc601", CPU_TYPE_POWERPC, 1],
            ["ppc602", CPU_TYPE_POWERPC, 2],
            ["ppc603", CPU_TYPE_POWERPC, 3],
            ["ppc603e", CPU_TYPE_POWERPC, 4],
            ["ppc603ev", CPU_TYPE_POWERPC, 5],
            ["ppc604", CPU_TYPE_POWERPC, 6],
            ["ppc604e", CPU_TYPE_POWERPC, 7],
            ["ppc620", CPU_TYPE_POWERPC, 8],
            ["ppc750", CPU_TYPE_POWERPC, 9],
            ["ppc7400", CPU_TYPE_POWERPC, 10],
            ["ppc7450", CPU_TYPE_POWERPC, 11],
            ["ppc970", CPU_TYPE_POWERPC, 100],
            ["ppc64", CPU_TYPE_POWERPC64, 0],
            ["ppc970-64", CPU_TYPE_POWERPC64, 100],
            ["i386", CPU_TYPE_I386, 3],
            ["i486", CPU_TYPE_I386, 4],
            ["i486sx", CPU_TYPE_I386, 0x84],
            ["i386", CPU_TYPE_I386, CPU_TYPE_ANY],
            ["x86_64", CPU_TYPE_X86_64, 3],
            ["x86_64h", CPU_TYPE_X86_64, 8],
            ["x86_64", CPU_TYPE_X86_64, CPU_TYPE_ANY],
        ]

        def set_arch_by_name(self, arch_name):
            for info in self.cpu_infos:
                if info[0] == arch_name:
                    self.cpu = info[1]
                    self.sub = info[2]
                    return
            raise ValueError("unsupported architecture name '%s'" % (
                             arch_name))

        def get_arch_name(self):
            for info in self.cpu_infos:
                if info[1] == self.cpu and info[2] == self.sub & 0x00ffffff:
                    return info[0]
            return "0x%8.8x.0x%8.8x" % (self.cpu, self.sub)

        def __str__(self):
            for info in self.cpu_infos:
                if self.cpu == info[1] and (self.sub & 0x00ffffff) == info[2]:
                    return info[0]
            return "{0}.{1}".format(self.cpu, self.sub)

    class Magic(dict_utils.Enum):

        enum = {
            'MH_MAGIC': MH_MAGIC,
            'MH_CIGAM': MH_CIGAM,
            'MH_MAGIC_64': MH_MAGIC_64,
            'MH_CIGAM_64': MH_CIGAM_64,
            'FAT_MAGIC': FAT_MAGIC,
            'FAT_CIGAM': FAT_CIGAM
        }

        def __init__(self, initial_value=0):
            dict_utils.Enum.__init__(self, initial_value, self.enum)

        def is_skinny_mach_file(self):
            return (self.value == MH_MAGIC or self.value == MH_MAGIC_64 or
                    self.value == MH_CIGAM or self.value == MH_CIGAM_64)

        def is_universal_mach_file(self):
            return self.value == FAT_MAGIC or self.value == FAT_CIGAM

        def unpack(self, data):
            data.set_byte_order('native')
            self.value = data.get_uint32()

        def get_byte_order(self):
            if (self.value == MH_CIGAM or self.value == MH_CIGAM_64 or
                    self.value == FAT_CIGAM):
                return swap_unpack_char()
            else:
                return '='

        def is_64_bit(self):
            return self.value == MH_MAGIC_64 or self.value == MH_CIGAM_64

    @classmethod
    def load(cls, path):
        mach = Mach()
        mach.parse(path)
        if mach.is_valid():
            return mach
        return None

    def __init__(self):
        self.magic = Mach.Magic()
        self.content = None
        self.path = None

    def extract(self, path, extractor):
        self.path = path
        self.unpack(extractor)

    def parse(self, path):
        self.path = path
        try:
            f = open(self.path, 'rb')
            file_extractor = file_extract.FileExtract(f, byte_order='=')
            self.unpack(file_extractor)
        except IOError as e:
            print("I/O error({0}): {1}".format(e.errno, e.strerror))
        except ValueError:
            print("Could not convert data to an integer.")

    def get_num_archs(self):
        return self.content.get_num_archs()

    def get_architecture(self, index):
        return self.content.get_architecture(index)

    def get_architecture_slice(self, arch_name):
        return self.content.get_architecture_slice(arch_name)

    def compare(self, rhs):
        self.content.compare(rhs.content)

    def compare_size(self, rhs):
        self.content.compare_size(rhs.content)

    def dump(self, options=None):
        self.content.dump(options)

    def dump_header(self, dump_description=True, options=None):
        self.content.dump_header(dump_description, options)

    def dump_load_commands(self, dump_description=True, options=None):
        self.content.dump_load_commands(dump_description, options)

    def dump_sections(self, dump_description=True, options=None):
        self.content.dump_sections(dump_description, options)

    def dump_section_contents(self, options):
        self.content.dump_section_contents(options)

    def dump_symtab(self, dump_description=True, options=None):
        self.content.dump_symtab(dump_description, options)

    def dump_symbol_names_matching_regex(self, regex, file=None):
        self.content.dump_symbol_names_matching_regex(regex, file)

    def description(self):
        return self.content.description()

    def unpack(self, data):
        self.magic.unpack(data)
        if self.magic.is_skinny_mach_file():
            self.content = Mach.Skinny(self.path)
        elif self.magic.is_universal_mach_file():
            self.content = Mach.Universal(self.path)
        else:
            self.content = None

        if self.content is not None:
            self.content.unpack(data, self.magic)

    def is_valid(self):
        return self.content is not None

    class Universal:

        def __init__(self, path):
            self.path = path
            self.type = 'universal'
            self.file_off = 0
            self.magic = None
            self.nfat_arch = 0
            self.archs = []

        def get_num_archs(self):
            return len(self.archs)

        def get_architecture(self, index):
            if index < len(self.archs):
                return self.archs[index].arch
            return None

        def get_architecture_slice(self, arch_name):
            for arch in self.archs:
                if str(arch.arch) == arch_name:
                    return arch.mach
            return None

        def description(self):
            s = '%#8.8x: %s (' % (self.file_off, self.path)
            archs_string = ''
            for arch in self.archs:
                if len(archs_string):
                    archs_string += ', '
                archs_string += '%s' % arch.arch
            s += archs_string
            s += ')'
            return s

        def unpack(self, data, magic=None):
            self.file_off = data.tell()
            if magic is None:
                self.magic = Mach.Magic()
                self.magic.unpack(data)
            else:
                self.magic = magic
                self.file_off = self.file_off - 4
            # Universal headers are always in big endian
            data.set_byte_order('big')
            self.nfat_arch = data.get_uint32()
            for i in range(self.nfat_arch):
                self.archs.append(Mach.Universal.ArchInfo())
                self.archs[i].unpack(data)
            for i in range(self.nfat_arch):
                self.archs[i].mach = Mach.Skinny(self.path)
                data.seek(self.archs[i].offset, 0)
                skinny_magic = Mach.Magic()
                skinny_magic.unpack(data)
                self.archs[i].mach.unpack(data, skinny_magic)

        def compare(self, rhs):
            for i in range(self.nfat_arch):
                lhs_arch = self.archs[i]
                found_matching_arch = False
                for j in range(rhs.nfat_arch):
                    rhs_arch = rhs.archs[j]
                    if (lhs_arch.arch.cpu == rhs_arch.arch.cpu and
                            lhs_arch.arch.sub == rhs_arch.arch.sub):
                        lhs_arch.mach.compare(rhs_arch.mach)
                        found_matching_arch = True
                        break
                if not found_matching_arch:
                    print('error: "%s" contains architecture %s but "%s" does '
                          'not' % (self.path, lhs_arch.get_arch_name(),
                                   rhs.path))

        def dump(self, options):
            if options.dump_header:
                print()
                print("Universal Mach File: magic = %s, nfat_arch = %u" % (
                    self.magic, self.nfat_arch))
                print()
            if self.nfat_arch > 0:
                if options.dump_header:
                    self.archs[0].dump_header(True, options)
                    for i in range(self.nfat_arch):
                        self.archs[i].dump_flat(options)
                    print()
                for i in range(self.nfat_arch):
                    self.archs[i].mach.dump(options)

        def dump_header(self, dump_description=True, options=None):
            if dump_description:
                print(self.description())
            for i in range(self.nfat_arch):
                self.archs[i].mach.dump_header(True, options)
                print()

        def dump_load_commands(self, dump_description=True, options=None):
            if dump_description:
                print(self.description())

            for i in range(self.nfat_arch):
                self.archs[i].mach.dump_load_commands(True, options)
                print

        def dump_sections(self, dump_description=True, options=None):
            if dump_description:
                print(self.description())
            for i in range(self.nfat_arch):
                self.archs[i].mach.dump_sections(True, options)
                print

        def dump_section_contents(self, options):
            for i in range(self.nfat_arch):
                self.archs[i].mach.dump_section_contents(options)
                print

        def dump_symtab(self, dump_description=True, options=None):
            if dump_description:
                print(self.description())
            for i in range(self.nfat_arch):
                self.archs[i].mach.dump_symtab(True, options)
                print

        def dump_symbol_names_matching_regex(self, regex, file=None):
            for i in range(self.nfat_arch):
                self.archs[i].mach.dump_symbol_names_matching_regex(regex,
                                                                    file)

        class ArchInfo:

            def __init__(self):
                self.arch = Mach.Arch(0, 0)
                self.offset = 0
                self.size = 0
                self.align = 0
                self.mach = None

            def unpack(self, data):
                # Universal headers are always in big endian
                data.set_byte_order('big')
                (self.arch.cpu, self.arch.sub, self.offset, self.size,
                 self.align) = data.get_n_uint32(5)

            def dump_header(self, dump_description=True, options=None):
                if options.verbose:
                    print("CPU        SUBTYPE    OFFSET     SIZE       ALIGN")
                    print("---------- ---------- ---------- ---------- "
                          "----------")
                else:
                    print("ARCH       FILEOFFSET FILESIZE   ALIGN")
                    print("---------- ---------- ---------- ----------")

            def dump_flat(self, options):
                if options.verbose:
                    print("%#8.8x %#8.8x %#8.8x %#8.8x %#8.8x" % (
                          self.arch.cpu, self.arch.sub, self.offset, self.size,
                          self.align))
                else:
                    print("%-10s %#8.8x %#8.8x %#8.8x" % (self.arch,
                          self.offset, self.size, self.align))

            def dump(self):
                print("   cputype: %#8.8x" % (self.arch.cpu))
                print("cpusubtype: %#8.8x" % (self.arch.sub))
                print("    offset: %#8.8x" % (self.offset))
                print("      size: %#8.8x" % (self.size))
                print("     align: %#8.8x" % (self.align))

            def __str__(self):
                return ("Mach.Universal.ArchInfo: %#8.8x %#8.8x %#8.8x %#8.8x "
                        "%#8.8x") % (self.arch.cpu, self.arch.sub, self.offset,
                                     self.size, self.align)

            def __repr__(self):
                return ("Mach.Universal.ArchInfo: %#8.8x %#8.8x %#8.8x %#8.8x "
                        "%#8.8x") % (self.arch.cpu, self.arch.sub, self.offset,
                                     self.size, self.align)

    class Flags:

        def __init__(self, b):
            self.bits = b

        def __str__(self):
            s = ''
            if self.bits & MH_NOUNDEFS:
                s += 'MH_NOUNDEFS | '
            if self.bits & MH_INCRLINK:
                s += 'MH_INCRLINK | '
            if self.bits & MH_DYLDLINK:
                s += 'MH_DYLDLINK | '
            if self.bits & MH_BINDATLOAD:
                s += 'MH_BINDATLOAD | '
            if self.bits & MH_PREBOUND:
                s += 'MH_PREBOUND | '
            if self.bits & MH_SPLIT_SEGS:
                s += 'MH_SPLIT_SEGS | '
            if self.bits & MH_LAZY_INIT:
                s += 'MH_LAZY_INIT | '
            if self.bits & MH_TWOLEVEL:
                s += 'MH_TWOLEVEL | '
            if self.bits & MH_FORCE_FLAT:
                s += 'MH_FORCE_FLAT | '
            if self.bits & MH_NOMULTIDEFS:
                s += 'MH_NOMULTIDEFS | '
            if self.bits & MH_NOFIXPREBINDING:
                s += 'MH_NOFIXPREBINDING | '
            if self.bits & MH_PREBINDABLE:
                s += 'MH_PREBINDABLE | '
            if self.bits & MH_ALLMODSBOUND:
                s += 'MH_ALLMODSBOUND | '
            if self.bits & MH_SUBSECTIONS_VIA_SYMBOLS:
                s += 'MH_SUBSECTIONS_VIA_SYMBOLS | '
            if self.bits & MH_CANONICAL:
                s += 'MH_CANONICAL | '
            if self.bits & MH_WEAK_DEFINES:
                s += 'MH_WEAK_DEFINES | '
            if self.bits & MH_BINDS_TO_WEAK:
                s += 'MH_BINDS_TO_WEAK | '
            if self.bits & MH_ALLOW_STACK_EXECUTION:
                s += 'MH_ALLOW_STACK_EXECUTION | '
            if self.bits & MH_ROOT_SAFE:
                s += 'MH_ROOT_SAFE | '
            if self.bits & MH_SETUID_SAFE:
                s += 'MH_SETUID_SAFE | '
            if self.bits & MH_NO_REEXPORTED_DYLIBS:
                s += 'MH_NO_REEXPORTED_DYLIBS | '
            if self.bits & MH_PIE:
                s += 'MH_PIE | '
            if self.bits & MH_DEAD_STRIPPABLE_DYLIB:
                s += 'MH_DEAD_STRIPPABLE_DYLIB | '
            if self.bits & MH_HAS_TLV_DESCRIPTORS:
                s += 'MH_HAS_TLV_DESCRIPTORS | '
            if self.bits & MH_NO_HEAP_EXECUTION:
                s += 'MH_NO_HEAP_EXECUTION | '
            # Strip the trailing " |" if we have any flags
            if len(s) > 0:
                s = s[0:-2]
            return s

    class FileType(dict_utils.Enum):

        enum = {
            'MH_OBJECT': MH_OBJECT,
            'MH_EXECUTE': MH_EXECUTE,
            'MH_FVMLIB': MH_FVMLIB,
            'MH_CORE': MH_CORE,
            'MH_PRELOAD': MH_PRELOAD,
            'MH_DYLIB': MH_DYLIB,
            'MH_DYLINKER': MH_DYLINKER,
            'MH_BUNDLE': MH_BUNDLE,
            'MH_DYLIB_STUB': MH_DYLIB_STUB,
            'MH_DSYM': MH_DSYM,
            'MH_KEXT_BUNDLE': MH_KEXT_BUNDLE
        }

        def __init__(self, initial_value=0):
            dict_utils.Enum.__init__(self, initial_value, self.enum)

    class Skinny:

        def __init__(self, path):
            self.path = path
            self.type = 'skinny'
            self.data = None
            self.strtab_data = None
            self.file_off = 0
            self.magic = 0
            self.arch = Mach.Arch(0, 0)
            self.filetype = Mach.FileType(0)
            self.ncmds = 0
            self.sizeofcmds = 0
            self.flags = Mach.Flags(0)
            self.uuid_bytes = None
            self.commands = []
            self.segments = []
            self.sections = []
            self.symbols = []
            self.function_starts = None
            self.sections.append(Mach.Section())
            self.dwarf = -1
            self.base_address = None

        def get_address_mask(self):
            return self.arch.get_address_mask()

        def get_unwind_data_and_addr(self, is_eh_frame):
            if is_eh_frame:
                sect_name = '__eh_frame'
            else:
                sect_name = '__debug_frame'
            section = self.get_section_by_name(sect_name)
            if section:
                return (section.get_contents_as_extractor(self), section.addr)
            return (None, None)

        def get_arch(self):
            '''Return the short architecture name for this file'''
            return self.get_architecture(0).get_arch_name()

        def get_base_address(self):
            if self.base_address is None:
                text_segment = self.get_segment('__TEXT')
                if text_segment:
                    self.base_address = text_segment.vmaddr
                else:
                    raise ValueError('no __TEXT segment in get_base_address()')
            return self.base_address

        def get_function_starts(self):
            '''
                Parse the LC_FUNCTION_STARTS and return the array of function
                start addresses
            '''
            if self.function_starts is not None:
                return self.function_starts

            lc_func_starts = self.get_first_load_command(LC_FUNCTION_STARTS)
            if not lc_func_starts:
                return None
            self.function_starts = []
            # Address size is hard coded to 4 bytes below, but we only extract
            # ULEB128 numbers
            data = file_extract.FileExtract(io.BytesIO(lc_func_starts.data),
                                            self.get_byte_order(), 4)
            addr = self.get_base_address()
            delta = data.get_uleb128()
            while delta > 0:
                self.function_starts.append(addr + delta)
                addr += delta
                delta = data.get_uleb128()
            return self.function_starts

        def get_byte_order(self):
            if self.magic == 0:
                return '='
            return self.magic.get_byte_order()

        def get_file_type(self):
            return 'mach-o'

        def get_num_archs(self):
            return 1

        def get_architecture(self, index):
            if index == 0:
                return self.arch
            return None

        def get_architecture_slice(self, arch_name):
            if str(self.arch) == arch_name:
                return self
            return None

        def __str__(self):
            return self.description()

        __repr__ = __str__

        def description(self, show_offset=True):
            if show_offset:
                return '%#8.8x: %s (%s)' % (self.file_off, self.path, self.arch)
            return '%s (%s)' % (self.path, self.arch)

        def unpack(self, data, magic=None):
            self.data = data
            self.file_off = data.tell()
            if magic is None:
                self.magic = Mach.Magic()
                self.magic.unpack(data)
            else:
                self.magic = magic
                self.file_off = self.file_off - 4
            data.set_byte_order(self.get_byte_order())
            (self.arch.cpu, self.arch.sub, self.filetype.value, self.ncmds,
             self.sizeofcmds, bits) = data.get_n_uint32(6)
            self.flags.bits = bits

            if self.is_64_bit():
                data.set_addr_size(8)
                data.get_uint32()  # Skip reserved word in mach_header_64
            else:
                data.set_addr_size(4)

            for i in range(0, self.ncmds):
                lc = self.unpack_load_command(data)
                self.commands.append(lc)
                if lc.command == LC_SYMTAB:
                    self.strtab_data = lc.get_strtab_data(self)

        def get_string(self, strp):
            '''Get a string from the string table the specified offset.'''
            self.strtab_data.seek(strp)
            return self.strtab_data.get_c_string()

        def get_data(self):
            if self.data:
                self.data.set_byte_order(self.get_byte_order())
                if self.is_64_bit():
                    self.data.set_addr_size(8)
                else:
                    self.data.set_addr_size(4)
                return self.data
            return None

        def unpack_load_command(self, data):
            lc = Mach.LoadCommand()
            lc.unpack(self, data)
            lc_command = lc.command.get_enum_value()
            if (lc_command == LC_SEGMENT or lc_command == LC_SEGMENT_64):
                lc = Mach.SegmentLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_LOAD_DYLIB or
                  lc_command == LC_ID_DYLIB or
                  lc_command == LC_LOAD_WEAK_DYLIB or
                  lc_command == LC_REEXPORT_DYLIB):
                lc = Mach.DylibLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_LOAD_DYLINKER or
                  lc_command == LC_SUB_FRAMEWORK or
                  lc_command == LC_SUB_CLIENT or
                  lc_command == LC_SUB_UMBRELLA or
                  lc_command == LC_SUB_LIBRARY or
                  lc_command == LC_ID_DYLINKER or
                  lc_command == LC_RPATH):
                lc = Mach.LoadDYLDLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_DYLD_INFO_ONLY):
                lc = Mach.DYLDInfoOnlyLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_SYMTAB):
                lc = Mach.SymtabLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_DYSYMTAB):
                lc = Mach.DYLDSymtabLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_UUID):
                lc = Mach.UUIDLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_CODE_SIGNATURE or
                  lc_command == LC_SEGMENT_SPLIT_INFO or
                  lc_command == LC_FUNCTION_STARTS or
                  lc_command == LC_DATA_IN_CODE or
                  lc_command == LC_DYLIB_CODE_SIGN_DRS or
                  lc_command == LC_LINKER_OPTIMIZATION_HINT):
                lc = Mach.DataBlobLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_UNIXTHREAD):
                lc = Mach.UnixThreadLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_ENCRYPTION_INFO):
                lc = Mach.EncryptionInfoLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_MAIN):
                lc = Mach.MainLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command in [LC_VERSION_MIN_MACOSX,
                                 LC_VERSION_MIN_IPHONEOS,
                                 LC_VERSION_MIN_WATCHOS,
                                 LC_VERSION_MIN_TVOS]):
                lc = Mach.VersionMinLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_SOURCE_VERSION):
                lc = Mach.SourceVersionLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_LINKER_OPTION):
                lc = Mach.LinkerOptionLoadCommand(lc)
                lc.unpack(self, data)
            elif (lc_command == LC_BUILD_VERSION):
                lc = Mach.BuildVersionLoadCommand(lc)
                lc.unpack(self, data)
            lc.skip(data)
            return lc

        def find_matching_load_command(self, rhs_lc, hint_index):
            '''Find a load command that matches a one from another file'''
            rhs_cmd = rhs_lc.command.get_enum_value()
            lhs_lc = self.commands[hint_index]
            lhs_cmd = lhs_lc.command.get_enum_value()
            if rhs_cmd == lhs_cmd and lhs_lc.matches(rhs_lc):
                return lhs_lc
            for lhs_lc in self.commands:
                lhs_cmd = lhs_lc.command.get_enum_value()
                if rhs_cmd == lhs_cmd and lhs_lc.matches(rhs_lc):
                    return lhs_lc
            return None

        def compare_size(self, b):
            a = self
            print("\nComparing file sizes:")
            print("a) %s %s" % (a.arch, a.path))
            print("b) %s %s" % (b.arch, b.path))

            print("\nComparing LC_SEGMENT load commands:")
            for a_seg in a.segments:
                b_seg = b.get_segment(a_seg.segname)
                if b_seg:
                    first_col_width = len(a_seg.segname) + 16 + 1
                    if len(a_seg.sections):
                        print('%-*s %8s %8s' % (first_col_width, 'Section',
                              'Delta', 'Delta'))
                        print('-' * (first_col_width) + ' -------- --------')
                    for a_sect in a_seg.sections:
                        b_sect = b_seg.find_section(a_sect.sectname)
                        if b_sect:
                            a_size = a_sect.size
                            b_size = b_sect.size
                            delta = b_size - a_size
                            print('%s.%-16s  %+7i %8s' % (a_seg.segname,
                                  a_sect.sectname, delta, sizeof_fmt(delta)))
                        else:
                            print('%s.%-16s section missing in b)' % (
                                  a_seg.segname, a_sect.sectname))
                    if len(a_seg.sections):
                        print('-' * (first_col_width) + ' -------- --------')
                    a_size = a_seg.filesize
                    b_size = b_seg.filesize
                    delta = b_size - a_size
                    print('%s%17s  %+7i %8s\n' % (a_seg.segname, '', delta,
                          sizeof_fmt(delta)))
                else:
                    print('%s segment missing in b)' % (a_seg.segname))

        def compare(self, rhs):
            print("\nComparing:")
            print("a) %s %s" % (self.arch, self.path))
            print("b) %s %s" % (rhs.arch, rhs.path))
            result = True
            if self.type == rhs.type:
                print("Comparing Load Commands:")
                for (i, lhs_cmd) in enumerate(self.commands):
                    rhs_cmd = rhs.find_matching_load_command(lhs_cmd, i)
                    if rhs_cmd is None:
                        print('error: could not find matching load command '
                              'for %s' % (lhs_cmd))
                    else:
                        if not lhs_cmd.compare(self, rhs_cmd, rhs):
                            print("error: mismatching load commands:")
                            print(str(lhs_cmd))
                            print(str(rhs_cmd))

                print("Comparing sections:")
                for lhs_section in self.sections[1:]:
                    rhs_section = rhs.get_section_by_section(lhs_section)
                    if rhs_section:
                        sys.stdout.write('comparing %s.%s...' % (
                                         lhs_section.segname,
                                         lhs_section.sectname))
                        sys.stdout.flush()
                        lhs_data = lhs_section.get_contents(self)
                        rhs_data = rhs_section.get_contents(rhs)
                        if lhs_data and rhs_data:
                            if lhs_data == rhs_data:
                                print('ok')
                            else:
                                result = False
                                print('error: sections differ')
                        elif lhs_data and not rhs_data:
                            print('error: section data missing from b:')
                            print('a) %s' % (lhs_section))
                            print('b) %s' % (rhs_section))
                            result = False
                        elif not lhs_data and rhs_data:
                            print('error: section data missing from a:')
                            print('a) %s' % (lhs_section))
                            print('b) %s' % (rhs_section))
                            result = False
                        elif ((lhs_section.offset or rhs_section.offset) and
                              (lhs_section.size > 0 or rhs_section.size > 0)):
                            print('error: section data missing for a and b:')
                            print('a) %s' % (lhs_section))
                            print('b) %s' % (rhs_section))
                            result = False
                        else:
                            print('ok')
                    else:
                        result = False
                        print('error: section %s is missing in %s' % (
                              lhs_section.sectname, rhs.path))
            else:
                print('error: comaparing a %s mach-o file with a %s mach-o '
                      'file is not supported') % (self.type, rhs.type)
                result = False
            if not result:
                print('error: mach files differ')
            return result

        def dump_header_header(self, dump_description=True, options=None):
            if options.verbose:
                print("MAGIC      CPU        SUBTYPE    FILETYPE   NUM CMDS "
                      "SIZE CMDS  FLAGS")
                print("---------- ---------- ---------- ---------- -------- "
                      "---------- ----------")
            else:
                print("MAGIC        ARCH       FILETYPE       NUM CMDS "
                      "SIZE CMDS  FLAGS")
                print("------------ ---------- -------------- -------- "
                      "---------- ----------")

        def dump_flat(self, options):
            if options.verbose:
                print("%#8.8x %#8.8x %#8.8x %#8.8x %#8u %#8.8x %#8.8x" % (
                      self.magic, self.arch.cpu, self.arch.sub,
                      self.filetype.value, self.ncmds, self.sizeofcmds,
                      self.flags.bits))
            else:
                print("%-12s %-10s %-14s %#8u %#8.8x %s" % (
                      self.magic, self.arch, self.filetype, self.ncmds,
                      self.sizeofcmds, self.flags))

        def get_dwarf(self):
            if self.dwarf == -1:
                self.dwarf = None
                debug_abbrev_data = self.get_section_contents_by_name(
                    '__debug_abbrev')
                debug_info_data = self.get_section_contents_by_name(
                    '__debug_info')
                if debug_abbrev_data or debug_info_data:
                    debug_aranges_data = self.get_section_contents_by_name(
                        '__debug_aranges')
                    debug_line_data = self.get_section_contents_by_name(
                        '__debug_line')
                    debug_ranges_data = self.get_section_contents_by_name(
                        '__debug_ranges')
                    debug_str_data = self.get_section_contents_by_name(
                        '__debug_str')
                    debug_line_str_data = self.get_section_contents_by_name(
                        '__debug_line_str')
                    apple_names_data = self.get_section_contents_by_name(
                        '__apple_names')
                    apple_types_data = self.get_section_contents_by_name(
                        '__apple_types')
                    debug_names_data = self.get_section_contents_by_name(
                        '__debug_names')
                    self.dwarf = dwarf.context.DWARF(
                        objfile=self,
                        debug_abbrev=debug_abbrev_data,
                        debug_aranges=debug_aranges_data,
                        debug_info=debug_info_data,
                        debug_line=debug_line_data,
                        debug_line_str=debug_line_str_data,
                        debug_names=debug_names_data,
                        debug_ranges=debug_ranges_data,
                        debug_str=debug_str_data,
                        apple_names=apple_names_data,
                        apple_types=apple_types_data)
            return self.dwarf

        def dump(self, options):
            if len(options.archs) > 0 and str(self.arch) not in options.archs:
                return
            if options.dump_header:
                self.dump_header(True, options)
            if options.dump_load_commands:
                self.dump_load_commands(False, options)
            if options.dump_sections:
                self.dump_sections(False, options)
            if options.section_names:
                self.dump_section_contents(options)
            if options.dump_symtab:
                symbols = self.get_symtab()
                if len(symbols):
                    self.dump_symtab(False, options)
                else:
                    print("No symbols")
            if options.functions:
                # First figure out which sections contain code.
                sect_has_code = []
                for section in self.sections:
                    sect_has_code.append(section.contains_code())
                addr_to_funcs = defaultdict(lambda: [])
                symbols = self.get_symtab()
                for symbol in symbols:
                    if symbol.sect_idx < len(sect_has_code):
                        if sect_has_code[symbol.sect_idx]:
                            addr_to_funcs[symbol.value].append(symbol.name)
                func_starts = self.get_function_starts()
                if func_starts:
                    for addr in func_starts:
                        if addr not in addr_to_funcs:
                            addr_to_funcs[addr].append('<no-name>')
                for addr in sorted(addr_to_funcs.keys()):
                    funcs = addr_to_funcs[addr]
                    for func in funcs:
                        print(func)

            if options.symbols_in_section:
                sect_idx = None
                for (i, section) in enumerate(self.sections):
                    if section.sectname == options.symbols_in_section:
                        sect_idx = i
                        break
                if sect_idx is None:
                    print('error: no section with name "%s" was found' % (
                          options.symbols_in_section))
                else:
                    symbols = self.get_symtab()
                    sect_symbols = []
                    symbol_names = []
                    for symbol in symbols:
                        if symbol.sect_idx == sect_idx:
                            # symbol_names.append(symbol.name)
                            print(symbol)
                            # sect_symbols.append(symbol)
                    # for name in sorted(symbol_names):
                    #     print(name)

            if options.find_mangled:
                self.dump_symbol_names_matching_regex(re.compile('^_?_Z'))
            if options.objc:
                self.dump_objc(False, options)
            if options.objc_stats:
                self.dump_objc_stats(options)
            if options.compact_unwind or options.unwind_dups:
                compact_unwind = CompactUnwind(self)
                if compact_unwind:
                    if options.unwind_dups:
                        addr_to_unwind = defaultdict(lambda: [])
                        eh_frame = dwarf.options.get_unwind_info(self, True)
                        if eh_frame:
                            rows = compact_unwind.get_rows()
                            for row in rows:
                                addr_to_unwind[row.func_addr].append(row)
                                # fde = eh_frame.get_fde_for_addr(row.func_addr)
                                # if fde is not None:
                                #     print("warning: Apple compact unwind row and EH frame have unwind information:")
                                #     row.dump()
                                #     fde.dump()
                            for fde in eh_frame.get_fdes():
                                addr_to_unwind[fde.addr].append(fde)
                        for addr in sorted(addr_to_unwind.keys()):
                            entries_for_addr = addr_to_unwind[addr]
                            if len(entries_for_addr) > 1:
                                print("warning: multiple entries for %#8.8x" % (addr))
                            for e in entries_for_addr:
                                e.dump()
                        else:
                            print("error: no __eh_frame to check against")
                    else:
                        print('compact unwind:')
                        if options.verbose:
                            compact_unwind.dump()
                        else:
                            rows = compact_unwind.get_rows()
                            for row in rows:
                                row.dump()
                else:
                    print('error: no compact unwind')
            if options.func_starts:
                func_starts = self.get_function_starts()
                if func_starts:
                    for func_start in func_starts:
                        print("%#8.8x" % (func_start))

            dwarf.options.handle_options(options, self)

        def dump_header(self, dump_description=True, options=None):
            if dump_description:
                print(self.description())
            print("Mach Header")
            print("       magic: %#8.8x %s" % (self.magic.value, self.magic))
            print("     cputype: %#8.8x %s" % (self.arch.cpu, self.arch))
            print("  cpusubtype: %#8.8x" % self.arch.sub)
            print("    filetype: %#8.8x %s" % (self.filetype.get_enum_value(),
                                               self.filetype.get_enum_name()))
            print("       ncmds: %#8.8x %u" % (self.ncmds, self.ncmds))
            print("  sizeofcmds: %#8.8x" % self.sizeofcmds)
            print("       flags: %#8.8x %s" % (self.flags.bits, self.flags))

        def dump_load_commands(self, dump_description=True, options=None):
            if dump_description:
                print(self.description())
            for lc in self.commands:
                print(lc)

        def get_first_section_with_instructions(self):
            for section in self.sections:
                if section.contains_code():
                    return section
            return None

        def get_section_by_name(self, name):
            for section in self.sections:
                if section.sectname and section.sectname == name:
                    return section
            return None

        def get_section_contents_by_name(self, name):
            section = self.get_section_by_name(name)
            if section:
                return section.get_contents_as_extractor(self)
            return None

        def get_section_by_section(self, other_section):
            for section in self.sections:
                if (section.sectname == other_section.sectname and
                        section.segname == other_section.segname):
                    return section
            return None

        def addr_to_file_offset(self, addr):
            for section in self.sections:
                file_offset = section.addr_to_file_offset(addr)
                if file_offset is not None:
                    return file_offset + self.file_off
            return None

        def seek_to_addr(self, addr):
            file_offset = self.addr_to_file_offset(addr)
            if file_offset is None:
                raise ValueError('unable to convert %#x to file offset' % (
                                 addr))
            data = self.get_data()
            data.seek(file_offset)
            return data

        def read_c_string_from_addr(self, addr):
            return self.seek_to_addr(addr).get_c_string()

        def get_objc_classes(self):
            classlist_sect = self.get_section_by_name("__objc_classlist")
            data_sect = self.get_section_by_name("__objc_data")
            objc_classes = []
            if classlist_sect and data_sect:
                classlist = classlist_sect.get_contents_as_extractor(self)
                isas = []
                while True:
                    isa = classlist.get_address()
                    if isa == 0:
                        break
                    isas.append(isa)
                for isa in isas:
                    objc_classes.append(class_t(isa, self))
            return objc_classes

        def dump_objc(self, dump_description=True, options=None):
            out = OutputHelper()
            for objc_class in self.get_objc_classes():
                objc_class.dump(out)

        def dump_objc_stats(self, options):
            global g_objc_stats
            objc_stats = ObjcStats()
            for objc_class in self.get_objc_classes():
                objc_class.gather_stats(objc_stats)
            print('Objective C stats for %s (%s):' % (self.path, self.arch))
            objc_stats.dump()
            g_objc_stats.aggregate(objc_stats)

        def dump_sections(self, dump_description=True, options=None):
            if dump_description:
                print(self.description())
            num_sections = len(self.sections)
            if num_sections > 1:
                file_ranges = AddressRangeList()
                self.sections[1].dump_header()
                for sect_idx in range(1, num_sections):
                    sect = self.sections[sect_idx]
                    print("%s" % sect)
                    if sect.offset != 0:
                        file_range = AddressRange(sect.offset,
                                                  sect.offset + sect.size)
                        if file_ranges.any_range_intersects(file_range):
                            print(" error: this section's file range overlaps "
                                  "another")
                        file_ranges.append(file_range)
                        if file_range.hi > UINT32_MAX:
                            print("warning: this section's end file range %#x "
                                  "(%#x + %#x) exceeds the 4GB boundary, "
                                  "subsequent sections might have their "
                                  "offsets truncated since 64 bit mach-o "
                                  "sections only have 32 bit offsets." % (
                                        file_range.hi, sect.offset, sect.size))
                            print("         Subsequent section might have an "
                                  "offset greater than or equal to %#8.8x" % (
                                        file_range.hi & 0xFFFFFFFF))

        def dump_section_contents(self, options):
            saved_section_to_disk = False
            for sectname in options.section_names:
                section = self.get_section_by_name(sectname)
                if section:
                    sect_bytes = section.get_contents(self)
                    if options.outfile:
                        if not saved_section_to_disk:
                            outfile = open(options.outfile, 'w')
                            print("Saving section %s to '%s'" % (
                                  sectname, options.outfile))
                            outfile.write(sect_bytes)
                            outfile.close()
                            saved_section_to_disk = True
                        else:
                            print(("error: you can only save a single section "
                                   "to disk at a time, skipping section "
                                   "'%s'") % (sectname))
                    else:
                        print('section %s:\n' % (sectname))
                        section.dump_header()
                        print('%s\n' % (section))
                        file_extract.dump_memory(0, sect_bytes, 16, sys.stdout)
                else:
                    print('error: no section named "%s" was found' % (
                          sectname))

        def get_segment(self, segname):
            if len(self.segments) == 1 and self.segments[0].segname == '':
                return self.segments[0]
            for segment in self.segments:
                if segment.segname == segname:
                    return segment
            return None

        def get_uuid_bytes(self):
            if self.uuid_bytes is None:
                lc_uuid = self.get_first_load_command(LC_UUID)
                if lc_uuid:
                    self.uuid_bytes = lc_uuid.uuid.bytes
            return self.uuid_bytes

        def get_first_load_command(self, lc_enum_value):
            for lc in self.commands:
                if lc.command.value == lc_enum_value:
                    return lc
            return None

        def get_symtab(self):
            if self.data and not self.symbols:
                lc_symtab = self.get_first_load_command(LC_SYMTAB)
                if lc_symtab:
                    symtab_offset = self.file_off
                    symtab_offset += lc_symtab.symoff
                    self.data.seek(symtab_offset)
                    for i in range(lc_symtab.nsyms):
                        nlist = Mach.NList()
                        nlist.unpack(self, self.data, lc_symtab)
                        self.symbols.append(nlist)
            return self.symbols

        def get_symbols_with_type(self, symbol_type):
            matches = []
            symbols = self.get_symtab()
            for symbol in symbols:
                if symbol.type.value == symbol_type:
                    matches.append(symbol)
            return matches

        def dump_symtab(self, dump_description=True, options=None):
            symbols = self.get_symtab()
            if dump_description:
                print(self.description())
            for i, symbol in enumerate(symbols):
                print('[%5u] %s' % (i, symbol))

        def dump_symbol_names_matching_regex(self, regex, file=None):
            symbols = self.get_symtab()
            for symbol in symbols:
                if symbol.name and regex.search(symbol.name):
                    print(symbol.name)
                    if file:
                        file.write('%s\n' % (symbol.name))

        def is_64_bit(self):
            return self.magic.is_64_bit()

        def get_bytes(self, offset, size):
            '''Get bytes of data from the mach-o file as a python string'''
            self.data.push_offset_and_seek(self.file_off + offset)
            bytes = self.data.read_size(size)
            self.data.pop_offset_and_seek()
            return bytes

        def get_data_slice(self, offset, size):
            '''Get bytes of data from the mach-o file as a FileExtract object'''
            self.data.push_offset_and_seek(self.file_off + offset)
            bytes = self.data.read_data(size)
            self.data.pop_offset_and_seek()
            return bytes

    class LoadCommand:
        class Command(dict_utils.Enum):
            enum = {
                'LC_SEGMENT': LC_SEGMENT,
                'LC_SYMTAB': LC_SYMTAB,
                'LC_SYMSEG': LC_SYMSEG,
                'LC_THREAD': LC_THREAD,
                'LC_UNIXTHREAD': LC_UNIXTHREAD,
                'LC_LOADFVMLIB': LC_LOADFVMLIB,
                'LC_IDFVMLIB': LC_IDFVMLIB,
                'LC_IDENT': LC_IDENT,
                'LC_FVMFILE': LC_FVMFILE,
                'LC_PREPAGE': LC_PREPAGE,
                'LC_DYSYMTAB': LC_DYSYMTAB,
                'LC_LOAD_DYLIB': LC_LOAD_DYLIB,
                'LC_ID_DYLIB': LC_ID_DYLIB,
                'LC_LOAD_DYLINKER': LC_LOAD_DYLINKER,
                'LC_ID_DYLINKER': LC_ID_DYLINKER,
                'LC_PREBOUND_DYLIB': LC_PREBOUND_DYLIB,
                'LC_ROUTINES': LC_ROUTINES,
                'LC_SUB_FRAMEWORK': LC_SUB_FRAMEWORK,
                'LC_SUB_UMBRELLA': LC_SUB_UMBRELLA,
                'LC_SUB_CLIENT': LC_SUB_CLIENT,
                'LC_SUB_LIBRARY': LC_SUB_LIBRARY,
                'LC_TWOLEVEL_HINTS': LC_TWOLEVEL_HINTS,
                'LC_PREBIND_CKSUM': LC_PREBIND_CKSUM,
                'LC_LOAD_WEAK_DYLIB': LC_LOAD_WEAK_DYLIB,
                'LC_SEGMENT_64': LC_SEGMENT_64,
                'LC_ROUTINES_64': LC_ROUTINES_64,
                'LC_UUID': LC_UUID,
                'LC_RPATH': LC_RPATH,
                'LC_CODE_SIGNATURE': LC_CODE_SIGNATURE,
                'LC_SEGMENT_SPLIT_INFO': LC_SEGMENT_SPLIT_INFO,
                'LC_REEXPORT_DYLIB': LC_REEXPORT_DYLIB,
                'LC_LAZY_LOAD_DYLIB': LC_LAZY_LOAD_DYLIB,
                'LC_ENCRYPTION_INFO': LC_ENCRYPTION_INFO,
                'LC_DYLD_INFO': LC_DYLD_INFO,
                'LC_DYLD_INFO_ONLY': LC_DYLD_INFO_ONLY,
                'LC_LOAD_UPWARD_DYLIB': LC_LOAD_UPWARD_DYLIB,
                'LC_VERSION_MIN_MACOSX': LC_VERSION_MIN_MACOSX,
                'LC_VERSION_MIN_IPHONEOS': LC_VERSION_MIN_IPHONEOS,
                'LC_FUNCTION_STARTS': LC_FUNCTION_STARTS,
                'LC_DYLD_ENVIRONMENT': LC_DYLD_ENVIRONMENT,
                'LC_MAIN': LC_MAIN,
                'LC_DATA_IN_CODE': LC_DATA_IN_CODE,
                'LC_SOURCE_VERSION': LC_SOURCE_VERSION,
                'LC_DYLIB_CODE_SIGN_DRS': LC_DYLIB_CODE_SIGN_DRS,
                'LC_ENCRYPTION_INFO_64': LC_ENCRYPTION_INFO_64,
                'LC_LINKER_OPTION': LC_LINKER_OPTION,
                'LC_LINKER_OPTIMIZATION_HINT': LC_LINKER_OPTIMIZATION_HINT,
                'LC_VERSION_MIN_TVOS': LC_VERSION_MIN_TVOS,
                'LC_VERSION_MIN_WATCHOS': LC_VERSION_MIN_WATCHOS,
                'LC_NOTE': LC_NOTE,
                'LC_BUILD_VERSION': LC_BUILD_VERSION,
                'LC_DYLD_EXPORTS_TRIE': LC_DYLD_EXPORTS_TRIE,
                'LC_DYLD_CHAINED_FIXUPS': LC_DYLD_CHAINED_FIXUPS
            }

            def __init__(self, initial_value=0):
                dict_utils.Enum.__init__(self, initial_value, self.enum)

        def __init__(self, c=None, len=0, o=0):
            if c is not None:
                self.command = c
            else:
                self.command = Mach.LoadCommand.Command(0)
            self.length = len
            self.file_off = o

        def matches(self, rhs):
            lhs_val = self.command.get_enum_value()
            rhs_val = rhs.command.get_enum_value()
            return lhs_val == rhs_val

        def compare_attr(self, rhs, name):
            lhs_value = getattr(self, name)
            rhs_value = getattr(rhs, name)
            success = lhs_value == rhs_value
            if not success:
                print('error: %s differs %s != %s' % (name, str(lhs_value),
                                                      str(rhs_value)))
            return success

        def compare(self, mach_file, rhs, rhs_mach_file):
            # No custom compare for load commands, so lets compare the string
            # value without the leading file offset
            lhs_str = str(self)[10:]
            rhs_str = str(rhs)[10:]
            return lhs_str == rhs_str

        def get_item_dictionary(self):
            return {'#0': str(self.command),
                    'children':
                        callable(getattr(self, "get_child_item_dictionaries",
                                         None)),
                    'tree-item-delegate': self}

        def unpack(self, mach_file, data):
            self.file_off = data.tell()
            self.command.value, self.length = data.get_n_uint32(2)

        def skip(self, data):
            data.seek(self.file_off + self.length, 0)

        def __str__(self):
            lc_name = self.command.get_enum_name()
            return '%#8.8x: <%#4.4x> %-24s' % (self.file_off, self.length,
                                               lc_name)

    class Section:

        class Type(dict_utils.Enum):
            enum = {
                'S_REGULAR': S_REGULAR,
                'S_ZEROFILL': S_ZEROFILL,
                'S_CSTRING_LITERALS': S_CSTRING_LITERALS,
                'S_4BYTE_LITERALS': S_4BYTE_LITERALS,
                'S_8BYTE_LITERALS': S_8BYTE_LITERALS,
                'S_LITERAL_POINTERS': S_LITERAL_POINTERS,
                'S_NON_LAZY_SYMBOL_POINTERS': S_NON_LAZY_SYMBOL_POINTERS,
                'S_LAZY_SYMBOL_POINTERS': S_LAZY_SYMBOL_POINTERS,
                'S_SYMBOL_STUBS': S_SYMBOL_STUBS,
                'S_MOD_INIT_FUNC_POINTERS': S_MOD_INIT_FUNC_POINTERS,
                'S_MOD_TERM_FUNC_POINTERS': S_MOD_TERM_FUNC_POINTERS,
                'S_COALESCED': S_COALESCED,
                'S_GB_ZEROFILL': S_GB_ZEROFILL,
                'S_INTERPOSING': S_INTERPOSING,
                'S_16BYTE_LITERALS': S_16BYTE_LITERALS,
                'S_DTRACE_DOF': S_DTRACE_DOF,
                'S_LAZY_DYLIB_SYMBOL_POINTERS': S_LAZY_DYLIB_SYMBOL_POINTERS,
                'S_THREAD_LOCAL_REGULAR': S_THREAD_LOCAL_REGULAR,
                'S_THREAD_LOCAL_ZEROFILL': S_THREAD_LOCAL_ZEROFILL,
                'S_THREAD_LOCAL_VARIABLES': S_THREAD_LOCAL_VARIABLES,
                'S_THREAD_LOCAL_VARIABLE_POINTERS':
                    S_THREAD_LOCAL_VARIABLE_POINTERS,
                'S_THREAD_LOCAL_INIT_FUNCTION_POINTERS':
                    S_THREAD_LOCAL_INIT_FUNCTION_POINTERS
            }

            def __init__(self, t=0):
                dict_utils.Enum.__init__(self, t, self.enum)

        def __init__(self):
            self.file_offset = 0
            self.index = 0
            self.is_64 = False
            self.sectname = None
            self.segname = None
            self.addr = 0
            self.size = 0
            self.offset = 0
            self.align = 0
            self.reloff = 0
            self.nreloc = 0
            self.flags = 0
            self.reserved1 = 0
            self.reserved2 = 0
            self.reserved3 = 0

        def addr_to_file_offset(self, addr):
            if addr >= self.addr and addr < self.addr + self.size:
                return self.offset + addr - self.addr
            return None

        def get_item_dictionary(self):
            summary = None
            if self.size:
                summary = address_range_to_str(self.addr,
                                               self.addr + self.size,
                                               self.is_64)
            if summary:
                summary = summary + ' ' + self.get_type_as_string()
            else:
                summary = self.get_type_as_string()

            return {'#0': str(self.index),
                    'value': self.sectname,
                    'summary': summary,
                    'children': True,
                    'tree-item-delegate': self}

        def contains_code(self):
            if self.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS):
                return True
            return False

        def get_type_as_string(self):
            return str(Mach.Section.Type(self.flags & SECTION_TYPE))

        def get_attributes_as_string(self):
            attrs = []
            if self.flags & S_ATTR_PURE_INSTRUCTIONS:
                attrs.append('S_ATTR_PURE_INSTRUCTIONS')
            if self.flags & S_ATTR_NO_TOC:
                attrs.append('S_ATTR_NO_TOC')
            if self.flags & S_ATTR_STRIP_STATIC_SYMS:
                attrs.append('S_ATTR_STRIP_STATIC_SYMS')
            if self.flags & S_ATTR_NO_DEAD_STRIP:
                attrs.append('S_ATTR_NO_DEAD_STRIP')
            if self.flags & S_ATTR_LIVE_SUPPORT:
                attrs.append('S_ATTR_LIVE_SUPPORT')
            if self.flags & S_ATTR_SELF_MODIFYING_CODE:
                attrs.append('S_ATTR_SELF_MODIFYING_CODE')
            if self.flags & S_ATTR_DEBUG:
                attrs.append('S_ATTR_DEBUG')
            if self.flags & S_ATTR_SOME_INSTRUCTIONS:
                attrs.append('S_ATTR_SOME_INSTRUCTIONS')
            if self.flags & S_ATTR_EXT_RELOC:
                attrs.append('S_ATTR_EXT_RELOC')
            if self.flags & S_ATTR_LOC_RELOC:
                attrs.append('S_ATTR_LOC_RELOC')
            return ' | '.join(attrs)

        def get_flags_as_string(self):
            type_str = self.get_type_as_string()
            attr_str = self.get_attributes_as_string()
            if len(attr_str):
                return 'type = ' + type_str + ', attrs = ' + attr_str
            else:
                return 'type = ' + type_str

        def get_child_item_dictionaries(self):
            item_dicts = []
            item_dicts.append({'#0': 'sectname', 'value': self.sectname})
            item_dicts.append({'#0': 'segname', 'value': self.segname})
            item_dicts.append({'#0': 'addr',
                               'value': address_to_str(self.addr, self.is_64)})
            item_dicts.append({'#0': 'size',
                               'value': address_to_str(self.size, self.is_64),
                               'summary': str(self.size)})
            item_dicts.append({'#0': 'offset',
                               'value': int_to_hex32(self.offset)})
            item_dicts.append({'#0': 'align',
                               'value': int_to_hex32(self.align),
                               'summary': str(self.align)})
            item_dicts.append({'#0': 'reloff',
                               'value': int_to_hex32(self.reloff)})
            item_dicts.append({'#0': 'nreloc',
                               'value': int_to_hex32(self.nreloc),
                               'summary': str(self.nreloc)})
            item_dicts.append({'#0': 'flags',
                               'value': int_to_hex32(self.flags),
                               'summary': self.get_flags_as_string()})
            item_dicts.append({'#0': 'reserved1',
                               'value': int_to_hex32(self.reserved1),
                               'summary': str(self.reserved1)})
            item_dicts.append({'#0': 'reserved2',
                               'value': int_to_hex32(self.reserved2),
                               'summary': str(self.reserved2)})
            if self.is_64:
                item_dicts.append({
                    '#0': 'reserved3',
                    'value': int_to_hex32(self.reserved3),
                    'summary': str(self.reserved3)})
            return item_dicts

        def unpack(self, is_64, data):
            self.file_offset = data.tell()
            self.is_64 = is_64
            self.sectname = data.get_fixed_length_c_string(16)
            self.segname = data.get_fixed_length_c_string(16)
            if self.is_64:
                self.addr, self.size = data.get_n_uint64(2)
                (self.offset, self.align, self.reloff, self.nreloc, self.flags,
                 self.reserved1, self.reserved2,
                 self.reserved3) = data.get_n_uint32(8)
            else:
                self.addr, self.size = data.get_n_uint32(2)
                (self.offset, self.align, self.reloff, self.nreloc, self.flags,
                 self.reserved1, self.reserved2) = data.get_n_uint32(7)

        def dump_header(self):
            if self.is_64:
                print("FILE OFF    INDEX ADDRESS            "
                      "SIZE               OFFSET     ALIGN      RELOFF     "
                      "NRELOC     FLAGS      RESERVED1  RESERVED2  RESERVED3  "
                      "NAME")
                print("=========== ===== ------------------ "
                      "------------------ ---------- ---------- ---------- "
                      "---------- ---------- ---------- ---------- ---------- "
                      "----------------------")
            else:
                print("FILE OFF    INDEX ADDRESS    SIZE       OFFSET     "
                      "ALIGN      RELOFF     NRELOC     FLAGS      RESERVED1  "
                      "RESERVED2  NAME")
                print("=========== ===== ---------- ---------- ---------- "
                      "---------- ---------- ---------- ---------- ---------- "
                      "---------- ----------------------")

        def __str__(self):
            if self.is_64:
                return ("0x%8.8x: [%3u] %#16.16x %#16.16x %#8.8x %#8.8x "
                        "%#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %s.%s") % (
                            self.file_offset, self.index, self.addr, self.size,
                            self.offset, self.align, self.reloff, self.nreloc,
                            self.flags, self.reserved1, self.reserved2,
                            self.reserved3, self.segname, self.sectname)
            else:
                return ("0x%8.8x: [%3u] %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x "
                        "%#8.8x %#8.8x %#8.8x %#8.8x %s.%s") % (
                            self.file_offset, self.index, self.addr, self.size,
                            self.offset, self.align, self.reloff, self.nreloc,
                            self.flags, self.reserved1, self.reserved2,
                            self.segname, self.sectname)

        def get_contents(self, mach_file):
            '''Get the section contents as a python string'''
            if (self.size > 0 and
                    mach_file.get_segment(self.segname).filesize > 0):
                data = mach_file.get_data()
                if data:
                    section_data_offset = mach_file.file_off + self.offset
                    data.push_offset_and_seek(section_data_offset)
                    bytes = data.read_size(self.size)
                    data.pop_offset_and_seek()
                    return bytes
            return None

        def get_contents_as_extractor(self, mach_file):
            bytes = self.get_contents(mach_file)
            if self.is_64:
                addr_size = 8
            else:
                addr_size = 4
            return file_extract.FileExtract(io.BytesIO(bytes),
                                            mach_file.get_byte_order(),
                                            addr_size)

    class DylibLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.name = None
            self.timestamp = 0
            self.current_version = 0
            self.compatibility_version = 0

        def unpack(self, mach_file, data):
            mach_file.get_byte_order()
            (name_offset, self.timestamp, self.current_version,
             self.compatibility_version) = data.get_n_uint32(4)
            data.seek(self.file_off + name_offset, 0)
            self.name = data.get_fixed_length_c_string(self.length - 24)

        def get_item_dictionary(self):
            item_dict = Mach.LoadCommand.get_item_dictionary(self)
            item_dict['summary'] = self.name
            return item_dict

        def get_child_item_dictionaries(self):
            item_dicts = []
            item_dicts.append({'#0': 'name', 'value': self.name})
            item_dicts.append({'#0': 'timestamp',
                               'value': int_to_hex32(self.timestamp)})
            item_dicts.append({
                '#0': 'current_version',
                'value': get_version32_as_string(self.current_version)})
            item_dicts.append({
                '#0': 'compatibility_version',
                'value': get_version32_as_string(self.compatibility_version)})
            return item_dicts

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += "timestamp = %#8.8x, " % (self.timestamp)
            s += "current_version = %10s, " % (
                get_version32_as_string(self.current_version))
            s += "compatibility_version = %10s, name = '" % (
                get_version32_as_string(self.compatibility_version))
            s += self.name + "'"
            return s

    class LoadDYLDLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.name = None

        def unpack(self, mach_file, data):
            data.get_uint32()
            self.name = data.get_fixed_length_c_string(self.length - 12)

        def get_item_dictionary(self):
            item_dict = Mach.LoadCommand.get_item_dictionary(self)
            item_dict['summary'] = self.name
            return item_dict

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += "%s" % self.name
            return s

    class UnixThreadLoadCommand(LoadCommand):
        class ThreadState:
            def __init__(self):
                self.flavor = 0
                self.count = 0
                self.register_values = []

            def unpack(self, data):
                self.flavor, self.count = data.get_n_uint32(2)
                self.register_values = data.get_n_uint32(self.count)

            def __str__(self):
                s = "flavor = %u, count = %u, regs =" % (self.flavor,
                                                         self.count)
                i = 0
                for register_value in self.register_values:
                    if i % 8 == 0:
                        s += "\n                                            "
                    s += " %#8.8x" % register_value
                    i += 1
                return s

        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.reg_sets = []

        def unpack(self, mach_file, data):
            reg_set = Mach.UnixThreadLoadCommand.ThreadState()
            reg_set.unpack(data)
            self.reg_sets.append(reg_set)

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            for reg_set in self.reg_sets:
                s += "%s" % reg_set
            return s

    class DYLDInfoOnlyLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.rebase_off = 0
            self.rebase_size = 0
            self.bind_off = 0
            self.bind_size = 0
            self.weak_bind_off = 0
            self.weak_bind_size = 0
            self.lazy_bind_off = 0
            self.lazy_bind_size = 0
            self.export_off = 0
            self.export_size = 0

        def get_rebase_bytes(self, mach_file):
            if self.rebase_size == 0:
                return ''
            return mach_file.get_bytes(self.rebase_off, self.rebase_size)

        def get_bind_bytes(self, mach_file):
            if self.bind_size == 0:
                return ''
            return mach_file.get_bytes(self.bind_off, self.bind_size)

        def get_weak_bind_bytes(self, mach_file):
            if self.weak_bind_size == 0:
                return ''
            return mach_file.get_bytes(self.weak_bind_off, self.weak_bind_size)

        def get_lazy_bind_bytes(self, mach_file):
            if self.lazy_bind_size == 0:
                return ''
            return mach_file.get_bytes(self.lazy_bind_off, self.lazy_bind_size)

        def get_export_bytes(self, mach_file):
            if self.export_size == 0:
                return ''
            return mach_file.get_bytes(self.export_off, self.export_size)

        def compare(self, mach_file, rhs, rhs_mach_file):
            success = True
            if (self.get_rebase_bytes(mach_file) !=
                    rhs.get_rebase_bytes(rhs_mach_file)):
                print('error: rebase bytes differ')
                success = False
            if (self.get_bind_bytes(mach_file) !=
                    rhs.get_bind_bytes(rhs_mach_file)):
                print('error: bind bytes differ')
                success = False
            if (self.get_weak_bind_bytes(mach_file) !=
                    rhs.get_weak_bind_bytes(rhs_mach_file)):
                print('error: weak bind bytes differ')
                success = False
            if (self.get_lazy_bind_bytes(mach_file) !=
                    rhs.get_lazy_bind_bytes(rhs_mach_file)):
                print('error: lazy bind bytes differ')
                success = False
            if (self.get_export_bytes(mach_file) !=
                    rhs.get_export_bytes(rhs_mach_file)):
                print('error: export bytes differ')
                success = False
            return success

        def unpack(self, mach_file, data):
            mach_file.get_byte_order()
            (self.rebase_off, self.rebase_size, self.bind_off, self.bind_size,
             self.weak_bind_off, self.weak_bind_size, self.lazy_bind_off,
             self.lazy_bind_size, self.export_off,
             self.export_size) = data.get_n_uint32(10)

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += "rebase_off     = %#8.8x, rebase_size    = %u\n" % (
                self.rebase_off, self.rebase_size)
            s += "                                             "
            s += "bind_off       = %#8.8x, bind_size      = %u\n" % (
                self.bind_off, self.bind_size)
            s += "                                             "
            s += "weak_bind_off  = %#8.8x, weak_bind_size = %u\n" % (
                self.weak_bind_off, self.weak_bind_size)
            s += "                                             "
            s += "lazy_bind_off  = %#8.8x, lazy_bind_size = %u\n" % (
                self.lazy_bind_off, self.lazy_bind_size)
            s += "                                             "
            s += "export_off     = %#8.8x, export_size    = %u" % (
                self.export_off, self.export_size)
            return s

    class DYLDSymtabLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.ilocalsym = 0
            self.nlocalsym = 0
            self.iextdefsym = 0
            self.nextdefsym = 0
            self.iundefsym = 0
            self.nundefsym = 0
            self.tocoff = 0
            self.ntoc = 0
            self.modtaboff = 0
            self.nmodtab = 0
            self.extrefsymoff = 0
            self.nextrefsyms = 0
            self.indirectsymoff = 0
            self.nindirectsyms = 0
            self.extreloff = 0
            self.nextrel = 0
            self.locreloff = 0
            self.nlocrel = 0

        def compare(self, mach_file, rhs, rhs_mach_file):
            success = True
            if not self.compare_attr(rhs, 'ilocalsym'):
                success = False
            if not self.compare_attr(rhs, 'nlocalsym'):
                success = False
            if not self.compare_attr(rhs, 'iextdefsym'):
                success = False
            if not self.compare_attr(rhs, 'nextdefsym'):
                success = False
            if not self.compare_attr(rhs, 'iundefsym'):
                success = False
            if not self.compare_attr(rhs, 'nundefsym'):
                success = False
            return success

        def unpack(self, mach_file, data):
            mach_file.get_byte_order()
            (self.ilocalsym, self.nlocalsym, self.iextdefsym, self.nextdefsym,
             self.iundefsym, self.nundefsym, self.tocoff, self.ntoc,
             self.modtaboff, self.nmodtab, self.extrefsymoff, self.nextrefsyms,
             self.indirectsymoff, self.nindirectsyms, self.extreloff,
             self.nextrel, self.locreloff,
             self.nlocrel) = data.get_n_uint32(18)

        def get_child_item_dictionaries(self):
            item_dicts = []
            item_dicts.append({'#0': 'ilocalsym',
                               'value': str(self.ilocalsym)})
            item_dicts.append({'#0': 'nlocalsym',
                               'value': str(self.nlocalsym)})
            item_dicts.append({'#0': 'iextdefsym',
                               'value': str(self.iextdefsym)})
            item_dicts.append({'#0': 'nextdefsym',
                               'value': str(self.nextdefsym)})
            item_dicts.append({'#0': 'iundefsym',
                               'value': str(self.iundefsym)})
            item_dicts.append({'#0': 'nundefsym',
                               'value': str(self.nundefsym)})
            item_dicts.append({'#0': 'tocoff',
                               'value': str(self.tocoff)})
            item_dicts.append({'#0': 'ntoc',
                               'value': str(self.ntoc)})
            item_dicts.append({'#0': 'modtaboff',
                               'value': int_to_hex32(self.modtaboff)})
            item_dicts.append({'#0': 'nmodtab',
                               'value': str(self.nmodtab)})
            item_dicts.append({'#0': 'extrefsymoff',
                               'value': int_to_hex32(self.extrefsymoff)})
            item_dicts.append({'#0': 'nextrefsyms',
                               'value': str(self.nextrefsyms)})
            item_dicts.append({'#0': 'indirectsymoff',
                               'value': int_to_hex32(self.indirectsymoff)})
            item_dicts.append({'#0': 'nindirectsyms',
                               'value': str(self.nindirectsyms)})
            item_dicts.append({'#0': 'extreloff',
                               'value': int_to_hex32(self.extreloff)})
            item_dicts.append({'#0': 'nextrel',
                               'value': str(self.nextrel)})
            item_dicts.append({'#0': 'locreloff',
                               'value': int_to_hex32(self.locreloff)})
            item_dicts.append({'#0': 'nlocrel',
                               'value': str(self.nlocrel)})
            return item_dicts

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += "ilocalsym      = %-10u, nlocalsym      = %u\n" % (
                self.ilocalsym, self.nlocalsym)
            s += "                                             "
            s += "iextdefsym     = %-10u, nextdefsym     = %u\n" % (
                self.iextdefsym, self.nextdefsym)
            s += "                                             "
            s += "iundefsym      = %-10u, nundefsym      = %u\n" % (
                self.iundefsym, self.nundefsym)
            s += "                                             "
            s += "tocoff         = %#8.8x, ntoc           = %u\n" % (
                self.tocoff, self.ntoc)
            s += "                                             "
            s += "modtaboff      = %#8.8x, nmodtab        = %u\n" % (
                self.modtaboff, self.nmodtab)
            s += "                                             "
            s += "extrefsymoff   = %#8.8x, nextrefsyms    = %u\n" % (
                self.extrefsymoff, self.nextrefsyms)
            s += "                                             "
            s += "indirectsymoff = %#8.8x, nindirectsyms  = %u\n" % (
                self.indirectsymoff, self.nindirectsyms)
            s += "                                             "
            s += "extreloff      = %#8.8x, nextrel        = %u\n" % (
                self.extreloff, self.nextrel)
            s += "                                             "
            s += "locreloff      = %#8.8x, nlocrel        = %u" % (
                self.locreloff, self.nlocrel)
            return s

    class SymtabLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.symoff = 0
            self.nsyms = 0
            self.stroff = 0
            self.strsize = 0

        def get_item_dictionary(self):
            item_dict = Mach.LoadCommand.get_item_dictionary(self)
            item_dict['summary'] = "%u symbols" % (self.nsyms)
            return item_dict

        def get_symtab_bytes(self, mach_file):
            if mach_file.is_64_bit():
                symbol_byte_size = 16
            else:
                symbol_byte_size = 12
            if self.nsyms > 0:
                return mach_file.get_bytes(self.symoff,
                                           self.nsyms * symbol_byte_size)
            return None

        def get_strtab_bytes(self, mach_file):
            if self.strsize > 0:
                return mach_file.get_bytes(self.stroff, self.strsize)
            return None

        def get_strtab_data(self, mach_file):
            if self.strsize > 0:
                return mach_file.get_data_slice(self.stroff, self.strsize)
            return None

        def compare(self, mach_file, rhs, rhs_mach_file):
            success = True
            if self.nsyms != rhs.nsyms:
                print('error: nsyms differs %u != %u' % (self.nsyms,
                                                         rhs.nsyms))
                success = False
            lhs_bytes = self.get_strtab_bytes(mach_file)
            rhs_bytes = rhs.get_strtab_bytes(rhs_mach_file)
            if lhs_bytes != rhs_bytes:
                dump_memory(0, lhs_bytes, 16, sys.stdout)
                dump_memory(0, rhs_bytes, 16, sys.stdout)
                print('error: string tables differ')
                success = False
            return success

        def get_child_item_dictionaries(self):
            item_dicts = []
            item_dicts.append({'#0': 'symoff',
                               'value': int_to_hex32(self.symoff)})
            item_dicts.append({'#0': 'nsyms',
                               'value': int_to_hex32(self.nsyms),
                               'summary': str(self.nsyms)})
            item_dicts.append({'#0': 'stroff',
                               'value': int_to_hex32(self.stroff)})
            item_dicts.append({'#0': 'strsize',
                               'value': int_to_hex32(self.strsize),
                               'summary': str(self.strsize)})
            return item_dicts

        def unpack(self, mach_file, data):
            mach_file.get_byte_order()
            (self.symoff, self.nsyms, self.stroff,
             self.strsize) = data.get_n_uint32(4)

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += "symoff         = %#8.8x, nsyms          = %u\n" % (
                self.symoff, self.nsyms)
            s += "                                             "
            s += "stroff         = %#8.8x, strsize        = %u" % (
                self.stroff, self.strsize)
            return s

    class UUIDLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.uuid = None

        def get_item_dictionary(self):
            item_dict = Mach.LoadCommand.get_item_dictionary(self)
            item_dict['summary'] = self.uuid.__str__().upper()
            return item_dict

        def unpack(self, mach_file, data):
            uuid_data = data.get_n_uint8(16)
            uuid_str = ''
            for byte in uuid_data:
                uuid_str += '%2.2x' % byte
            self.uuid = uuid.UUID(uuid_str)
            mach_file.uuid = self.uuid

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += self.uuid.__str__().upper()
            return s

    class DataBlobLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.dataoff = 0
            self.datasize = 0
            self.data = None

        def get_child_item_dictionaries(self):
            item_dicts = []
            item_dicts.append({'#0': 'dataoff',
                               'value': int_to_hex32(self.dataoff)})
            item_dicts.append({'#0': 'datasize',
                               'value': int_to_hex32(self.datasize),
                               'summary': str(self.datasize)})
            return item_dicts

        def compare(self, mach_file, rhs, rhs_mach_file):
            success = True
            lhs_bytes = mach_file.get_bytes(self.dataoff, self.datasize)
            rhs_bytes = rhs_mach_file.get_bytes(rhs.dataoff, rhs.datasize)
            if lhs_bytes != rhs_bytes:
                print('error: data mismatch')
                success = False
            return success

        def unpack(self, mach_file, data):
            mach_file.get_byte_order()
            self.dataoff, self.datasize = data.get_n_uint32(2)
            if self.datasize > 0:
                data.seek(self.dataoff, 0)
                self.data = data.read_size(self.datasize)

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += "dataoff = %#8.8x, datasize = %#8.8x (%u)" % (
                self.dataoff, self.datasize, self.datasize)
            return s

    class EncryptionInfoLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.cryptoff = 0
            self.cryptsize = 0
            self.cryptid = 0

        def unpack(self, mach_file, data):
            mach_file.get_byte_order()
            self.cryptoff, self.cryptsize, self.cryptid = data.get_n_uint32(3)

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += "file-range = [%#8.8x - %#8.8x), " % (
                self.cryptoff, self.cryptoff + self.cryptsize)
            s += "cryptsize = %u, cryptid = %u" % (
                self.cryptsize, self.cryptid)
            return s

    class SegmentLoadCommand(LoadCommand):

        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.segname = None
            self.vmaddr = 0
            self.vmsize = 0
            self.fileoff = 0
            self.filesize = 0
            self.maxprot = 0
            self.initprot = 0
            self.nsects = 0
            self.flags = 0
            self.sections = []
            self.section_delegate = None

        def find_section(self, sectname):
            for sect in self.sections:
                if sect.sectname == sectname:
                    return sect
            return None

        def get_item_dictionary(self):
            item_dict = Mach.LoadCommand.get_item_dictionary(self)
            item_dict['value'] = self.segname
            is_64 = self.is_64()
            if is_64:
                item_dict['summary'] = "[0x%16.16x - 0x%16.16x) %s" % (
                    self.vmaddr, self.vmaddr + self.vmsize,
                    vm_prot_names[self.initprot])
            else:
                item_dict['summary'] = "[0x%8.8x - 0x%8.8x) %s" % (
                    self.vmaddr, self.vmaddr + self.vmsize,
                    vm_prot_names[self.initprot])
            return item_dict

        def matches(self, rhs):
            if self.is_64() == rhs.is_64() and self.segname == rhs.segname:
                return True
            return False

        def compare(self, mach_file, rhs, rhs_mach_file):
            success = True
            if self.segname != rhs.segname:
                print('error: segment name mismatch')
                success = False
            if self.vmaddr != rhs.vmaddr:
                print('error: vmaddr mismatch')
                success = False
            if self.vmsize != rhs.vmsize:
                print('error: vmsize mismatch')
                success = False
            if self.fileoff != rhs.fileoff:
                print('error: fileoff mismatch')
                success = False
            if self.filesize != rhs.filesize:
                print('error: filesize mismatch')
                success = False
            if self.maxprot != rhs.maxprot:
                print('error: maxprot mismatch')
                success = False
            if self.initprot != rhs.initprot:
                print('error: initprot mismatch')
                success = False
            if self.nsects != rhs.nsects:
                print('error: nsects mismatch')
                success = False
            if self.flags != rhs.flags:
                print('error: flags mismatch')
                success = False
            return success

        def get_child_item_dictionaries(self):
            is_64 = self.is_64()

            item_dicts = []
            if len(self.sections) > 0:
                if self.section_delegate is None:
                    self.section_delegate = SectionListTreeItemDelegate(
                        self.sections, False)
                item_dicts.append(self.section_delegate.get_item_dictionary())
            item_dicts.append({'#0': 'segname',    'value': self.segname})
            if is_64:
                item_dicts.append({'#0': 'vmaddr',
                                   'value': int_to_hex64(self.vmaddr)})
                item_dicts.append({'#0': 'vmsize',
                                   'value': int_to_hex64(self.vmsize),
                                   'summary': str(self.vmsize)})
                item_dicts.append({'#0': 'fileoff',
                                   'value': int_to_hex64(self.fileoff)})
                item_dicts.append({'#0': 'filesize',
                                   'value': int_to_hex64(self.filesize),
                                   'summary': str(self.filesize)})
            else:
                item_dicts.append({'#0': 'vmaddr',
                                   'value': int_to_hex32(self.vmaddr)})
                item_dicts.append({'#0': 'vmsize',
                                   'value': int_to_hex32(self.vmsize),
                                   'summary': str(self.vmsize)})
                item_dicts.append({'#0': 'fileoff',
                                   'value': int_to_hex32(self.fileoff)})
                item_dicts.append({'#0': 'filesize',
                                   'value': int_to_hex32(self.filesize),
                                   'summary': str(self.filesize)})
            item_dicts.append({'#0': 'maxprot',
                               'value': int_to_hex32(self.maxprot),
                               'summary': "%s" % (
                                    vm_prot_names[self.maxprot])})
            item_dicts.append({'#0': 'initprot',
                               'value': int_to_hex32(self.initprot),
                               'summary': "%s" % (
                                    vm_prot_names[self.initprot])})
            item_dicts.append({'#0': 'nsects',
                               'value': int_to_hex32(self.nsects),
                               'summary': str(self.nsects)})
            item_dicts.append({'#0': 'flags',
                               'value': int_to_hex32(self.flags),
                               'summary': self.get_flags_as_string()})
            return item_dicts

        def is_64(self):
            return self.command.get_enum_value() == LC_SEGMENT_64

        def unpack(self, mach_file, data):
            is_64 = self.is_64()
            self.segname = data.get_fixed_length_c_string(16)
            if is_64:
                (self.vmaddr, self.vmsize, self.fileoff,
                 self.filesize) = data.get_n_uint64(4)
            else:
                (self.vmaddr, self.vmsize, self.fileoff,
                 self.filesize) = data.get_n_uint32(4)
            (self.maxprot, self.initprot, self.nsects,
             self.flags) = data.get_n_uint32(4)
            mach_file.segments.append(self)
            for i in range(self.nsects):
                section = Mach.Section()
                section.unpack(is_64, data)
                section.index = len(mach_file.sections)
                mach_file.sections.append(section)
                self.sections.append(section)

        def get_flags_as_string(self):
            flag_strings = []
            if self.flags & SG_HIGHVM:
                flag_strings.append('SG_HIGHVM')
            if self.flags & SG_FVMLIB:
                flag_strings.append('SG_HIGHVM')
            if self.flags & SG_NORELOC:
                flag_strings.append('SG_HIGHVM')
            if self.flags & SG_PROTECTED_VERSION_1:
                flag_strings.append('SG_HIGHVM')
            if len(flag_strings):
                return ' | '.join(flag_strings)
            else:
                return ''

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            if self.command.get_enum_value() == LC_SEGMENT:
                s += "%#8.8x %#8.8x %#8.8x %#8.8x " % (
                    self.vmaddr, self.vmsize, self.fileoff, self.filesize)
            else:
                s += "%#16.16x %#16.16x %#16.16x %#16.16x " % (
                    self.vmaddr, self.vmsize, self.fileoff, self.filesize)
            s += "%s %s %3u %#8.8x" % (vm_prot_names[self.maxprot],
                                       vm_prot_names[self.initprot],
                                       self.nsects, self.flags)
            s += ' ' + self.segname
            return s

    class VersionMinLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.version = 0
            self.sdk = 0

        def get_item_dictionary(self):
            item_dict = Mach.LoadCommand.get_item_dictionary(self)
            item_dict['summary'] = "version = %s, sdk = %s" % (
                get_version32_as_string(self.version),
                get_version32_as_string(self.sdk))
            return item_dict

        def unpack(self, mach_file, data):
            self.version, self.sdk = data.get_n_uint32(2)

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += "version = %s, sdk = %s" % (
                get_version32_as_string(self.version),
                get_version32_as_string(self.sdk))
            return s

    class BuildVersionLoadCommand(LoadCommand):
        class Platform(dict_utils.Enum):
            enum = {
                'PLATFORM_MACOS': PLATFORM_MACOS,
                'PLATFORM_IOS': PLATFORM_IOS,
                'PLATFORM_TVOS': PLATFORM_TVOS,
                'PLATFORM_WATCHOS': PLATFORM_WATCHOS,
                'PLATFORM_BRIDGEOS': PLATFORM_BRIDGEOS,
                'PLATFORM_MACCATALYST': PLATFORM_MACCATALYST,
                'PLATFORM_IOSSIMULATOR': PLATFORM_IOSSIMULATOR,
                'PLATFORM_TVOSSIMULATOR': PLATFORM_TVOSSIMULATOR,
                'PLATFORM_WATCHOSSIMULATOR': PLATFORM_WATCHOSSIMULATOR,
                'PLATFORM_DRIVERKIT': PLATFORM_DRIVERKIT,
            }

            def __init__(self, value=0):
                dict_utils.Enum.__init__(self, value, self.enum)

        class Tool(dict_utils.Enum):
            enum = {
                'TOOL_CLANG': TOOL_CLANG,
                'TOOL_SWIFT': TOOL_SWIFT,
                'TOOL_LD': TOOL_LD,
            }

            def __init__(self, value=0):
                dict_utils.Enum.__init__(self, value, self.enum)

        class BuildToolVersion:
            def __init__(self, t, v):
                self.tool = t
                self.version = v

            @classmethod
            def unpack(cls, mach_file, data):
                tool, version = data.get_n_uint32(2)
                return cls(Mach.BuildVersionLoadCommand.Tool(tool), version)

            def __str__(self):
                return "tool = %s, version = %s" % (self.tool,
                        get_version32_as_string(self.version))

        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.platform = self.Platform(PLATFORM_INVALID)
            self.minos = 0      # X.Y.Z is in uint32_t nibbles xxxx.yy.zz
            self.sdk = 0        # X.Y.Z is in uint32_t nibbles xxxx.yy.zz
            self.ntools = 0
            self.tools = []

        def unpack(self, mach_file, data):
            platform, self.minos, self.sdk, self.ntools = data.get_n_uint32(4)
            self.platform = self.Platform(platform)
            for i in range(self.ntools):
                self.tools.append(self.BuildToolVersion.unpack(mach_file, data))

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += "platform = %s, minos = %s, sdk = %s, ntools = %u" % (
                str(self.platform),
                get_version32_as_string(self.minos),
                get_version32_as_string(self.sdk),
                self.ntools)
            for tool in self.tools:
                s += "\n                                             "
                s += str(tool)
            return s

    class SourceVersionLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.version = 0

        def get_item_dictionary(self):
            item_dict = Mach.LoadCommand.get_item_dictionary(self)
            v = self.version
            item_dict['summary'] = "version = %u.%u.%u.%u.%u" % (
                (v >> 40) & 0xFFFFFFFFFF,
                (v >> 30) & 0x3ff,
                (v >> 20) & 0x3ff,
                (v >> 10) & 0x3ff,
                v & 0x3ff)
            return item_dict

        def unpack(self, mach_file, data):
            self.version = data.get_uint64()

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            v = self.version
            s += "version = %u.%u.%u.%u.%u" % (
                (v >> 40) & 0xFFFFFFFFFF,
                (v >> 30) & 0x3ff,
                (v >> 20) & 0x3ff,
                (v >> 10) & 0x3ff,
                v & 0x3ff)
            return s

    class LinkerOptionLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.options = []

        def unpack(self, mach_file, data):
            num_options = data.get_uint32()
            for i in range(num_options):
                self.options.append(data.get_c_string())

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            for opt in self.options:
                s += '"%s" ' % (opt)
            return s

    class MainLoadCommand(LoadCommand):
        def __init__(self, lc):
            Mach.LoadCommand.__init__(self, lc.command, lc.length, lc.file_off)
            self.entryoff = 0
            self.stacksize = 0

        def unpack(self, mach_file, data):
            self.entryoff, self.stacksize = data.get_n_uint64(2)

        def __str__(self):
            s = Mach.LoadCommand.__str__(self)
            s += "entryoff = %#8.8x, stacksize = %u" % (
                self.entryoff, self.stacksize)
            return s

    class NList:
        class Type:

            def __init__(self, t=0):
                self.value = t

            def sect_idx_is_section_index(self):
                if self.is_stab():
                    return False
                return (self.value & N_TYPE) == N_SECT

            def is_stab(self):
                return (self.value & N_STAB) != 0

            def is_stab_with_type(self, stab_type):
                if not self.is_stab():
                    return False
                return self.value == stab_type

            def get_type_as_string(self):
                n_type = self.value
                if self.is_stab():
                    return str(Stab(self.value))
                else:
                    type = self.value & N_TYPE
                    if type == N_UNDF:
                        return 'N_UNDF'
                    elif type == N_ABS:
                        return 'N_ABS '
                    elif type == N_SECT:
                        return 'N_SECT'
                    elif type == N_PBUD:
                        return 'N_PBUD'
                    elif type == N_INDR:
                        return 'N_INDR'
                    else:
                        return "??? (%#2.2x)" % type

            def get_flags_as_string(self):
                n_type = self.value
                if not self.is_stab():
                    if n_type & N_PEXT:
                        if n_type & N_EXT:
                            return 'N_PEXT | N_EXT'
                        else:
                            return 'N_PEXT'
                    elif n_type & N_EXT:
                        return 'N_EXT'
                return ''

            def __str__(self):
                n_type = self.value
                if self.is_stab():
                    stab = Stab(self.value)
                    return '%s' % stab
                else:
                    type = self.value & N_TYPE
                    type_str = ''
                    if type == N_UNDF:
                        type_str = 'N_UNDF'
                    elif type == N_ABS:
                        type_str = 'N_ABS '
                    elif type == N_SECT:
                        type_str = 'N_SECT'
                    elif type == N_PBUD:
                        type_str = 'N_PBUD'
                    elif type == N_INDR:
                        type_str = 'N_INDR'
                    else:
                        type_str = "??? (%#2.2x)" % type
                    if n_type & N_PEXT:
                        type_str += ' | PEXT'
                    if n_type & N_EXT:
                        type_str += ' | EXT '
                    return type_str

        def __init__(self):
            self.index = 0
            self.name_offset = 0
            self.name = 0
            self.type = Mach.NList.Type()
            self.sect_idx = 0
            self.desc = 0
            self.value = 0

        def sect_idx_is_section_index(self):
            return self.type.sect_idx_is_section_index()

        def get_item_dictionary(self):
            item_dict = {'#0': str(self.index),
                         'name_offset': int_to_hex32(self.name_offset),
                         'type': self.type.get_type_as_string(),
                         'flags': self.type.get_flags_as_string(),
                         'sect_idx': self.sect_idx,
                         'desc': int_to_hex16(self.desc),
                         'value': int_to_hex64(self.value),
                         'tree-item-delegate': self}
            if self.name:
                item_dict['name'] = self.name
            return item_dict

        def unpack(self, mach_file, data, symtab_lc):
            self.index = len(mach_file.symbols)
            self.name_offset = data.get_uint32()
            self.type.value, self.sect_idx = data.get_n_uint8(2)
            self.desc = data.get_uint16()
            if mach_file.is_64_bit():
                self.value = data.get_uint64()
            else:
                self.value = data.get_uint32()
            self.name = mach_file.get_string(self.name_offset)

        def __str__(self):
            name_display = ''
            if len(self.name):
                name_display = ' "%s"' % self.name
            return '%#8.8x %#2.2x (%-20s) %#2.2x %#4.4x %16.16x%s' % (
                self.name_offset, self.type.value, self.type, self.sect_idx,
                self.desc, self.value, name_display)

    class Interactive(cmd.Cmd):
        '''Interactive command interpreter to mach-o files.'''

        def __init__(self, mach, options):
            cmd.Cmd.__init__(self)
            self.intro = 'Interactive mach-o command interpreter'
            self.prompt = 'mach-o: %s %% ' % mach.path
            self.mach = mach
            self.options = options

        def default(self, line):
            '''Catch all unknown commands, which will exit the interpreter.'''
            print("uknown command: %s" % line)
            return True

        def do_q(self, line):
            '''Quit command'''
            return True

        def do_quit(self, line):
            '''Quit command'''
            return True

        def do_header(self, line):
            '''Dump mach-o file headers'''
            self.mach.dump_header(True, self.options)
            return False

        def do_load(self, line):
            '''Dump all mach-o load commands'''
            self.mach.dump_load_commands(True, self.options)
            return False

        def do_sections(self, line):
            '''Dump all mach-o sections'''
            self.mach.dump_sections(True, self.options)
            return False

        def do_symtab(self, line):
            '''Dump all mach-o symbols in the symbol table'''
            self.mach.dump_symtab(True, self.options)
            return False

        def do_section(self, line):
            '''A command that dumps sections contents'''
            args = shlex.split(line)
            old_names = self.options.section_names
            self.options.section_names = args
            self.mach.dump_section_contents(self.options)
            self.options.section_names = old_names


# class ScrollText(Frame):
#     def __init__(self, parent):
#         Frame.__init__(self, parent)
#         self.parent = parent
#         self.createWidgets()

#     def createWidgets(self):

#         self.text = Text(self, wrap=NONE)

#         # Create scroll bars and bind them to the text view
#         self.v_scroll = Scrollbar(orient=VERTICAL, command=self.text.yview)
#         self.h_scroll = Scrollbar(orient=HORIZONTAL, command=self.text.xview)
#         self.text['yscroll'] = self.v_scroll.set
#         self.text['xscroll'] = self.h_scroll.set

#         # Place the text view and scroll bars into this frame Make sure the
#         # text view always resizes horizontally to take up all space
#         self.columnconfigure(0, weight=1)
#         # Make sure the text view always resizes vertically to take up all
#         # space
#         self.rowconfigure(0, weight=1)
#         self.text.grid(in_=self, row=0, column=0, sticky=NSEW)
#         self.v_scroll.grid(in_=self, row=0, column=1, rowspan=2, sticky=NS)
#         self.h_scroll.grid(in_=self, row=1, column=0, sticky=EW)

#     def setText(self, text):
#         pass
#         self.text.delete(1.0, END)
#         self.text.insert(END, text)


# class DelegateTree(Frame):

#     def __init__(self, parent, column_dicts, delegate):
#         Frame.__init__(self, parent)
#         self.sort_column_id = None
#         self.sort_type = 'string'
#         self.sort_direction = 1  # 0 = None, 1 = Ascending, 2 = Descending
#         self.pack(expand=Y, fill=BOTH)
#         self.delegate = delegate
#         self.column_dicts = column_dicts
#         self.item_id_to_item_dict = {}
#         frame = Frame(self)
#         frame.pack(side=TOP, fill=BOTH, expand=Y)
#         self._create_treeview(frame)
#         self._populate_root()

#     def _heading_clicked(self, column_id):
#         # Detect if we are clicking on the same column again?
#         reclicked = self.sort_column_id == column_id
#         self.sort_column_id = column_id
#         if reclicked:
#             self.sort_direction += 1
#             if self.sort_direction > 2:
#                 self.sort_direction = 0
#         else:
#             self.sort_direction = 1

#         matching_column_dict = None
#         for column_dict in self.column_dicts:
#             if column_dict['id'] == self.sort_column_id:
#                 matching_column_dict = column_dict
#                 break
#         new_sort_type = None
#         if matching_column_dict:
#             new_heading_text = ' ' + column_dict['text']
#             if self.sort_direction == 1:
#                 new_heading_text += ' ' + unichr(0x25BC).encode('utf8')
#             elif self.sort_direction == 2:
#                 new_heading_text += ' ' + unichr(0x25B2).encode('utf8')
#             self.tree.heading(column_id, text=new_heading_text)
#             if 'sort_type' in matching_column_dict:
#                 new_sort_type = matching_column_dict['sort_type']

#         if new_sort_type is None:
#             new_sort_type = 'string'
#         self.sort_type = new_sort_type
#         self.reload()

#     def _create_treeview(self, parent):
#         frame = Frame(parent)
#         frame.pack(side=TOP, fill=BOTH, expand=Y)

#         column_ids = []
#         for i in range(1, len(self.column_dicts)):
#             column_ids.append(self.column_dicts[i]['id'])
#         # create the tree and scrollbars
#         self.tree = Treeview(columns=column_ids)
#         self.tree.tag_configure('monospace', font=('Menlo', '12'))
#         scroll_bar_v = Scrollbar(orient=VERTICAL, command=self.tree.yview)
#         scroll_bar_h = Scrollbar(orient=HORIZONTAL, command=self.tree.xview)
#         self.tree['yscroll'] = scroll_bar_v.set
#         self.tree['xscroll'] = scroll_bar_h.set

#         # setup column headings and columns properties
#         for column_dict in self.column_dicts:
#             column_id = column_dict['id']
#             self.tree.heading(
#                 column_id, text=' ' + column_dict['text'],
#                 anchor=column_dict['anchor'],
#                 command=lambda c=column_id: self._heading_clicked(c))
#             if 'width' in column_dict:
#                 self.tree.column(
#                     column_id, stretch=column_dict['stretch'],
#                     width=column_dict['width'])
#             else:
#                 self.tree.column(column_id, stretch=column_dict['stretch'])

#         # add tree and scrollbars to frame
#         self.tree.grid(in_=frame, row=0, column=0, sticky=NSEW)
#         scroll_bar_v.grid(in_=frame, row=0, column=1, sticky=NS)
#         scroll_bar_h.grid(in_=frame, row=1, column=0, sticky=EW)

#         # set frame resizing priorities
#         frame.rowconfigure(0, weight=1)
#         frame.columnconfigure(0, weight=1)

#         # action to perform when a node is expanded
#         self.tree.bind('<<TreeviewOpen>>', self._update_tree)

#     def insert_items(self, parent_id, item_dicts):
#         for item_dict in item_dicts:
#             name = None
#             values = []
#             first = True
#             for column_dict in self.column_dicts:
#                 column_key = column_dict['id']
#                 if column_key in item_dict:
#                     column_value = item_dict[column_key]
#                 else:
#                     column_value = ''
#                 if first:
#                     name = column_value
#                     first = False
#                 else:
#                     values.append(column_value)
#             item_id = self.tree.insert(parent_id,  # root item has an no name
#                                        END, text=name, values=values,
#                                        tag='monospace')
#             self.item_id_to_item_dict[item_id] = item_dict
#             if 'children' in item_dict and item_dict['children']:
#                 self.tree.insert(item_id, END, text='dummy')

#     def _sort_item_dicts(self, item_dicts):
#         if self.sort_column_id is None or self.sort_direction == 0:
#             return item_dicts  # No sorting needs to happen
#         if self.sort_type == 'number':
#             return sorted(item_dicts, reverse=self.sort_direction == 2,
#                           key=lambda k, c=self.sort_column_id:
#                           int(k.get(c, 0), 0))
#         else:
#             return sorted(item_dicts, reverse=self.sort_direction == 2,
#                           key=lambda k, c=self.sort_column_id: k.get(c, ''))

#     def _populate_root(self):
#         # use current directory as root node
#         item_dicts = self._sort_item_dicts(
#             self.delegate.get_child_item_dictionaries())
#         self.insert_items('', item_dicts)

#     def _update_tree(self, event):
#         # user expanded a node - build the related directory
#         item_id = self.tree.focus()      # the id of the expanded node
#         children = self.tree.get_children(item_id)
#         if len(children):
#             first_child = children[0]
#             # if the node only has a 'dummy' child, remove it and
#             # build new directory skip if the node is already
#             # populated
#             if self.tree.item(first_child, option='text') == 'dummy':
#                 self.tree.delete(first_child)
#                 item_dict = self.item_id_to_item_dict[item_id]
#                 delegate = item_dict['tree-item-delegate']
#                 item_dicts = self._sort_item_dicts(
#                     delegate.get_child_item_dictionaries())
#                 self.insert_items(item_id, item_dicts)

#     def reload(self):
#         for item in self.tree.get_children():
#             self.tree.delete(item)
#         self._populate_root()


class LoadCommandTreeItemDelegate(object):
    def __init__(self, mach_frame):
        self.mach_frame = mach_frame

    def get_item_dictionary(self):
        name = "Load Commands"
        return {'#0': name,
                'value': '',
                'summary': '',
                'children': True,
                'tree-item-delegate': self}

    def get_child_item_dictionaries(self):
        item_dicts = []
        load_commands = self.mach_frame.selected_mach.commands
        for idx, lc in enumerate(load_commands):
            item_dicts.append(lc.get_item_dictionary())
        return item_dicts


class SectionListTreeItemDelegate(object):
    def __init__(self, sections, flat):
        self.sections = sections
        self.flat = flat

    def get_item_dictionary(self):
        return {'#0': 'sections',
                'value': '',
                'summary': '%u sections' % (len(self.sections)),
                'children': True,
                'tree-item-delegate': self}

    def get_child_item_dictionaries(self):
        item_dicts = []
        for section in self.sections:
            if self.flat:
                item_dict = {'#0': str(section.index),
                             'offset': int_to_hex32(section.offset),
                             'align': int_to_hex32(section.align),
                             'reloff': int_to_hex32(section.reloff),
                             'nreloc': int_to_hex32(section.nreloc),
                             'flags': section.get_flags_as_string(),
                             'type': section.get_type_as_string(),
                             'attrs': section.get_attributes_as_string(),
                             'reserved1': int_to_hex32(section.reserved1),
                             'reserved2': int_to_hex32(section.reserved2)}
                if section.sectname:
                    item_dict['sectname'] = section.sectname
                if section.segname:
                    item_dict['segname'] = section.segname
                item_dict['range'] = address_range_to_str(
                    section.addr, section.addr + section.size, section.is_64)
                item_dict['addr'] = address_to_str(section.addr, section.is_64)
                item_dict['size'] = address_to_str(section.size, section.is_64)
                if section.is_64:
                    item_dict['reserved3'] = int_to_hex32(section.reserved3)
                item_dicts.append(item_dict)
            else:
                item_dicts.append(section.get_item_dictionary())
        return item_dicts


class SymbolsTreeItemDelegate(object):
    def __init__(self, mach_frame):
        self.mach_frame = mach_frame

    def get_item_dictionary(self):
        return {'#0': 'symbols',
                'value': '',
                'summary': '%u symbols' % (len(self.symbols)),
                'children': True,
                'tree-item-delegate': self}

    def get_child_item_dictionaries(self):
        item_dicts = []
        mach = self.mach_frame.selected_mach
        symbols = mach.get_symtab()
        for nlist in symbols:
            item_dict = nlist.get_item_dictionary()
            sect_idx = item_dict['sect_idx']
            if nlist.sect_idx_is_section_index():
                section = self.mach_frame.selected_mach.sections[sect_idx]
                item_dict['sect'] = section.segname + '.' + section.sectname
            else:
                item_dict['sect'] = str(sect_idx)
            item_dicts.append(item_dict)
        return item_dicts


class DWARFDebugInfoTreeItemDelegate(object):
    def __init__(self, mach_frame):
        self.mach_frame = mach_frame

    def get_child_item_dictionaries(self):
        item_dicts = []
        mach = self.mach_frame.selected_mach
        dwarf = mach.get_dwarf()
        if dwarf:
            debug_info = dwarf.get_debug_info()
            cus = debug_info.get_dwarf_units()
            for cu in cus:
                item_dict = cu.get_die().get_item_dictionary()
                if item_dict:
                    item_dicts.append(item_dict)
        return item_dicts


class DWARFDebugLineTreeItemDelegate(object):
    def __init__(self, mach_frame):
        self.mach_frame = mach_frame

    def get_child_item_dictionaries(self):
        item_dicts = []
        mach = self.mach_frame.selected_mach
        dwarf = mach.get_dwarf()
        if dwarf:
            debug_info = dwarf.get_debug_info()
            cus = debug_info.get_dwarf_units()
            for cu in cus:
                line_table = cu.get_line_table()
                item_dict = line_table.get_item_dictionary()
                if item_dict:
                    item_dicts.append(item_dict)
        return item_dicts


class StringTableTreeItemDelegate(object):
    def __init__(self, mach_frame):
        self.mach_frame = mach_frame

    def get_child_item_dictionaries(self):
        item_dicts = []
        mach = self.mach_frame.selected_mach
        dwarf = mach.get_dwarf()
        if dwarf:
            data = dwarf.debug_str_data
            length = data.get_size()
            data.seek(0)
            while data.tell() < length:
                item_dicts.append({'#0': '0x%8.8x' % (data.tell()),
                                   'string':  '"%s"' % (data.get_c_string())})
        return item_dicts


# class MachFrame(Frame):

#     def __init__(self, parent, options, mach_files):
#         Frame.__init__(self, parent)
#         self.parent = parent
#         self.options = options
#         self.mach = None
#         self.mach_files = mach_files
#         self.mach_index = 0
#         self.selected_mach = None
#         self.lc_tree = None
#         self.sections_tree = None
#         self.symbols_tree = None
#         self.selected_filepath = StringVar()
#         self.selected_arch = StringVar()
#         self.selected_arch.trace("w", self.arch_changed_callback)
#         self.selected_filepath.set(self.mach_files[0])
#         self.load_mach_file(self.mach_files[0])
#         self.createWidgets()
#         self.update_arch_option_menu()

#     def load_mach_file(self, path):
#         self.mach = Mach()
#         self.mach.parse(path)
#         self.selected_filepath.set(path)
#         first_arch_name = str(self.mach.get_architecture(0))
#         self.selected_mach = self.mach.get_architecture_slice(first_arch_name)
#         self.selected_arch.set(first_arch_name)

#     # def update_arch_option_menu(self):
#     #     # Update the architecture menu
#     #     menu = self.arch_mb['menu']
#     #     menu.delete(0, END)
#     #     if self.mach:
#     #         num_archs = self.mach.get_num_archs()
#     #         for i in range(num_archs):
#     #             arch_name = str(self.mach.get_architecture(i))
#     #             menu.add_command(
#     #                 label=arch_name,
#     #                 command=Tkinter._setit(self.selected_arch, arch_name))

#     def refresh_frames(self):
#         if self.lc_tree:
#             self.lc_tree.reload()
#         if self.sections_tree:
#             self.sections_tree.delegate = SectionListTreeItemDelegate(
#                 self.selected_mach.sections[1:], True)
#             self.sections_tree.reload()
#         if self.symbols_tree:
#             self.symbols_tree.reload()

#     def file_changed_callback(self, *dummy):
#         path = self.selected_filepath.get()
#         if self.mach is None or self.mach.path != path:
#             self.load_mach_file(path)
#             self.refresh_frames()
#         else:
#             print('file did not change')

#     def arch_changed_callback(self, *dummy):
#         arch = self.selected_arch.get()
#         self.selected_mach = self.mach.get_architecture_slice(arch)
#         self.refresh_frames()

#     def createWidgets(self):
#         self.parent.title("Source")
#         self.style = Style()
#         self.style.theme_use("default")
#         self.pack(fill=BOTH, expand=1)

#         self.columnconfigure(0, pad=5, weight=1)
#         self.columnconfigure(1, pad=5)
#         self.rowconfigure(1, weight=1)

#         files = []
#         for i, mach_file in enumerate(self.mach_files):
#             files.append(mach_file)
#             if i == 0:
#                 files.append(files[0])
#         self.mach_mb = OptionMenu(self, self.selected_filepath, *files,
#                                   command=self.file_changed_callback)
#         self.mach_mb.grid(row=0, column=0, stick=NSEW)

#         self.arch_mb = OptionMenu(self, self.selected_arch,
#                                   command=self.arch_changed_callback)
#         self.arch_mb.grid(row=0, column=1, stick=NSEW)

#         note = Notebook(self)

#         lc_column_dicts = [
#             {'id': '#0', 'text': 'Name', 'anchor': W, 'stretch': 0},
#             {'id': 'value', 'text': 'Value', 'anchor': W, 'stretch': 0},
#             {'id': 'summary', 'text': 'Summary', 'anchor': W, 'stretch': 1}
#         ]

#         sect_column_dicts = [
#             {'id': '#0', 'text': 'Index', 'width': 40, 'anchor': W,
#              'stretch': 0, 'sort_type': 'number'},
#             {'id': 'segname', 'text': 'Segment', 'width': 80, 'anchor': W,
#              'stretch': 0},
#             {'id': 'sectname', 'text': 'Section', 'width': 120, 'anchor': W,
#              'stretch': 0},
#             {'id': 'range', 'text': 'Address Range', 'width': 300, 'anchor': W,
#              'stretch': 0},
#             {'id': 'size', 'text': 'Size', 'width': 140, 'anchor': W,
#              'stretch': 0, 'sort_type': 'number'},
#             {'id': 'offset', 'text': 'File Offset', 'width': 80, 'anchor': W,
#              'stretch': 0, 'sort_type': 'number'},
#             {'id': 'align', 'text': 'Align', 'width': 80, 'anchor': W,
#              'stretch': 0, 'sort_type': 'number'},
#             {'id': 'reloff', 'text': 'Rel Offset', 'width': 80, 'anchor': W,
#              'stretch': 0, 'sort_type': 'number'},
#             {'id': 'nreloc', 'text': 'Num Relocs', 'width': 80, 'anchor': W,
#              'stretch': 0, 'sort_type': 'number'},
#             {'id': 'type', 'text': 'Type', 'width': 200, 'anchor': W,
#              'stretch': 0},
#             {'id': 'attrs', 'text': 'Attributes', 'width': 200, 'anchor': W,
#              'stretch': 1},
#             {'id': 'reserved1', 'text': 'reserved1', 'width': 100, 'anchor': W,
#              'stretch': 0, 'sort_type': 'number'},
#             {'id': 'reserved2', 'text': 'reserved2', 'width': 100, 'anchor': W,
#              'stretch': 0, 'sort_type': 'number'},
#             {'id': 'reserved3', 'text': 'reserved3', 'width': 100, 'anchor': W,
#              'stretch': 0, 'sort_type': 'number'}
#         ]

#         symbol_column_dicts = [
#             {'id': '#0', 'text': 'Index', 'width': 50, 'anchor': W,
#              'stretch': 0, 'sort_type': 'number'},
#             {'id': 'type', 'text': 'Type', 'width': 60, 'anchor': W,
#              'stretch': 0},
#             {'id': 'flags', 'text': 'Flags', 'width': 60, 'anchor': W,
#              'stretch': 0},
#             {'id': 'sect', 'text': 'Section', 'width': 200, 'anchor': W,
#              'stretch': 0},
#             {'id': 'desc', 'text': 'Descriptor', 'width': 60, 'anchor': W,
#              'stretch': 0, 'sort_type': 'number'},
#             {'id': 'value', 'text': 'Value', 'width': 140, 'anchor': W,
#              'stretch': 0, 'sort_type': 'number'},
#             {'id': 'name', 'text': 'Name', 'width': 80, 'anchor': W,
#              'stretch': 1}
#         ]

#         debug_info_column_dicts = [
#             {'id': '#0', 'text': 'Offset', 'anchor': W, 'stretch': 0},
#             {'id': 'name', 'text': 'Name', 'anchor': W, 'stretch': 0},
#             {'id': 'value', 'text': 'Value', 'anchor': W, 'stretch': 1}
#         ]

#         debug_line_column_dicts = [
#             {'id': '#0', 'text': 'Address', 'width': 200, 'anchor': W,
#              'stretch': 0},
#             {'id': 'file', 'text': 'File', 'width': 400, 'anchor': W,
#              'stretch': 0},
#             {'id': 'line', 'text': 'Line', 'width': 40, 'anchor': W,
#              'stretch': 0},
#             {'id': 'column', 'text': 'Col', 'width': 40, 'anchor': W,
#              'stretch': 0},
#             {'id': 'is_stmt', 'text': 'Stmt', 'width': 40, 'anchor': W,
#              'stretch': 0},
#             {'id': 'end_sequence', 'text': 'End', 'width': 10, 'anchor': W,
#              'stretch': 1}
#         ]
#         debug_str_column_dicts = [
#             {'id': '#0', 'width': 100, 'text': 'Offset', 'anchor': W,
#              'stretch': 0},
#             {'id': 'string', 'text': 'String', 'anchor': W, 'stretch': 1}
#         ]

#         self.lc_tree = DelegateTree(self, lc_column_dicts,
#                                     LoadCommandTreeItemDelegate(self))
#         self.sections_tree = DelegateTree(self, sect_column_dicts,
#                                           SectionListTreeItemDelegate(
#                                               self.selected_mach.sections[1:],
#                                               True))
#         self.symbols_tree = DelegateTree(self, symbol_column_dicts,
#                                          SymbolsTreeItemDelegate(self))
#         self.debug_info_tree = DelegateTree(
#             self, debug_info_column_dicts,
#             DWARFDebugInfoTreeItemDelegate(self))
#         self.debug_line_tree = DelegateTree(
#             self, debug_line_column_dicts,
#             DWARFDebugLineTreeItemDelegate(self))
#         self.debug_str_tree = DelegateTree(
#             self, debug_str_column_dicts,
#             StringTableTreeItemDelegate(self))
#         note.add(self.lc_tree, text="Load Commands", compound=TOP)
#         note.add(self.sections_tree, text="Sections")
#         note.add(self.symbols_tree, text="Symbols")
#         note.add(self.debug_info_tree, text=".debug_info")
#         note.add(self.debug_line_tree, text=".debug_line")
#         note.add(self.debug_str_tree, text=".debug_str")
#         note.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky=NSEW)


# def tk_gui(options, mach_files):
#     root = Tk()
#     root.geometry("800x600+300+300")
#     app = MachFrame(root, options, mach_files)
#     root.mainloop()


def handle_mach(options, path):
    mach = Mach()
    mach.parse(path)
    if mach.is_valid():
        if options.interactive:
            interpreter = Mach.Interactive(mach, options)
            interpreter.cmdloop()
        else:
            mach.dump(options)
    else:
        print('error: "%s" is not a valid mach-o file' % (path))


def user_specified_options(options):
    '''Return true if the user specified any options, false otherwise.'''
    if options.dump_header:
        return True
    if options.dump_symtab:
        return True
    if options.symbols_in_section:
        return True
    if options.functions:
        return True
    if options.dump_load_commands:
        return True
    if options.dump_sections:
        return True
    if options.section_names:
        return True
    if options.interactive:
        return True
    if options.find_mangled:
        return True
    if options.compare:
        return True
    if options.tk:
        return True
    if options.outfile:
        return True
    if dwarf.options.have_dwarf_options(options):
        return True
    if options.objc or options.objc_stats:
        return True
    if options.compact_unwind or options.unwind_dups:
        return True
    if options.func_starts:
        return True
    return False


if __name__ == '__main__':
    parser = optparse.OptionParser(
        description='A script that parses skinny and universal mach-o files.')
    parser.add_option(
        '--arch', '-a',
        type='string',
        metavar='<arch-name>',
        dest='archs',
        action='append',
        help='specify one or more architectures by name',
        default=[])
    parser.add_option(
        '-v', '--verbose',
        action='store_true',
        dest='verbose',
        help='display verbose debug info',
        default=False)
    parser.add_option(
        '-g', '--debug',
        action='store_true',
        dest='debug',
        help='Dump debug level logging',
        default=False)
    parser.add_option(
        '-H', '--header',
        action='store_true',
        dest='dump_header',
        help='dump the mach-o file header',
        default=False)
    parser.add_option(
        '-l', '--load-commands',
        action='store_true',
        dest='dump_load_commands',
        help='dump the mach-o load commands',
        default=False)
    parser.add_option(
        '-s', '--symtab',
        action='store_true',
        dest='dump_symtab',
        help='dump the mach-o symbol table',
        default=False)
    parser.add_option(
        '--symbols-in-section',
        type='string',
        metavar='<section-name>',
        dest='symbols_in_section',
        help=('dump the symbols from the mach-o symbol table from the '
              'specified named section'),
        default=None)
    parser.add_option(
        '--functions',
        action='store_true',
        dest='functions',
        help='dump the mach-o functions from the symbol table and LC_FUNCTION_STARTS',
        default=False)
    parser.add_option(
        '-S', '--sections',
        action='store_true',
        dest='dump_sections',
        help=('dump the mach-o sections in all LC_SEGMENT and LC_SEGMENT_64 '
              'load commands'),
        default=False)
    parser.add_option(
        '--section', type='string',
        metavar='<section-name>',
        dest='section_names',
        action='append',
        help='Specify one or more section names to dump')
    parser.add_option(
        '-i', '--interactive',
        action='store_true',
        dest='interactive',
        help='enable interactive mode',
        default=False)
    parser.add_option(
        '-m', '--mangled',
        action='store_true',
        dest='find_mangled',
        help='dump all mangled names in a mach file',
        default=False)
    parser.add_option(
        '-c', '--compare',
        action='store_true',
        dest='compare',
        help='compare two mach files',
        default=False)
    parser.add_option(
        '--compare-size',
        action='store_true',
        dest='compare_size',
        help=('compare the sizes of two mach files or directories containing'
              ' mach files.'),
        default=False)
    parser.add_option(
        '-t', '--tk',
        action='store_true',
        dest='tk',
        help='Use TK to display an interactive window',
        default=False)
    parser.add_option(
        '-o', '--out',
        type='string',
        metavar='<path>',
        dest='outfile',
        help=('Used in conjunction with the --section=NAME option to save a '
              'single section\'s data to disk.'),
        default=None)
    parser.add_option(
        '--objc',
        action='store_true',
        dest='objc',
        help='dump the objective C metadata',
        default=False)
    parser.add_option(
        '--objc-stats',
        action='store_true',
        dest='objc_stats',
        help='dump stats on the objective C classes',
        default=False)
    parser.add_option(
        '-u', '--compact-unwind',
        action='store_true',
        dest='compact_unwind',
        help='dump the Apple compact unwind tables',
        default=False)
    parser.add_option(
        '-U', '--unwind-dups',
        action='store_true',
        dest='unwind_dups',
        help='Check for duplicate unwind info in both Apple compact unwind '
             'and EH frame.',
        default=False)
    parser.add_option(
        '-f', '--func-starts', '--function-starts', '--LC_FUNCTION_STARTS',
        action='store_true',
        dest='func_starts',
        help='dump the function starts map',
        default=False)
    dwarf.options.append_dwarf_options(parser)
    (options, mach_files) = parser.parse_args()
    dwarf.enable_colors = options.color
    if options.tk:
        tk_gui(options, mach_files)
    elif options.compare:
        if len(mach_files) == 2:
            mach_a = Mach()
            mach_b = Mach()
            mach_a.parse(mach_files[0])
            mach_b.parse(mach_files[1])
            mach_a.compare(mach_b)
        else:
            print('error: --compare takes two mach files as arguments')
    elif options.compare_size:
        if len(mach_files) == 2:
            if os.path.isdir(mach_files[0]):
                if not os.path.isdir(mach_files[1]):
                    print('error: --compare-size arguments must be both '
                          'directories or both paths to mach-o files')
                    sys.exit(1)
                compare_size_in_directories(mach_files[0], mach_files[1])
            else:
                if os.path.isdir(mach_files[1]):
                    print('error: --compare-size arguments must be both '
                          'directories or both paths to mach-o files')
                    sys.exit(1)
                mach_a = Mach()
                mach_b = Mach()
                mach_a.parse(mach_files[0])
                mach_b.parse(mach_files[1])
                mach_a.compare_size(mach_b)
        else:
            print('error: --compare-size takes two paths as arguments')
    else:
        if not user_specified_options(options):
            options.dump_header = True
            options.dump_load_commands = True
        for path in mach_files:
            if os.path.isdir(path):
                print('Searching "%s" for mach-o files...' % (path))
                mach_files = []
                get_mach_files_in_directory(path, options, mach_files)
                for mach in mach_files:
                    mach.dump(options)
            else:
                handle_mach(options, path)
        if options.objc_stats and len(mach_files) > 1:
            print('Combined Objective C Statistics:')
            g_objc_stats.dump()
