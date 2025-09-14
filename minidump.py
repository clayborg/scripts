#!/usr/bin/env python3

import binascii
import bisect
from re import I
import file_extract
import hashlib
import inspect
import io
import json
import optparse
import multiprocessing
import pprint
import shlex
import string
import struct
import sys


def uuid_bytes_to_str(uuid_bytes):
    if uuid_bytes:
        uuid_len = len(uuid_bytes)
        uuid_hex_bytes = binascii.hexlify(uuid_bytes).decode('utf-8')
        if uuid_len == 16:
            str = "%s-%s-%s-%s-%s" % (uuid_hex_bytes[0:8],
                                      uuid_hex_bytes[8:12],
                                      uuid_hex_bytes[12:16],
                                      uuid_hex_bytes[16:20],
                                      uuid_hex_bytes[20:32])
            return str.upper()
        if uuid_len == 20:
            str = "%s-%s-%s-%s-%s-%s" % (uuid_hex_bytes[0:8],
                                         uuid_hex_bytes[8:12],
                                         uuid_hex_bytes[12:16],
                                         uuid_hex_bytes[16:20],
                                         uuid_hex_bytes[20:32],
                                         uuid_hex_bytes[32:40])
            return str.upper()
        return uuid_hex_bytes.upper()


class DumpOptions(object):
    def __init__(self, f=sys.stdout, flat=False, prefix=None):
        self.f = f
        self.flat = flat
        self.prefix = prefix

    def has_prefix(self):
        return self.prefix and len(self.prefix) > 0

    def write(self, s):
        if self.has_prefix():
            self.f.write(self.prefix)
        self.f.write(s)

    def write_name(self, name_width, name, suffix=' = '):
        self.write('%-*s%s' % (name_width, name, suffix))

    def write_str(self, name_width, name, value):
        self.write_name(name_width, name)
        self.f.write('%s\n' % (str(value)))

    def write_hex16(self, name_width, name, value):
        self.write_name(name_width, name)
        self.f.write('%#4.4x\n' % (value))

    def write_hex32(self, name_width, name, value, suffix=None):
        self.write_name(name_width, name)
        if suffix is None:
            suffix = ''
        self.f.write('%#8.8x%s\n' % (value, suffix))

    def write_hex64(self, name_width, name, value, suffix=None):
        self.write_name(name_width, name)
        if suffix is None:
            suffix = ''
        self.f.write('%#16.16x%s\n' % (value, suffix))

    def write_unsigned(self, name_width, name, value):
        self.write_name(name_width, name)
        self.f.write('%u\n' % (value))

    def write_attr_unsigned(self, name_width, obj, name):
        value = getattr(obj, name)
        return self.write_unsigned(name_width, name, value)

    def write_attr_hex16(self, name_width, obj, name):
        value = getattr(obj, name)
        return self.write_hex16(name_width, name, value)

    def write_attr_str(self, name_width, obj, name):
        value = getattr(obj, name)
        if type(value) is list:
            for (i, v) in enumerate(value):
                self.write_str(name_width, name + '[%i]' % (i), v)
        else:
            return self.write_str(name_width, name, value)

    def write_attr_hex32(self, name_width, obj, name, suffix=None):
        value = getattr(obj, name)
        if type(value) is list:
            for (i, v) in enumerate(value):
                self.write_hex32(name_width, name + '[%i]' % (i), v,
                                 suffix=suffix)
        else:
            return self.write_hex32(name_width, name, value, suffix=suffix)

    def write_attr_hex64(self, name_width, obj, name, suffix=None):
        value = getattr(obj, name)
        if type(value) is list:
            for (i, v) in enumerate(value):
                self.write_hex64(name_width, name + '[%i]' % (i), v,
                                 suffix=suffix)
        else:
            return self.write_hex64(name_width, name, value)

    def write_dump(self, name_width, name, value):
        if self.flat:
            self.write(("%%-%is = " % (name_width)) % (name))
            value.dump(self)
        else:
            value.dump(self.append_prefix(name + '.'))

    def write_attr_dump(self, name_width, obj, name):
        value = getattr(obj, name)
        if value is None:
            self.write(("%%-%is = <unavailable>\n" % (name_width)) % (name))
            return
        if type(value) is list:
            for (i, v) in enumerate(value):
                name_with_idx = name + '[%i]' % (i)
                self.write_dump(name_width, name_with_idx, v)
        else:
            self.write_dump(name_width, name, value)

    def set_flat(self, new_flat):
        if not new_flat:
            new_prefix = None
        else:
            new_prefix = self.prefix
        return DumpOptions(f=self.f, flat=new_flat, prefix=new_prefix)

    def append_prefix(self, p):
        if self.has_prefix():
            return DumpOptions(f=self.f, flat=self.flat,
                               prefix=self.prefix + p)
        return DumpOptions(f=self.f, flat=self.flat, prefix=p)

    def clear_prefix(self):
        return DumpOptions(f=self.f, flat=self.flat, prefix=None)


# ----------------------------------------------------------------------
# Enumeration values for Header.Flags
# ----------------------------------------------------------------------
MiniDumpNormal = 0x00000000
MiniDumpWithDataSegs = 0x00000001
MiniDumpWithFullMemory = 0x00000002
MiniDumpWithHandleData = 0x00000004
MiniDumpFilterMemory = 0x00000008
MiniDumpScanMemory = 0x00000010
MiniDumpWithUnloadedModules = 0x00000020
MiniDumpWithIndirectlyReferencedMemory = 0x00000040
MiniDumpFilterModulePaths = 0x00000080
MiniDumpWithProcessThreadData = 0x00000100
MiniDumpWithPrivateReadWriteMemory = 0x00000200
MiniDumpWithoutOptionalData = 0x00000400
MiniDumpWithFullMemoryInfo = 0x00000800
MiniDumpWithThreadInfo = 0x00001000
MiniDumpWithCodeSegs = 0x00002000
MiniDumpWithoutAuxiliaryState = 0x00004000
MiniDumpWithFullAuxiliaryState = 0x00008000
MiniDumpWithPrivateWriteCopyMemory = 0x00010000
MiniDumpIgnoreInaccessibleMemory = 0x00020000
MiniDumpWithTokenInformation = 0x00040000
MiniDumpWithModuleHeaders = 0x00080000
MiniDumpFilterTriage = 0x00100000
MiniDumpValidTypeFlags = 0x001fffff

# ----------------------------------------------------------------------
# Stream types for Directory.StreamType
# ----------------------------------------------------------------------
UnusedStream = 0
ReservedStream0 = 1
ReservedStream1 = 2
ThreadListStream = 3
ModuleListStream = 4
MemoryListStream = 5
ExceptionStream = 6
SystemInfoStream = 7
ThreadExListStream = 8
Memory64ListStream = 9
CommentStreamA = 10
CommentStreamW = 11
HandleDataStream = 12
FunctionTableStream = 13
UnloadedModuleListStream = 14
MiscInfoStream = 15
MemoryInfoListStream = 16
ThreadInfoListStream = 17
HandleOperationListStream = 18
BreakpadInfo = 0x47670001
BreakpadAssertionInfo = 0x47670002
BreakpadLinuxCPUInfo = 0x47670003     # /proc/cpuinfo
BreakpadLinuxProcStatus = 0x47670004  # /proc/<pid>/status
BreakpadLinuxLSBRelease = 0x47670005  # /etc/lsb-release
BreakpadLinuxCMDLine = 0x47670006     # /proc/<pid>/cmdline
BreakpadLinuxEnviron = 0x47670007     # /proc/<pid>/environ
BreakpadLinuxAuxv = 0x47670008        # /proc/<pid>/auxv
BreakpadLinuxMaps = 0x47670009        # /proc/<pid>/maps
BreakpadLinuxDSODebug = 0x4767000A
BreakpadLinuxProcStat = 0x4767000B    # /proc/<pid>/stat
BreakpadLinuxProcUptime = 0x4767000C  # uptime
BreakpadLinuxProcFD = 0x4767000D      # /proc/<pid>/fd

FacebookUnwindStackSymbols = 0xFACECAF0
FacebookAppCustomData = 0xFACECAFA
FacebookAppBuildID = 0xFACECAFB
FacebookAppVersionName = 0xFACECAFC
FacebookJavaStack = 0xFACECAFD
FacebookDalvikInfo = 0xFACECAFE
FacebookUnwindSymbols = 0xFACECAFF
FacebookDumpErrorLog = 0xFACECB00
FacebookAppStateLog = 0xFACECCCC
FacebookAbortReason = 0xFACEDEAD
FacebookThreadName = 0xFACEE000
FacebookLogcat = 0xFACE1CA7
FacebookStreamMarkers = 0xFACE0000


LastReservedStream = 0xffff

def StreamTypeToStr(StreamType):
    if StreamType == UnusedStream:
        return "UnusedStream"
    if StreamType == ReservedStream0:
        return "ReservedStream0"
    if StreamType == ReservedStream1:
        return "ReservedStream1"
    if StreamType == ThreadListStream:
        return "ThreadListStream"
    if StreamType == ModuleListStream:
        return "ModuleListStream"
    if StreamType == MemoryListStream:
        return "MemoryListStream"
    if StreamType == ExceptionStream:
        return "ExceptionStream"
    if StreamType == SystemInfoStream:
        return "SystemInfoStream"
    if StreamType == ThreadExListStream:
        return "ThreadExListStream"
    if StreamType == Memory64ListStream:
        return "Memory64ListStream"
    if StreamType == CommentStreamA:
        return "CommentStreamA"
    if StreamType == CommentStreamW:
        return "CommentStreamW"
    if StreamType == HandleDataStream:
        return "HandleDataStream"
    if StreamType == FunctionTableStream:
        return "FunctionTableStream"
    if StreamType == UnloadedModuleListStream:
        return "UnloadedModuleListStream"
    if StreamType == MiscInfoStream:
        return "MiscInfoStream"
    if StreamType == MemoryInfoListStream:
        return "MemoryInfoListStream"
    if StreamType == ThreadInfoListStream:
        return "ThreadInfoListStream"
    if StreamType == HandleOperationListStream:
        return "HandleOperationListStream"
    if StreamType == BreakpadInfo:
        return "BreakpadInfo"
    if StreamType == BreakpadAssertionInfo:
        return "BreakpadAssertionInfo"
    if StreamType == BreakpadLinuxCPUInfo:
        return "BreakpadLinuxCPUInfo"
    if StreamType == BreakpadLinuxProcStatus:
        return "BreakpadLinuxProcStatus"
    if StreamType == BreakpadLinuxLSBRelease:
        return "BreakpadLinuxLSBRelease"
    if StreamType == BreakpadLinuxCMDLine:
        return "BreakpadLinuxCMDLine"
    if StreamType == BreakpadLinuxEnviron:
        return "BreakpadLinuxEnviron"
    if StreamType == BreakpadLinuxAuxv:
        return "BreakpadLinuxAuxv"
    if StreamType == BreakpadLinuxMaps:
        return "BreakpadLinuxMaps"
    if StreamType == BreakpadLinuxDSODebug:
        return "BreakpadLinuxDSODebug"
    if StreamType == BreakpadLinuxProcStat:
        return "BreakpadLinuxProcStat"
    if StreamType == BreakpadLinuxProcUptime:
        return "BreakpadLinuxProcUptime"
    if StreamType == BreakpadLinuxProcFD:
        return "BreakpadLinuxProcFD"
    if StreamType == FacebookAppCustomData:
        return "FacebookAppCustomData"
    if StreamType == FacebookAppBuildID:
        return "FacebookAppBuildID"
    if StreamType == FacebookAppVersionName:
        return "FacebookAppVersionName"
    if StreamType == FacebookJavaStack:
        return "FacebookJavaStack"
    if StreamType == FacebookDalvikInfo:
        return "FacebookDalvikInfo"
    if StreamType == FacebookUnwindSymbols:
        return "FacebookUnwindSymbols"
    if StreamType == FacebookDumpErrorLog:
        return "FacebookDumpErrorLog"
    if StreamType == FacebookAppStateLog:
        return "FacebookAppStateLog"
    if StreamType == FacebookAppStateLog:
        return "FacebookAppStateLog"
    if StreamType == FacebookThreadName:
        return "FacebookThreadName"
    if StreamType == FacebookLogcat:
        return "FacebookLogcat"
    if StreamType == FacebookStreamMarkers:
        return "FacebookStreamMarkers"
    if StreamType == FacebookUnwindStackSymbols:
        return "FacebookUnwindStackSymbols"
    return '???'

# SystemInfo.PlatformId values
VER_PLATFORM_WIN32s = 0
VER_PLATFORM_WIN32_WINDOWS = 1
VER_PLATFORM_WIN32_NT = 2
VER_PLATFORM_WIN32_CE = 3
VER_PLATFORM_UNIX = 0x8000
VER_PLATFORM_MACOSX = 0x8101
VER_PLATFORM_IOS = 0x8102
VER_PLATFORM_LINUX = 0x8201
VER_PLATFORM_SOLARIS = 0x8202
VER_PLATFORM_ANDROID = 0x8203
VER_PLATFORM_PS3 = 0x8204
VER_PLATFORM_NACL = 0x8205


def PlatformIDToStr(p):
    if p == VER_PLATFORM_WIN32s:
        return 'Win32s'
    elif p == VER_PLATFORM_WIN32_WINDOWS:
        return 'Windows'
    elif p == VER_PLATFORM_WIN32_NT:
        return 'Win32_NT'
    elif p == VER_PLATFORM_WIN32_CE:
        return 'Win32_CE'
    elif p == VER_PLATFORM_UNIX:
        return 'Unix'
    elif p == VER_PLATFORM_MACOSX:
        return 'macOS'
    elif p == VER_PLATFORM_IOS:
        return 'iOS'
    elif p == VER_PLATFORM_LINUX:
        return 'Linux'
    elif p == VER_PLATFORM_SOLARIS:
        return 'Solaris'
    elif p == VER_PLATFORM_ANDROID:
        return 'Android'
    elif p == VER_PLATFORM_PS3:
        return 'PS3'
    elif p == VER_PLATFORM_NACL:
        return 'NaCL'
    return '%u' % (p)


# ProcessorArchitecure values
PROCESSOR_ARCHITECTURE_INTEL = 0
PROCESSOR_ARCHITECTURE_MIPS = 1
PROCESSOR_ARCHITECTURE_ALPHA = 2
PROCESSOR_ARCHITECTURE_PPC = 3
PROCESSOR_ARCHITECTURE_SHX = 4
PROCESSOR_ARCHITECTURE_ARM = 5
PROCESSOR_ARCHITECTURE_IA64 = 6
PROCESSOR_ARCHITECTURE_ALPHA64 = 7
PROCESSOR_ARCHITECTURE_MSIL = 8
PROCESSOR_ARCHITECTURE_AMD64 = 9
PROCESSOR_ARCHITECTURE_IA32_ON_WIN64 = 10
PROCESSOR_ARCHITECTURE_ARM64 = 0x000c
PROCESSOR_ARCHITECTURE_SPARC = 0x8001
PROCESSOR_ARCHITECTURE_PPC64 = 0x8002
PROCESSOR_ARCHITECTURE_ARM64_BP = 0x8003
PROCESSOR_ARCHITECTURE_MIPS64 = 0x8004

def ProcessorArchitectureToStr(a):
    if a == PROCESSOR_ARCHITECTURE_INTEL:
        return 'x86'
    if a == PROCESSOR_ARCHITECTURE_MIPS:
        return 'MIPS'
    if a == PROCESSOR_ARCHITECTURE_ALPHA:
        return 'Alpha'
    if a == PROCESSOR_ARCHITECTURE_PPC:
        return 'PPC'
    if a == PROCESSOR_ARCHITECTURE_SHX:
        return 'SHX'
    if a == PROCESSOR_ARCHITECTURE_ARM:
        return 'ARM'
    if a == PROCESSOR_ARCHITECTURE_IA64:
        return 'IA64'
    if a == PROCESSOR_ARCHITECTURE_ALPHA64:
        return 'ALPHA64'
    if a == PROCESSOR_ARCHITECTURE_MSIL:
        return 'MSIL'
    if a == PROCESSOR_ARCHITECTURE_AMD64:
        return 'x86_64'
    if a == PROCESSOR_ARCHITECTURE_IA32_ON_WIN64:
        return 'X86Win64'
    if a == PROCESSOR_ARCHITECTURE_SPARC:
        return 'SPARC'
    if a == PROCESSOR_ARCHITECTURE_PPC64:
        return 'PPC64'
    if a == PROCESSOR_ARCHITECTURE_ARM64 or a == PROCESSOR_ARCHITECTURE_ARM64_BP:
        return 'ARM64'
    if a == PROCESSOR_ARCHITECTURE_MIPS64:
        return 'MIPS64'
    return '%#4.4x' % (a)

class Header(object):
    Magic = 0x504d444d  # 'PMDM'
    '''
        struct MINIDUMP_HEADER {
          ULONG32 Signature;
          ULONG32 Version;
          ULONG32 NumberOfStreams;
          RVA     StreamDirectoryRva;
          ULONG32 CheckSum;
          union {
            ULONG32 Reserved;
            ULONG32 TimeDateStamp;
          };
          ULONG64 Flags;
        };
    '''
    def __init__(self, Signature=0, Version=0, NumberOfStreams=0,
                 StreamDirectoryRva=0, CheckSum=0, TimeDateStamp=0, Flags=0):
        self.Signature = Signature
        self.Version = Version
        self.NumberOfStreams = NumberOfStreams
        self.StreamDirectoryRva = StreamDirectoryRva
        self.CheckSum = CheckSum
        self.TimeDateStamp = TimeDateStamp
        self.Flags = Flags

    @classmethod
    def sizeof(cls):
        return 32

    @classmethod
    def decode(cls, data):
        return cls(data.get_uint32(),
                   data.get_uint32(),
                   data.get_uint32(),
                   data.get_uint32(),
                   data.get_uint32(),
                   data.get_uint32(),
                   data.get_uint64())

    def encode(self, strm):
        strm.put_uint32(self.Signature)
        strm.put_uint32(self.Version)
        strm.put_uint32(self.NumberOfStreams)
        strm.put_uint32(self.StreamDirectoryRva)
        strm.put_uint32(self.CheckSum)
        strm.put_uint32(self.TimeDateStamp)
        strm.put_uint64(self.Flags)

    def valid(self):
        return self.Signature == self.Magic

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        w = 18
        d.write('MINIDUMP_HEADER:\n')
        d.write_attr_hex32(w, self, 'Signature')
        d.write_attr_hex32(w, self, 'Version')
        d.write_attr_hex32(w, self, 'NumberOfStreams')
        d.write_attr_hex32(w, self, 'StreamDirectoryRva')
        d.write_attr_hex32(w, self, 'CheckSum')
        d.write_attr_hex32(w, self, 'TimeDateStamp')
        d.write_attr_hex32(w, self, 'Flags')


class MiscInfo(object):
    '''
        struct MINIDUMP_MISC_INFO {
          ULONG32 SizeOfInfo;
          ULONG32 Flags1;
          ULONG32 ProcessId;
          ULONG32 ProcessCreateTime;
          ULONG32 ProcessUserTime;
          ULONG32 ProcessKernelTime;
        }
    '''
    MINIDUMP_MISC1_PROCESS_ID = 1
    MINIDUMP_MISC1_PROCESS_TIMES = 2

    def __init__(self, SizeOfInfo=0, Flags1=0, ProcessId=0,
                 ProcessCreateTime=0, ProcessUserTime=0, ProcessKernelTime=0):
        self.SizeOfInfo = SizeOfInfo
        self.Flags1 = Flags1
        self.ProcessId = ProcessId
        self.ProcessCreateTime = ProcessCreateTime
        self.ProcessUserTime = ProcessUserTime
        self.ProcessKernelTime = ProcessKernelTime

    @classmethod
    def decode(cls, data):
        return cls(data.get_uint32(), data.get_uint32(), data.get_uint32(),
                   data.get_uint32(), data.get_uint32(), data.get_uint32())

    @classmethod
    def sizeof(cls):
        return 24

    def encode(self, strm):
        if self.ProcessId:
            self.Flags1 |= self.MINIDUMP_MISC1_PROCESS_ID
        if (self.ProcessCreateTime or self.ProcessUserTime or
                self.ProcessKernelTime):
            self.Flags1 |= self.MINIDUMP_MISC1_PROCESS_TIMES
        strm.put_uint32(self.SizeOfInfo)
        strm.put_uint32(self.Flags1)
        strm.put_uint32(self.ProcessId)
        strm.put_uint32(self.ProcessCreateTime)
        strm.put_uint32(self.ProcessUserTime)
        strm.put_uint32(self.ProcessKernelTime)

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        if d.flat:
            d.f.write('%#8.8x %#8.8x %#8.8x %#8.8x %#8.8x %#8.8x\n' % (
                self.SizeOfInfo, self.Flags1, self.ProcessId,
                self.ProcessCreateTime, self.ProcessUserTime,
                self.ProcessKernelTime))
        else:
            d.write_attr_hex32(w, self, 'SizeOfInfo')
            d.write_attr_hex32(w, self, 'Flags1')
            d.write_attr_hex32(w, self, 'ProcessId')
            d.write_attr_hex32(w, self, 'ProcessCreateTime')
            d.write_attr_hex32(w, self, 'ProcessUserTime')
            d.write_attr_hex32(w, self, 'ProcessKernelTime')

            d.write("DataSize = %#8.8x (%u)\n" % (self.DataSize,
                                                  self.DataSize))
            d.write("Rva = %#8.8x\n" % (self.Rva))


class LocationDescriptor(object):
    '''
        struct MINIDUMP_LOCATION_DESCRIPTOR {
          ULONG32 DataSize;
          RVA     Rva;
        };
    '''
    def __init__(self, DataSize=0, Rva=0, Object=None):
        self.DataSize = DataSize
        self.Rva = Rva
        # Object for generating minidumps that must be able to encode itself
        self.Object = Object

    @classmethod
    def decode(cls, data):
        return cls(data.get_uint32(), data.get_uint32())

    @classmethod
    def sizeof(cls):
        return 8

    def read_bytes(self, data):
        data.push_offset_and_seek(self.Rva)
        result = data.read_data(self.DataSize)
        data.pop_offset_and_seek()
        return result

    def encode(self, strm):
        strm.put_uint32(self.DataSize)
        strm.put_uint32(self.Rva)

    def encode_object(self, data, loc_data_offset):
        if self.Object:
            RVA = data.tell()
            self.Object.encode(data)
            Size = data.tell() - RVA
            data.fixup_uint_size(4, Size, loc_data_offset)
            data.fixup_uint_size(4, RVA, loc_data_offset + 4)
            return True
        return False

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        if d.flat:
            d.f.write('%#8.8x %#8.8x\n' % (self.DataSize, self.Rva))
        else:
            d.write("DataSize = %#8.8x (%u)\n" % (self.DataSize,
                                                  self.DataSize))
            d.write("Rva = %#8.8x\n" % (self.Rva))


class LocationDescriptor64(object):
    '''
        struct _MINIDUMP_LOCATION_DESCRIPTOR64 {
            ULONG64 DataSize;
            RVA64 Rva;
        }
    '''
    def __init__(self, DataSize, Rva, Data=None):
        self.DataSize = DataSize
        self.Rva = Rva
        self.Data = Data # For generating minidumps

    @classmethod
    def sizeof(cls):
        return 16

    @classmethod
    def decode(cls, data, is_64):
        return cls(data.get_uint64(), data.get_uint64())

    def encode(self, strm):
        strm.put_uint64(self.DataSize)
        strm.put_uint64(self.Rva)

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        if d.flat:
            d.f.write('%#16.16x %#16.16x\n' % (self.DataSize, self.Rva))
        else:
            d.write("DataSize = %#16.16x (%u)\n" % (self.DataSize,
                                                    self.DataSize))
            d.write("Rva = %#16.16x\n" % (self.Rva))


class Directory(object):
    '''
        struct MINIDUMP_DIRECTORY {
          ULONG32                      StreamType;
          MINIDUMP_LOCATION_DESCRIPTOR Location;
        };
    '''
    def __init__(self, StreamType, Location):
        self.StreamType = StreamType
        self.Location = Location

    @classmethod
    def sizeof(cls):
        return 4 + LocationDescriptor.sizeof()

    @classmethod
    def decode(cls, data):
        return cls(data.get_uint32(), LocationDescriptor.decode(data))

    def encode(self, strm):
        strm.put_uint32(self.StreamType)
        self.Location.encode(strm)

    @classmethod
    def dump_header(cls, d=None):
        if d is None:
            d = DumpOptions()
        f = d.f
        f.write('StreamType                           DataSize   RVA\n')
        f.write('------------------------------------ ---------- ----------\n')

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        f = d.f
        s = StreamTypeToStr(self.StreamType)
        if d.flat:
            f.write('%#8.8x %-25s ' % (self.StreamType, s))
        else:
            f.write("StreamType = %#8.8x %s\n" % (self.StreamType, s))
        self.Location.dump(d)


class Exception(object):
    EXCEPTION_MAXIMUM_PARAMETERS = 15
    '''
        struct MINIDUMP_EXCEPTION {
          ULONG32 ExceptionCode;
          ULONG32 ExceptionFlags;
          ULONG64 ExceptionRecord;
          ULONG64 ExceptionAddress;
          ULONG32 NumberParameters;
          ULONG32 __unusedAlignment;
          ULONG64 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
        }
    '''
    def __init__(self, data):
        self.ExceptionCode = data.get_uint32()
        self.ExceptionFlags = data.get_uint32()
        self.ExceptionRecord = data.get_uint64()
        self.ExceptionAddress = data.get_uint64()
        self.NumberParameters = data.get_uint32()
        self.__unusedAlignment = data.get_uint32()
        self.ExceptionInformation = []
        for _i in range(self.EXCEPTION_MAXIMUM_PARAMETERS):
            self.ExceptionInformation.append(data.get_uint64())

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        if not d.has_prefix():
            d.write('MINIDUMP_EXCEPTION:\n')
        d.write('ExceptionCode = %#8.8x\n' % (self.ExceptionCode))
        d.write('ExceptionFlags = %#8.8x\n' % (self.ExceptionFlags))
        d.write('ExceptionRecord = %#16.16x\n' % (self.ExceptionRecord))
        d.write('ExceptionAddress = %#16.16x\n' % (self.ExceptionAddress))
        d.write('NumberParameters = %#8.8x\n' % (self.NumberParameters))
        for i in range(self.NumberParameters):
            d.write('ExceptionInformation[%i] = %#8.8x\n' % (i,
                    self.ExceptionInformation[i]))


class ExceptionInfo(object):
    '''
        struct MINIDUMP_EXCEPTION_STREAM {
          ULONG32                      ThreadId;
          ULONG32                      __alignment;
          MINIDUMP_EXCEPTION           ExceptionRecord;
          MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
        };
    '''
    def __init__(self, data):
        self.ThreadId = data.get_uint32()
        self.__alignment = data.get_uint32()
        self.ExceptionRecord = Exception(data)
        self.ThreadContext = LocationDescriptor.decode(data)

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        f = d.f
        f.write('MINIDUMP_EXCEPTION_STREAM:\n')
        f.write('ThreadId = %#8.8x\n' % (self.ThreadId))
        self.ExceptionRecord.dump(d.append_prefix('ExceptionRecord.'))
        self.ThreadContext.dump(d.append_prefix('ThreadContext.'))


class MemoryList(object):
    '''
        struct MINIDUMP_MEMORY_LIST {
          ULONG32                    NumberOfMemoryRanges;
          MINIDUMP_MEMORY_DESCRIPTOR MemoryRanges[];
        };
    '''
    def __init__(self, NumberOfMemoryRanges=0, MemoryRanges=None):
        self.NumberOfMemoryRanges = NumberOfMemoryRanges
        if MemoryRanges is None:
            self.MemoryRanges = []
        else:
            self.MemoryRanges = MemoryRanges

    @classmethod
    def decode(cls, data, size):
        NumberOfMemoryRanges = data.get_uint32()
        if 4 + NumberOfMemoryRanges * MemoryDescriptor.sizeof() < size:
            data.get_uint32()
        MemoryRanges = []
        for _i in range(NumberOfMemoryRanges):
            MemoryRanges.append(MemoryDescriptor.decode(data))
        return cls(NumberOfMemoryRanges, MemoryRanges)

    def encode(self, strm, pad):
        strm.put_uint32(self.NumberOfMemoryRanges)
        if pad:
            strm.put_uint32(0)
        for MemoryRange in self.MemoryRanges:
            MemoryRange.encode(strm)

    def append(self, memory):
        self.MemoryRanges.append(memory)
        self.NumberOfMemoryRanges = len(self.MemoryRanges)

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        w = 20
        d.write('MINIDUMP_MEMORY_LIST:\n')
        d.write_attr_hex32(w, self, 'NumberOfMemoryRanges')
        d.set_flat(True).write_attr_dump(w, self, 'MemoryRanges')

class Memory64List(object):
    '''
        struct MINIDUMP_MEMORY64_LIST {
            ULONG64                      NumberOfMemoryRanges;
            RVA64                        BaseRva;
            MINIDUMP_MEMORY_DESCRIPTOR64 MemoryRanges[];
        }
    '''
    def __init__(self, NumberOfMemoryRanges=0, BaseRva=0, MemoryRanges=None):
        self.NumberOfMemoryRanges = NumberOfMemoryRanges
        self.BaseRva = BaseRva
        if MemoryRanges is None:
            self.MemoryRanges = []
        else:
            self.MemoryRanges = MemoryRanges

    @classmethod
    def decode(cls, data, size):
        NumberOfMemoryRanges = data.get_uint64()
        BaseRva = data.get_uint64()
        MemoryRanges = []
        for _i in range(NumberOfMemoryRanges):
            MemoryRanges.append(MemoryDescriptor64.decode(data))
        return cls(NumberOfMemoryRanges, BaseRva, MemoryRanges)

    def encode(self, strm, pad):
        strm.put_uint64(self.NumberOfMemoryRanges)
        strm.put_uint64(self.BaseRva)
        for MemoryRange in self.MemoryRanges:
            MemoryRange.encode(strm)

    def append(self, memory):
        self.MemoryRanges.append(memory)
        self.NumberOfMemoryRanges = len(self.MemoryRanges)

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        w = 20
        d.write('MINIDUMP_MEMORY64_LIST:\n')
        d.write_attr_hex64(w, self, 'NumberOfMemoryRanges')
        d.write_attr_hex64(w, self, 'BaseRva')
        d.set_flat(True).write_attr_dump(w, self, 'MemoryRanges')

class MemoryInfo(object):
    '''
        struct MINIDUMP_MEMORY_INFO {
          ULONG64 BaseAddress;
          ULONG64 AllocationBase;
          ULONG32 AllocationProtect;
          ULONG32 __alignment1;
          ULONG64 RegionSize;
          ULONG32 State;
          ULONG32 Protect;
          ULONG32 Type;
          ULONG32 __alignment2;
        };
    '''
    def __init__(self, data):
        self.BaseAddress = data.get_uint64()
        self.AllocationBase = data.get_uint64()
        self.AllocationProtect = data.get_uint32()
        self.__alignment1 = data.get_uint32()
        self.RegionSize = data.get_uint64()
        self.State = data.get_uint32()
        self.Protect = data.get_uint32()
        self.Type = data.get_uint32()
        self.__alignment2 = data.get_uint32()

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        f = d.f
        f.write('BaseAddress       = %#16.16x\n' % (self.BaseAddress))
        f.write('AllocationBase    = %#16.16x\n' % (self.AllocationBase))
        f.write('AllocationProtect = %#8.8x\n' % (self.AllocationProtect))
        f.write('__alignment1      = %#8.8x\n' % (self.__alignment1))
        f.write('RegionSize        = %#16.16x\n' % (self.RegionSize))
        f.write('State             = %#8.8x\n' % (self.State))
        f.write('Protect           = %#8.8x\n' % (self.Protect))
        f.write('Type              = %#8.8x\n' % (self.Type))
        f.write('__alignment2      = %#8.8x\n' % (self.__alignment2))


class MemoryInfoList(object):
    '''
        struct MINIDUMP_MEMORY_INFO_LIST {
          ULONG   SizeOfHeader;
          ULONG   SizeOfEntry;
          ULONG64 NumberOfEntries;
        };
    '''
    def __init__(self, data):
        self.SizeOfHeader = data.get_uint32()
        self.SizeOfEntry = data.get_uint32()
        self.NumberOfEntries = data.get_uint64()
        print("MemoryInfoList.SizeOfHeader = %#x" % (self.SizeOfHeader))
        print("MemoryInfoList.SizeOfEntry = %#x" % (self.SizeOfEntry))
        print("MemoryInfoList.NumberOfEntries = %#x" % (self.NumberOfEntries))
        self.MemoryInfos = []
        for _i in range(self.NumberOfEntries):
            self.MemoryInfos.append(MemoryInfo(data))

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        f = d.f
        f.write('SizeOfHeader = %#8.8x\n' % (self.SizeOfHeader))
        f.write('SizeOfEntry  = %#8.8x\n' % (self.SizeOfEntry))
        f.write('NumberOfEntries = %#16.16x\n' % (self.NumberOfEntries))
        for MemoryInfo in self.MemoryInfos:
            MemoryInfo.dump(d)
            f.write('\n')


class MemoryDescriptor(object):
    '''
        struct MINIDUMP_MEMORY_DESCRIPTOR {
          ULONG64                      StartOfMemoryRange;
          MINIDUMP_LOCATION_DESCRIPTOR Memory;
        };
    '''
    @classmethod
    def sizeof(cls):
        return 16

    def __init__(self, StartOfMemoryRange=0, Memory=None, Bytes=None):
        self.StartOfMemoryRange = StartOfMemoryRange
        if Memory is None:
            self.Memory = LocationDescriptor()
        else:
            self.Memory = Memory
        self.Bytes = Bytes

    @classmethod
    def decode(cls, data):
        return cls(data.get_uint64(), LocationDescriptor.decode(data))

    def encode(self, strm):
        strm.put_uint64(self.StartOfMemoryRange)
        if self.Bytes:
            self.Memory.DataSize = len(self.Bytes)
        self.Memory.encode(strm)

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        if d.flat:
            d.f.write('[0x%16.16x - 0x%16.16x) @ 0x%8.8x\n' % (
                self.StartOfMemoryRange,
                self.StartOfMemoryRange + self.Memory.DataSize,
                self.Memory.Rva))
        else:
            d.write('StartOfMemoryRange = 0x%16.16x\n' % (
                    self.StartOfMemoryRange))
            self.Memory.dump(d)

class MemoryDescriptor64(object):
    '''
        struct MINIDUMP_MEMORY_DESCRIPTOR64 {
            ULONG64 StartOfMemoryRange;
            ULONG64 DataSize;
        };
    '''
    @classmethod
    def sizeof(cls):
        return 16

    def __init__(self, StartOfMemoryRange=0, DataSize=0, Bytes=None):
        self.StartOfMemoryRange = StartOfMemoryRange
        if Bytes is not None:
            self.DataSize = len(Bytes)
        else:
            self.DataSize = DataSize
        self.Bytes = Bytes

    @classmethod
    def decode(cls, data):
        return cls(StartOfMemoryRange=data.get_uint64(),
                   DataSize=data.get_uint64())

    def encode(self, strm):
        strm.put_uint64(self.StartOfMemoryRange)
        strm.put_uint64(self.DataSize)

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        if d.flat:
            d.f.write('[0x%16.16x - 0x%16.16x)\n' % (
                self.StartOfMemoryRange,
                self.StartOfMemoryRange + self.DataSize))
        else:
            d.write('StartOfMemoryRange = 0x%16.16x\n' % (
                    self.StartOfMemoryRange))
            d.write('DataSize = 0x%16.16x\n' % (self.DataSize))


class CvRecordType(object):
    # CvRecord signature field
    CV_PDB80 = 0x53445352           # RSDS
    CV_ELF_BUILD_ID = 0x4270454c    # BpEL (Breakpad/Crashpad minidumps)

    @classmethod
    def SignatureToStr(cls, a):
        if a == cls.CV_PDB80:
            return 'Pdb70'
        if a == cls.CV_ELF_BUILD_ID:
            return "ELF build ID"
        return None

    def __init__(self, location=None, signature=0, uuid=0, age=0, pdb_name=None):
        if location is None:
            self.location = LocationDescriptor()
        else:
            self.location = location
        self.signature = signature
        self.uuid = uuid
        self.age = age
        self.pdb_name = pdb_name

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        d.write_attr_dump(12, self, 'location')
        d.write_attr_hex32(12, self, 'signature', ' (%s)' % (self.SignatureToStr(self.signature)))
        d.write_str(12, 'uuid', uuid_bytes_to_str(self.uuid))
        if self.signature == self.CV_PDB80:
            d.write_attr_hex32(12, self, 'age')
            d.write_attr_str(12, self, 'pdb_name')

    def dump_summary(self, d=None):
        if d is None:
            d = DumpOptions()
        d.write(uuid_bytes_to_str(self.uuid))

    @classmethod
    def decode(cls, data):
        location = LocationDescriptor.decode(data)
        record_data = location.read_bytes(data)
        signature = record_data.get_uint32()
        if signature == cls.CV_PDB80:
            uuid = record_data.read_size(16)
            age = record_data.get_uint32()
            pdb_name = record_data.get_c_string()
            return cls(location=location,
                       signature=signature,
                       uuid=uuid,
                       age=age,
                       pdb_name=pdb_name)
        elif signature == cls.CV_ELF_BUILD_ID:
            uuid = record_data.read_size(record_data.get_size()-4)
            return cls(location=location, signature=signature, uuid=uuid)
        else:
            raise ValueError("invalid CVRecord signature: %#8.8x" % (signature))

    def encode(self, strm):
        strm.put_uint32(self.signature)
        if self.signature == self.CV_PDB80:
            if len(self.uuid) != 16:
                raise ValueError("invalid size of UUID")
            if file_extract.is_string(self.uuid):
                strm.file.write(self.uuid)
            elif isinstance(self.uuid, list):
                for byte in self.uuid:
                    strm.put_uint8(byte)
            else:
                raise ValueError("invalid CvRecord.uuid type")
            strm.put_uint32(self.age)
            if self.pdb_name is None:
                strm.put_c_string('')
            else:
                strm.put_c_string(self.pdb_name)
        elif self.signature == self.CV_ELF_BUILD_ID:
            if len(self.uuid) != 16 and len(self.uuid) != 20:
                raise ValueError("invalid size of UUID")
            if file_extract.is_string(self.uuid):
                strm.file.write(self.uuid)
            elif isinstance(self.uuid, list):
                for byte in self.uuid:
                    strm.put_uint8(byte)
            else:
                raise ValueError("invalid CvRecord.uuid type")

class VsFixedFileInfo(object):
    '''
        struct VS_FIXEDFILEINFO {
          DWORD dwSignature;
          DWORD dwStrucVersion;
          DWORD dwFileVersionMS;
          DWORD dwFileVersionLS;
          DWORD dwProductVersionMS;
          DWORD dwProductVersionLS;
          DWORD dwFileFlagsMask;
          DWORD dwFileFlags;
          DWORD dwFileOS;
          DWORD dwFileType;
          DWORD dwFileSubtype;
          DWORD dwFileDateMS;
          DWORD dwFileDateLS;
        };
    '''

    @classmethod
    def sizeof(cls):
        return 13*4

    @classmethod
    def decode(cls, data):
        dwSignature = data.get_uint32()
        dwStrucVersion = data.get_uint32()
        dwFileVersionMS = data.get_uint32()
        dwFileVersionLS = data.get_uint32()
        dwProductVersionMS = data.get_uint32()
        dwProductVersionLS = data.get_uint32()
        dwFileFlagsMask = data.get_uint32()
        dwFileFlags = data.get_uint32()
        dwFileOS = data.get_uint32()
        dwFileType = data.get_uint32()
        dwFileSubtype = data.get_uint32()
        dwFileDateMS = data.get_uint32()
        dwFileDateLS = data.get_uint32()
        return cls(dwSignature=dwSignature,
                   dwStrucVersion=dwStrucVersion,
                   dwFileVersionMS=dwFileVersionMS,
                   dwFileVersionLS=dwFileVersionLS,
                   dwProductVersionMS=dwProductVersionMS,
                   dwProductVersionLS=dwProductVersionLS,
                   dwFileFlagsMask=dwFileFlagsMask,
                   dwFileFlags=dwFileFlags,
                   dwFileOS=dwFileOS,
                   dwFileType=dwFileType,
                   dwFileSubtype=dwFileSubtype,
                   dwFileDateMS=dwFileDateMS,
                   dwFileDateLS=dwFileDateLS)

    def encode(self, strm):
        strm.put_uint32(self.dwSignature)
        strm.put_uint32(self.dwStrucVersion)
        strm.put_uint32(self.dwFileVersionMS)
        strm.put_uint32(self.dwFileVersionLS)
        strm.put_uint32(self.dwProductVersionMS)
        strm.put_uint32(self.dwProductVersionLS)
        strm.put_uint32(self.dwFileFlagsMask)
        strm.put_uint32(self.dwFileFlags)
        strm.put_uint32(self.dwFileOS)
        strm.put_uint32(self.dwFileType)
        strm.put_uint32(self.dwFileSubtype)
        strm.put_uint32(self.dwFileDateMS)
        strm.put_uint32(self.dwFileDateLS)

    def __init__(self, dwSignature=0, dwStrucVersion=0, dwFileVersionMS=0,
                 dwFileVersionLS=0, dwProductVersionMS=0, dwProductVersionLS=0,
                 dwFileFlagsMask=0, dwFileFlags=0, dwFileOS=0, dwFileType=0,
                 dwFileSubtype=0, dwFileDateMS=0, dwFileDateLS=0):
        self.dwSignature = dwSignature
        self.dwStrucVersion = dwStrucVersion
        self.dwFileVersionMS = dwFileVersionMS
        self.dwFileVersionLS = dwFileVersionLS
        self.dwProductVersionMS = dwProductVersionMS
        self.dwProductVersionLS = dwProductVersionLS
        self.dwFileFlagsMask = dwFileFlagsMask
        self.dwFileFlags = dwFileFlags
        self.dwFileOS = dwFileOS
        self.dwFileType = dwFileType
        self.dwFileSubtype = dwFileSubtype
        self.dwFileDateMS = dwFileDateMS
        self.dwFileDateLS = dwFileDateLS

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        d.write('dwSignature        = %#8.8x\n' % (self.dwSignature))
        d.write('dwStrucVersion     = %#8.8x\n' % (self.dwStrucVersion))
        d.write('dwFileVersionMS    = %#8.8x\n' % (self.dwFileVersionMS))
        d.write('dwFileVersionLS    = %#8.8x\n' % (self.dwFileVersionLS))
        d.write('dwProductVersionMS = %#8.8x\n' % (self.dwProductVersionMS))
        d.write('dwProductVersionLS = %#8.8x\n' % (self.dwProductVersionLS))
        d.write('dwFileFlagsMask    = %#8.8x\n' % (self.dwFileFlagsMask))
        d.write('dwFileFlags        = %#8.8x\n' % (self.dwFileFlags))
        d.write('dwFileOS           = %#8.8x\n' % (self.dwFileOS))
        d.write('dwFileType         = %#8.8x\n' % (self.dwFileType))
        d.write('dwFileSubtype      = %#8.8x\n' % (self.dwFileSubtype))
        d.write('dwFileDateMS       = %#8.8x\n' % (self.dwFileDateMS))
        d.write('dwFileDateLS       = %#8.8x\n' % (self.dwFileDateLS))

class Module(object):
    name_to_offset = {
        'BaseOfImage': 0,
        'SizeOfImage': 8,
        'CheckSum': 12,
        'TimeDateStamp': 16,
        'ModuleNameRva': 20,
        'VersionInfo': 24,
        'CvRecord': 24 + VsFixedFileInfo.sizeof(),
        'MiscRecord': 24 + VsFixedFileInfo.sizeof() + LocationDescriptor.sizeof(),
        'Reserved0': 24 + VsFixedFileInfo.sizeof() + LocationDescriptor.sizeof() * 2,
        'Reserved1': 24 + VsFixedFileInfo.sizeof() + LocationDescriptor.sizeof() * 2 + 8
    }
    '''
        struct MINIDUMP_MODULE {
          ULONG64                      BaseOfImage;
          ULONG32                      SizeOfImage;
          ULONG32                      CheckSum;
          ULONG32                      TimeDateStamp;
          RVA                          ModuleNameRva;
          VS_FIXEDFILEINFO             VersionInfo;
          MINIDUMP_LOCATION_DESCRIPTOR CvRecord;
          MINIDUMP_LOCATION_DESCRIPTOR MiscRecord;
          ULONG64                      Reserved0;
          ULONG64                      Reserved1;
        }
    '''
    @classmethod
    def sizeof(cls):
        return 108

    @classmethod
    def offsetof(cls, name):
        if name in cls.name_to_offset:
            return cls.name_to_offset[name]
        raise ValueError('invalid member name of MINIDUMP_MODULE')

    def contains_addr(self, addr):
        return self.BaseOfImage <= addr and addr < (self.BaseOfImage + self.SizeOfImage)

    def __eq__(self, other):
        return self.BaseOfImage == other.BaseOfImage and self.SizeOfImage == other.SizeOfImage

    def __lt__(self, other):
        return self.BaseOfImage < other.BaseOfImage

    @classmethod
    def decode(cls, data):
        BaseOfImage = data.get_uint64()
        SizeOfImage = data.get_uint32()
        CheckSum = data.get_uint32()
        TimeDateStamp = data.get_uint32()
        ModuleNameRva = data.get_uint32()
        VersionInfo = VsFixedFileInfo.decode(data)
        CvRecord = CvRecordType.decode(data)
        MiscRecord = LocationDescriptor.decode(data)
        Reserved0 = data.get_uint64()
        Reserved1 = data.get_uint64()
        ModuleName = String.decode(data, ModuleNameRva)
        return cls(BaseOfImage=BaseOfImage, SizeOfImage=SizeOfImage,
                   CheckSum=CheckSum, TimeDateStamp=TimeDateStamp,
                   ModuleNameRva=ModuleNameRva, ModuleName=ModuleName,
                   VersionInfo=VersionInfo, CvRecord=CvRecord,
                   MiscRecord=MiscRecord, Reserved0=Reserved0,
                   Reserved1=Reserved1)

    def encode(self, strm):
        strm.put_uint64(self.BaseOfImage)
        strm.put_uint32(self.SizeOfImage)
        strm.put_uint32(self.CheckSum)
        strm.put_uint32(self.TimeDateStamp)
        strm.put_uint32(self.ModuleNameRva)
        self.VersionInfo.encode(strm)
        self.CvRecord.encode(strm)
        self.MiscRecord.encode(strm)
        strm.put_uint64(self.Reserved0)
        strm.put_uint64(self.Reserved1)

    def __init__(self, BaseOfImage=0, SizeOfImage=0, CheckSum=0,
                 TimeDateStamp=0, ModuleNameRva=0, ModuleName=None,
                 VersionInfo=None, CvRecord=None, MiscRecord=None,
                 Reserved0=0, Reserved1=0):
        self.BaseOfImage = BaseOfImage
        self.SizeOfImage = SizeOfImage
        self.CheckSum = CheckSum
        self.TimeDateStamp = TimeDateStamp
        self.ModuleNameRva = ModuleNameRva
        self.ModuleName = ModuleName
        if VersionInfo is None:
            self.VersionInfo = VsFixedFileInfo()
        else:
            self.VersionInfo = VersionInfo
        if CvRecord is None:
            self.CvRecord = LocationDescriptor()
        else:
            self.CvRecord = CvRecord
        if MiscRecord is None:
            self.MiscRecord = LocationDescriptor()
        else:
            self.MiscRecord = MiscRecord
        self.Reserved0 = Reserved0
        self.Reserved1 = Reserved1

    def get_path(self):
        return self.ModuleName.utf8

    def dump_summary(self, d=None):
        if d is None:
            d = DumpOptions()
        d.write('%#16.16x: %s %s\n' % (self.BaseOfImage,
                                       uuid_bytes_to_str(self.CvRecord.uuid),
                                       self.ModuleName.utf8))

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        if not d.has_prefix():
            d.write('MINIDUMP_MODULE:\n')
        w = 24
        d.write_attr_hex64(w, self, 'BaseOfImage')
        d.write_attr_hex32(w, self, 'SizeOfImage')
        d.write_attr_hex32(w, self, 'CheckSum')
        d.write_attr_hex32(w, self, 'TimeDateStamp')
        if self.ModuleName is not None:
            d.write_attr_hex32(w, self, 'ModuleNameRva', ' "%s"' % (
                self.ModuleName.utf8))
        else:
            d.write_attr_hex32(w, self, 'ModuleNameRva')
        d.write_attr_dump(w, self, 'VersionInfo')
        d.write_attr_dump(w, self, 'CvRecord')
        d.write_attr_dump(w, self, 'MiscRecord')
        d.write_attr_hex64(w, self, 'Reserved0')
        d.write_attr_hex64(w, self, 'Reserved1')


class ModuleList(object):
    '''
        struct MINIDUMP_MODULE_LIST {
          ULONG32         NumberOfModules;
          MINIDUMP_MODULE Modules[];
        };
    '''

    def __init__(self, NumberOfModules=0, Modules=None):
        self.NumberOfModules = NumberOfModules
        self.SortedModules = None
        if Modules is None:
            self.Modules = []
        else:
            self.Modules = Modules

    def find_module_for_address(self, addr):
        if not self.Modules:
            return None
        if self.SortedModules is None:
            self.SortedModules = sorted(self.Modules)
        idx = bisect.bisect(self.SortedModules, Module(BaseOfImage=addr, SizeOfImage=1))
        if idx < len(self.SortedModules) and self.SortedModules[idx].contains_addr(addr):
            return self.SortedModules[idx]
        if idx > 0:
            idx -= 1
            if idx < len(self.SortedModules) and self.SortedModules[idx].contains_addr(addr):
                return self.SortedModules[idx]
        return None

    @classmethod
    def decode(cls, data, size):
        NumberOfModules = data.get_uint32()
        if 4 + NumberOfModules * Module.sizeof() < size:
            data.get_uint32()
        Modules = []
        for _i in range(NumberOfModules):
            module = Module.decode(data)
            Modules.append(module)
        return cls(NumberOfModules, Modules)

    def encode(self, strm, pad=False):
        strm.put_uint32(self.NumberOfModules)
        if pad:
            strm.put_uint32(0)
        for module in self.Modules:
            module.encode(strm)

    def append(self, module):
        self.Modules.append(module)
        self.NumberOfModules = len(self.Modules)


    def dump_summary(self, d=None):
        if d is None:
            d = DumpOptions()
        w = 15
        for module in self.Modules:
            module.dump_summary(d)

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        w = 15
        d.write('MINIDUMP_MODULE_LIST:\n')
        d.write_attr_hex32(w, self, 'NumberOfModules')
        d.write_attr_dump(w, self, 'Modules')


class String(object):
    '''
        struct MINIDUMP_STRING {
            ULONG32 Length;
            WCHAR   Buffer[];
        }
    '''
    def __init__(self, utf8=''):
        self.utf8 = utf8

    @classmethod
    def decode(cls, data, Offset):
        if Offset == 0:
            return None
        data.push_offset_and_seek(Offset)
        Length = data.get_uint32()
        Buffer = []
        unicode_str = u''
        for _i in range(Length//2):
            wchar = data.get_uint16()
            Buffer.append(wchar)
            unicode_str += chr(wchar)
        data.pop_offset_and_seek()
        return cls(unicode_str.encode('utf-8').decode('utf-8'))

    def encode(self, strm):
        utf16 = self.utf8.encode('utf-16')[2:]
        strm.put_uint32(len(utf16))
        strm.file.write(utf16)

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        f = d.f
        f.write(self.utf8)
        f.write('\n')


class X86CpuInfo(object):
    '''
        struct X86CpuInfo {
          ULONG32 VendorId[3];
          ULONG32 VersionInformation;
          ULONG32 FeatureInformation;
          ULONG32 AMDExtendedCpuFeatures;
        };
    '''

    def __init__(self, VendorId=None, VersionInformation=0,
                 FeatureInformation=0, AMDExtendedCpuFeatures=0):
        if VendorId is None:
            self.VendorId = []
            for _i in range(3):
                self.VendorId.append(0)
        else:
            self.VendorId = VendorId
        self.VersionInformation = VersionInformation
        self.FeatureInformation = FeatureInformation
        self.AMDExtendedCpuFeatures = AMDExtendedCpuFeatures

    @classmethod
    def decode(cls, data):
        VendorId = []
        for _i in range(3):
            VendorId.append(data.get_uint32())
        VersionInformation = data.get_uint32()
        FeatureInformation = data.get_uint32()
        AMDExtendedCpuFeatures = data.get_uint32()

    def encode(self, strm):
        for x in self.VendorId:
            strm.put_uint32(x)
        strm.put_uint32(self.VersionInformation)
        strm.put_uint32(self.FeatureInformation)
        strm.put_uint32(self.AMDExtendedCpuFeatures)

    def dump(self, w, d=None):
        if d is None:
            d = DumpOptions()
        d.write_attr_hex32(w, self, 'VendorId')
        d.write_attr_hex32(w, self, 'VersionInformation')
        d.write_attr_hex32(w, self, 'FeatureInformation')
        d.write_attr_hex32(w, self, 'AMDExtendedCpuFeatures')


class OtherCpuInfo(object):
    '''
        struct OtherCpuInfo {
            ULONG64 ProcessorFeatures[2];
        };
    '''
    def __init__(self, ProcessorFeatures=None):
        if ProcessorFeatures is None:
            self.ProcessorFeatures = []
            for _i in range(2):
                self.ProcessorFeatures.append(0)
        else:
            self.ProcessorFeatures = ProcessorFeatures

    @classmethod
    def decode(cls, data):
        ProcessorFeatures = []
        for _i in range(2):
            ProcessorFeatures.append(data.get_uint64())
        # Read pad bytes that make this stream match the size of X86CpuInfo
        data.get_uint64()

    def encode(self, strm):
        for x in self.ProcessorFeatures:
            strm.put_uint64(x)
        # Match size of X86CpuInfo
        strm.put_uint64(0)

    def dump(self, w, d=None):
        if d is None:
            d = DumpOptions()
        d.write_attr_hex64(w, self, 'ProcessorFeatures')


class SystemInfo(object):
    '''
        struct MINIDUMP_SYSTEM_INFO {
          USHORT  ProcessorArchitecture;
          USHORT  ProcessorLevel;
          USHORT  ProcessorRevision;
          union {
            USHORT Reserved0;
            struct {
              UCHAR NumberOfProcessors;
              UCHAR ProductType;
            };
          };
          ULONG32 MajorVersion;
          ULONG32 MinorVersion;
          ULONG32 BuildNumber;
          ULONG32 PlatformId;
          RVA     CSDVersionRva;
          union {
            ULONG32 Reserved1;
            struct {
              USHORT SuiteMask;
              USHORT Reserved2;
            };
          };
          union {
            struct {
              ULONG32 VendorId[3];
              ULONG32 VersionInformation;
              ULONG32 FeatureInformation;
              ULONG32 AMDExtendedCpuFeatures;
            } X86CpuInfo;
            struct {
              ULONG64 ProcessorFeatures[2];
            } OtherCpuInfo;
          } Cpu;
        };
        '''

    def __init__(self, ProcessorArchitecture=0, ProcessorLevel=0,
                 ProcessorRevision=0, NumberOfProcessors=0, ProductType=0,
                 MajorVersion=0, MinorVersion=0, BuildNumber=0,
                 PlatformId=0, CSDVersionRva=0, SuiteMask=0, Reserved2=0,
                 Cpu=None, CSDVersion=None):
        self.ProcessorArchitecture = ProcessorArchitecture
        self.ProcessorLevel = ProcessorLevel
        self.ProcessorRevision = ProcessorRevision
        self.NumberOfProcessors = NumberOfProcessors
        self.ProductType = ProductType
        self.MajorVersion = MajorVersion
        self.MinorVersion = MinorVersion
        self.BuildNumber = BuildNumber
        self.PlatformId = PlatformId
        self.CSDVersionRva = CSDVersionRva
        self.SuiteMask = SuiteMask
        self.Reserved2 = Reserved2
        if Cpu is None:
            if (ProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 or
                    ProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL):
                self.Cpu = X86CpuInfo()
            else:
                self.Cpu = OtherCpuInfo()
        else:
            self.Cpu = Cpu
        if CSDVersion is None:
            self.CSDVersion = String()
        else:
            self.CSDVersion = CSDVersion

    @classmethod
    def decode(cls, data):
        ProcessorArchitecture = data.get_uint16()
        ProcessorLevel = data.get_uint16()
        ProcessorRevision = data.get_uint16()
        NumberOfProcessors = data.get_uint8()
        ProductType = data.get_uint8()
        MajorVersion = data.get_uint32()
        MinorVersion = data.get_uint32()
        BuildNumber = data.get_uint32()
        PlatformId = data.get_uint32()
        CSDVersionRva = data.get_uint32()
        SuiteMask = data.get_uint16()
        Reserved2 = data.get_uint16()
        if (ProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 or
                ProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL):
            Cpu = X86CpuInfo.decode(data)
        else:
            Cpu = OtherCpuInfo.decode(data)
        CSDVersion = String.decode(data, CSDVersionRva)
        return cls(ProcessorArchitecture=ProcessorArchitecture,
                   ProcessorLevel=ProcessorLevel,
                   ProcessorRevision=ProcessorRevision,
                   NumberOfProcessors=NumberOfProcessors,
                   ProductType=ProductType,
                   MajorVersion=MajorVersion,
                   MinorVersion=MinorVersion,
                   BuildNumber=BuildNumber,
                   PlatformId=PlatformId,
                   CSDVersionRva=CSDVersionRva,
                   SuiteMask=SuiteMask,
                   Reserved2=Reserved2,
                   Cpu=Cpu,
                   CSDVersion=CSDVersion)

    def encode(self, strm):
        strm.put_uint16(self.ProcessorArchitecture)
        strm.put_uint16(self.ProcessorLevel)
        strm.put_uint16(self.ProcessorRevision)
        strm.put_uint8(self.NumberOfProcessors)
        strm.put_uint8(self.ProductType)
        strm.put_uint32(self.MajorVersion)
        strm.put_uint32(self.MinorVersion)
        strm.put_uint32(self.BuildNumber)
        strm.put_uint32(self.PlatformId)
        strm.put_uint32(self.CSDVersionRva)
        strm.put_uint16(self.SuiteMask)
        strm.put_uint16(self.Reserved2)
        self.Cpu.encode(strm)

    def get_addr_size(self):
        arch = self.ProcessorArchitecture
        if (arch == PROCESSOR_ARCHITECTURE_AMD64 or
            arch == PROCESSOR_ARCHITECTURE_ARM64 or
            arch == PROCESSOR_ARCHITECTURE_ARM64_BP or
            arch == PROCESSOR_ARCHITECTURE_PPC64):
            return 8
        if (arch == PROCESSOR_ARCHITECTURE_ARM or
            arch == PROCESSOR_ARCHITECTURE_PPC):
            return 4
        raise ValueError("modify this function to support ProcessorArchitecture %s" % (ProcessorArchitectureToStr(arch)))

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        w = 23
        d.write('MINIDUMP_SYSTEM_INFO:\n')
        d.write_attr_hex32(w, self, 'ProcessorArchitecture', ' "%s"' % (
            ProcessorArchitectureToStr(self.ProcessorArchitecture)))
        d.write_attr_hex32(w, self, 'ProcessorLevel')
        d.write_attr_hex32(w, self, 'ProcessorRevision')
        d.write_attr_hex32(w, self, 'NumberOfProcessors')
        d.write_attr_hex32(w, self, 'ProductType')
        d.write_attr_hex32(w, self, 'MajorVersion')
        d.write_attr_hex32(w, self, 'MinorVersion')
        d.write_attr_hex32(w, self, 'BuildNumber')
        d.write_attr_hex32(w, self, 'PlatformId', ' "%s"' % (
            PlatformIDToStr(self.PlatformId)))
        d.write_attr_hex32(w, self, 'CSDVersionRva', ' "%s"' % (
            self.CSDVersion.utf8))
        d.write_attr_hex32(w, self, 'SuiteMask')
        d.write_attr_hex32(w, self, 'Reserved2')
        if self.Cpu is not None:
            self.Cpu.dump(w, d)


class ThreadContext_ARM64(object):
    '''
        struct ThreadContext_ARM64 {
          uint64_t context_flags;
          uint64_t x[32];
          uint64_t pc;
          uint32_t cpsr;
          uint32_t fpsr;
          uint32_t fpcr;
          uint8_t v[32*16];
        };
    '''
    Flag = 0x80000000
    Integer = Flag | 0x00000002
    Float = Flag | 0x00000004

    def __init__(self, context_flags=None, x=None, pc=None, cpsr=None,
                 fpsr=None, fpcr=None, v=None):
        if context_flags is None:
            self.context_flags = self.Flag | self.Integer | self.Float
        else:
            self.context_flags = context_flags
        if x is None:
            self.x = []
            for _i in range(32):
                self.x.append(0)
        else:
            self.x = x
        if pc is None:
            self.pc = 0
        else:
            self.pc = pc
        if cpsr is None:
            self.cpsr = 0
        else:
            self.cpsr = cpsr
        if fpsr is None:
            self.fpsr = 0
        else:
            self.fpsr = fpsr
        if fpcr is None:
            self.fpcr = 0
        else:
            self.fpcr = fpcr
        if v is None:
            self.v = []
            for _i in range(32*16):
                self.v.append(0)
        else:
            self.v = v

    @classmethod
    def decode(cls, data):
        context_flags = data.get_uint64()
        r = []
        for _i in range(32):
            r.append(data.get_uint64())
        pc = data.get_uint64()
        cpsr = data.get_uint32()
        fpsr = data.get_uint32()
        fpcr = data.get_uint32()
        v = []             # Extended
        for _i in range(32*16):
            v.append(data.get_uint8())
        return cls(context_flags, r, pc, cpsr, fpsr, fpcr, v)

    def encode(self, strm):
        strm.put_uint64(self.context_flags)
        for x in self.x:
            strm.put_uint64(x)
        strm.put_uint64(self.pc)
        strm.put_uint32(self.cpsr)
        strm.put_uint32(self.fpsr)
        strm.put_uint32(self.fpcr)
        for v in self.v:
            strm.put_uint8(v)

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        w = 13
        d.write_attr_hex64(w, self, 'context_flags')
        d.write_attr_hex64(w, self, 'x')
        d.write_attr_hex64(w, self, 'pc')
        d.write_attr_hex32(w, self, 'cpsr')
        d.write_attr_hex32(w, self, 'fpsr')
        d.write_attr_hex32(w, self, 'fpcr')
        d.write_attr_hex64(w, self, 'v')


class ThreadContext_ARM(object):
    '''
        struct ThreadContext_ARM {
            uint32_t context_flags;
            uint32_t r[16];
            uint32_t cpsr;
            uint64_t fpscr;
            uint64_t d[32];
            uint32_t extra[8];
        };
    '''
    Flag = 0x40000000
    Integer = Flag | 0x00000002
    Float = Flag | 0x00000004

    def __init__(self, context_flags=None, r=None, cpsr=0, fpscr=0, d=None,
                 extra=None):
        if context_flags is None:
            self.context_flags = self.Flag | self.Integer | self.Float
        else:
            self.context_flags = context_flags

        if r is None:
            self.r = []
            for _i in range(16):
                self.r.append(0)
        else:
            self.r = r
        self.cpsr = cpsr
        self.fpscr = fpscr
        if d is None:
            self.d = []
            for _i in range(32):
                self.d.append(0)
        else:
            self.d = d
        if extra is None:
            self.extra = []
            for _i in range(8):
                self.extra.append(0)
        else:
            self.extra = extra

    @classmethod
    def decode(cls, data):
        context_flags = data.get_uint32()
        r = []
        for _i in range(16):
            r.append(data.get_uint32())
        cpsr = data.get_uint32()
        fpscr = data.get_uint64()
        d = []
        for _i in range(32):
            d.append(data.get_uint64())
        extra = []
        for _i in range(8):
            extra.append(data.get_uint32())
        return cls(context_flags, r, cpsr, fpscr, d, extra)

    def encode(self, strm):
        strm.put_uint32(self.context_flags)
        for r in self.r:
            strm.put_uint32(r)
        strm.put_uint32(self.cpsr)
        strm.put_uint64(self.fpscr)
        for d in self.d:
            strm.put_uint64(d)
        for e in self.extra:
            strm.put_uint32(e)

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        w = 13
        d.write_attr_hex32(w, self, 'context_flags')
        for (i, reg) in enumerate(self.r):
            d.write_hex32(w, 'r%i' % (i), reg)
        d.write_attr_hex32(w, self, 'cpsr')
        d.write_attr_hex64(w, self, 'fpscr')
        for (i, reg) in enumerate(self.d):
            d.write_hex64(w, 'd%i' % (i), reg)
        for (i, reg) in enumerate(self.extra):
            d.write_hex32(w, 'extra[%i]' % (i), reg)


class ThreadContext_x86(object):
    '''
        struct ThreadContext_x86 {
          uint32_t context_flags;
          uint32_t dr0;
          uint32_t dr1;
          uint32_t dr2;
          uint32_t dr3;
          uint32_t dr6;
          uint32_t dr7;
          MinidumpFloatingSaveAreaX86 float_save;
          uint32_t gs;
          uint32_t fs;
          uint32_t es;
          uint32_t ds;
          uint32_t edi;
          uint32_t esi;
          uint32_t ebx;
          uint32_t edx;
          uint32_t ecx;
          uint32_t eax;
          uint32_t ebp;
          uint32_t eip;
          uint32_t cs;
          uint32_t eflags;
          uint32_t esp;
          uint32_t ss;
          uint8_t extended_registers[512];
        };
    '''
    x86_32_Flag = 0x00010000
    Control = x86_32_Flag | 0x00000001
    Integer = x86_32_Flag | 0x00000002
    Segments = x86_32_Flag | 0x00000004
    Float = x86_32_Flag | 0x00000008
    Debug = x86_32_Flag | 0x00000010
    Extended = x86_32_Flag | 0x00000020
    XState = x86_32_Flag | 0x00000040

    def __init__(self, context_flags, dr0, dr1, dr2, dr3, dr6, dr7,
                 control_word, status_word, tag_word, error_offset,
                 error_selector, data_offset, data_selector, register_area,
                 cr0_npx_state, gs, fs, es, ds, edi, esi, ebx, edx, ecx, eax,
                 ebp, eip, cs, eflags, esp, ss, extended_registers):
        self.context_flags = context_flags
        self.dr0 = dr0
        self.dr1 = dr1
        self.dr2 = dr2
        self.dr3 = dr3
        self.dr6 = dr6
        self.dr7 = dr7
        self.control_word = control_word
        self.status_word = status_word
        self.tag_word = tag_word
        self.error_offset = error_offset
        self.error_selector = error_selector
        self.data_offset = data_offset
        self.data_selector = data_selector
        self.register_area = register_area
        self.cr0_npx_state = cr0_npx_state
        self.gs = gs
        self.fs = fs
        self.es = es
        self.ds = ds
        self.edi = edi
        self.esi = esi
        self.ebx = ebx
        self.edx = edx
        self.ecx = ecx
        self.eax = eax
        self.ebp = ebp
        self.eip = eip
        self.cs = cs
        self.eflags = eflags
        self.esp = esp
        self.ss = ss
        self.extended_registers = extended_registers

    @classmethod
    def decode(cls, data):
        context_flags = data.get_uint32()
        dr0 = data.get_uint32()             # Debug
        dr1 = data.get_uint32()             # Debug
        dr2 = data.get_uint32()             # Debug
        dr3 = data.get_uint32()             # Debug
        dr6 = data.get_uint32()             # Debug
        dr7 = data.get_uint32()             # Debug
        control_word = data.get_uint32()    # Float
        status_word = data.get_uint32()     # Float
        tag_word = data.get_uint32()        # Float
        error_offset = data.get_uint32()    # Float
        error_selector = data.get_uint32()  # Float
        data_offset = data.get_uint32()     # Float
        data_selector = data.get_uint32()   # Float
        register_area = []                  # Float
        for _i in range(80):
            register_area.append(data.get_uint8())
        cr0_npx_state = data.get_uint32()   # Float
        gs = data.get_uint32()              # Segments
        fs = data.get_uint32()              # Segments
        es = data.get_uint32()              # Segments
        ds = data.get_uint32()              # Segments
        edi = data.get_uint32()             # Integer
        esi = data.get_uint32()             # Integer
        ebx = data.get_uint32()             # Integer
        edx = data.get_uint32()             # Integer
        ecx = data.get_uint32()             # Integer
        eax = data.get_uint32()             # Integer
        ebp = data.get_uint32()             # Control
        eip = data.get_uint32()             # Control
        cs = data.get_uint32()              # Control
        eflags = data.get_uint32()          # Control
        esp = data.get_uint32()             # Control
        ss = data.get_uint32()              # Control
        extended_registers = []             # Extended
        for _i in range(512):
            extended_registers.append(data.get_uint8())
        return cls(context_flags, dr0, dr1, dr2, dr3, dr6, dr7,
                   control_word, status_word, tag_word, error_offset,
                   error_selector, data_offset, data_selector, register_area,
                   cr0_npx_state, gs, fs, es, ds, edi, esi, ebx, edx, ecx, eax,
                   ebp, eip, cs, eflags, esp, ss, extended_registers)

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        w = 13
        if self.context_flags & ThreadContext_x86_64.Debug:
            d.write_attr_hex32(w, self, 'dr0')
            d.write_attr_hex32(w, self, 'dr1')
            d.write_attr_hex32(w, self, 'dr2')
            d.write_attr_hex32(w, self, 'dr3')
            d.write_attr_hex32(w, self, 'dr6')
            d.write_attr_hex32(w, self, 'dr7')
        if self.context_flags & ThreadContext_x86_64.Float:
            d.write_attr_hex32(w, self, 'control_word')
            d.write_attr_hex32(w, self, 'status_word')
            d.write_attr_hex32(w, self, 'tag_word')
            d.write_attr_hex32(w, self, 'error_offset')
            d.write_attr_hex32(w, self, 'error_selector')
            d.write_attr_hex32(w, self, 'data_offset')
            d.write_attr_hex32(w, self, 'data_selector')
            # TODO: dump register_area
            d.write_attr_hex32(w, self, 'cr0_npx_state')
        if self.context_flags & ThreadContext_x86_64.Segments:
            d.write_attr_hex32(w, self, 'gs')
            d.write_attr_hex32(w, self, 'fs')
            d.write_attr_hex32(w, self, 'es')
            d.write_attr_hex32(w, self, 'ds')
        if self.context_flags & ThreadContext_x86_64.Integer:
            d.write_attr_hex32(w, self, 'edi')
            d.write_attr_hex32(w, self, 'esi')
            d.write_attr_hex32(w, self, 'ebx')
            d.write_attr_hex32(w, self, 'edx')
            d.write_attr_hex32(w, self, 'ecx')
            d.write_attr_hex32(w, self, 'eax')
        if self.context_flags & ThreadContext_x86_64.Control:
            d.write_attr_hex32(w, self, 'ebp')
            d.write_attr_hex32(w, self, 'eip')
            d.write_attr_hex32(w, self, 'cs')
            d.write_attr_hex32(w, self, 'eflags')
            d.write_attr_hex32(w, self, 'esp')
            d.write_attr_hex32(w, self, 'ss')

class ThreadContext_x86_64(object):
    '''
        struct ThreadContext_x86_64 {
          uint64_t p1_home;
          uint64_t p2_home;
          uint64_t p3_home;
          uint64_t p4_home;
          uint64_t p5_home;
          uint64_t p6_home;
          uint32_t context_flags;
          uint32_t mx_csr;
          uint16_t cs;
          uint16_t ds;
          uint16_t es;
          uint16_t fs;
          uint16_t gs;
          uint16_t ss;
          uint32_t eflags;
          uint64_t dr0;
          uint64_t dr1;
          uint64_t dr2;
          uint64_t dr3;
          uint64_t dr6;
          uint64_t dr7;
          uint64_t rax;
          uint64_t rcx;
          uint64_t rdx;
          uint64_t rbx;
          uint64_t rsp;
          uint64_t rbp;
          uint64_t rsi;
          uint64_t rdi;
          uint64_t r8;
          uint64_t r9;
          uint64_t r10;
          uint64_t r11;
          uint64_t r12;
          uint64_t r13;
          uint64_t r14;
          uint64_t r15;
          uint64_t rip;
          union FPR {
            struct  {
              uint16_t control_word;
              uint16_t status_word;
              uint8_t tag_word;
              uint8_t reserved1;
              uint16_t error_opcode;
              uint32_t error_offset;
              uint16_t error_selector;
              uint16_t reserved2;
              uint32_t data_offset;
              uint16_t data_selector;
              uint16_t reserved3;
              uint32_t mx_csr;
              uint32_t mx_csr_mask;
              Uint128 float_registers[8];
              Uint128 xmm_registers[16];
              uint8_t reserved4[96];
            } flt_save;
            struct {
              Uint128 header[2];
              Uint128 legacy[8];
              Uint128 xmm[16];
            } sse_registers;
          };
          Uint128 vector_register[26];
          uint64_t vector_control;
          uint64_t debug_control;
          uint64_t last_branch_to_rip;
          uint64_t last_branch_from_rip;
          uint64_t last_exception_to_rip;
          uint64_t last_exception_from_rip;
        };
    '''
    x86_64_Flag = 0x00100000
    Control = x86_64_Flag | 0x00000001
    Integer = x86_64_Flag | 0x00000002
    Segments = x86_64_Flag | 0x00000004
    Float = x86_64_Flag | 0x00000008
    Debug = x86_64_Flag | 0x00000010
    XState = x86_64_Flag | 0x00000040
    All = Control | Integer | Segments | Debug | XState
    Unset = 0

    @classmethod
    def sizeof(cls):
        return 1232

    def __init__(self, p1_home=Unset, p2_home=Unset, p3_home=Unset,
                 p4_home=Unset, p5_home=Unset, p6_home=Unset,
                 context_flags=All, mx_csr=Unset, cs=Unset, ds=Unset, es=Unset,
                 fs=Unset, gs=Unset, ss=Unset, eflags=Unset, dr0=Unset,
                 dr1=Unset, dr2=Unset, dr3=Unset, dr6=Unset, dr7=Unset,
                 rax=Unset, rcx=Unset, rdx=Unset, rbx=Unset, rsp=Unset,
                 rbp=Unset, rsi=Unset, rdi=Unset, r8=Unset, r9=Unset,
                 r10=Unset, r11=Unset, r12=Unset, r13=Unset, r14=Unset,
                 r15=Unset, rip=Unset):
        self.p1_home = p1_home
        self.p2_home = p2_home
        self.p3_home = p3_home
        self.p4_home = p4_home
        self.p5_home = p5_home
        self.p6_home = p6_home
        self.context_flags = context_flags
        self.mx_csr = mx_csr
        self.cs = cs
        self.ds = ds
        self.es = es
        self.fs = fs
        self.gs = gs
        self.ss = ss
        self.eflags = eflags
        self.dr0 = dr0
        self.dr1 = dr1
        self.dr2 = dr2
        self.dr3 = dr3
        self.dr6 = dr6
        self.dr7 = dr7
        self.rax = rax
        self.rcx = rcx
        self.rdx = rdx
        self.rbx = rbx
        self.rsp = rsp
        self.rbp = rbp
        self.rsi = rsi
        self.rdi = rdi
        self.r8 = r8
        self.r9 = r9
        self.r10 = r10
        self.r11 = r11
        self.r12 = r12
        self.r13 = r13
        self.r14 = r14
        self.r15 = r15
        self.rip = rip

    @classmethod
    def fix_lldb_register_name(cls, lldb_name):
        if lldb_name == 'rflags':
            return 'eflags'
        if lldb_name == 'mxcsr':
            return 'mx_csr'
        return lldb_name

    @classmethod
    def decode(cls, data):
        p1_home = data.get_uint64()
        p2_home = data.get_uint64()
        p3_home = data.get_uint64()
        p4_home = data.get_uint64()
        p5_home = data.get_uint64()
        p6_home = data.get_uint64()
        context_flags = data.get_uint32()
        mx_csr = data.get_uint32()

        # The next register is included with
        # ThreadContext_x86_64.Control
        cs = data.get_uint16()

        # The next 4 registers are included with
        # ThreadContext_x86_64.Segments
        ds = data.get_uint16()
        es = data.get_uint16()
        fs = data.get_uint16()
        gs = data.get_uint16()

        # The next 2 registers are included with
        # ThreadContext_x86_64.Control
        ss = data.get_uint16()
        eflags = data.get_uint32()

        # The next 6 registers are included with
        # ThreadContext_x86_64.Debug
        dr0 = data.get_uint64()
        dr1 = data.get_uint64()
        dr2 = data.get_uint64()
        dr3 = data.get_uint64()
        dr6 = data.get_uint64()
        dr7 = data.get_uint64()

        # The next 4 registers are included with
        # ThreadContext_x86_64.Integer
        rax = data.get_uint64()
        rcx = data.get_uint64()
        rdx = data.get_uint64()
        rbx = data.get_uint64()

        # The next register is included with
        # ThreadContext_x86_64.Control
        rsp = data.get_uint64()

        # The next 11 registers are included with
        # ThreadContext_x86_64.Integer
        rbp = data.get_uint64()
        rsi = data.get_uint64()
        rdi = data.get_uint64()
        r8 = data.get_uint64()
        r9 = data.get_uint64()
        r10 = data.get_uint64()
        r11 = data.get_uint64()
        r12 = data.get_uint64()
        r13 = data.get_uint64()
        r14 = data.get_uint64()
        r15 = data.get_uint64()

        # The next register is included with
        # ThreadContext_x86_64.Control
        rip = data.get_uint64()

        # The next set of registers are included with
        # ThreadContext_x86_64.Float
        # union FPR {
        #     MinidumpXMMSaveArea32AMD64 flt_save;
        #     struct {
        #         Uint128 header[2];
        #         Uint128 legacy[8];
        #         Uint128 xmm[16];
        #     } sse_registers;
        # };
        # Uint128 vector_register[26];
        # uint64_t vector_control = data.get_uint64()

        # The next 5 registers are included with
        # ThreadContext_x86_64.Debug
        # uint64_t debug_control = data.get_uint64()
        # uint64_t last_branch_to_rip = data.get_uint64()
        # uint64_t last_branch_from_rip = data.get_uint64()
        # uint64_t last_exception_to_rip = data.get_uint64()
        # uint64_t last_exception_from_rip = data.get_uint64()
        return cls(p1_home=p1_home, p2_home=p2_home, p3_home=p3_home,
                   p4_home=p4_home, p5_home=p5_home, p6_home=p6_home,
                   context_flags=context_flags, mx_csr=mx_csr, cs=cs, ds=ds,
                   es=es, fs=fs, gs=gs, ss=ss, eflags=eflags, dr0=dr0,
                   dr1=dr1, dr2=dr2, dr3=dr3, dr6=dr6, dr7=dr7, rax=rax,
                   rcx=rcx, rdx=rdx, rbx=rbx, rsp=rsp, rbp=rbp, rsi=rsi,
                   rdi=rdi, r8=r8, r9=r9, r10=r10, r11=r11, r12=r12, r13=r13,
                   r14=r14, r15=r15, rip=rip)

    def encode(self, strm):
        initial_offset = strm.tell()
        strm.put_uint64(self.p1_home)
        strm.put_uint64(self.p2_home)
        strm.put_uint64(self.p3_home)
        strm.put_uint64(self.p4_home)
        strm.put_uint64(self.p5_home)
        strm.put_uint64(self.p6_home)
        strm.put_uint32(self.context_flags)
        strm.put_uint32(self.mx_csr)
        strm.put_uint16(self.cs)
        strm.put_uint16(self.ds)
        strm.put_uint16(self.es)
        strm.put_uint16(self.fs)
        strm.put_uint16(self.gs)
        strm.put_uint16(self.ss)
        strm.put_uint32(self.eflags)
        strm.put_uint64(self.dr0)
        strm.put_uint64(self.dr1)
        strm.put_uint64(self.dr2)
        strm.put_uint64(self.dr3)
        strm.put_uint64(self.dr6)
        strm.put_uint64(self.dr7)
        strm.put_uint64(self.rax)
        strm.put_uint64(self.rcx)
        strm.put_uint64(self.rdx)
        strm.put_uint64(self.rbx)
        strm.put_uint64(self.rsp)
        strm.put_uint64(self.rbp)
        strm.put_uint64(self.rsi)
        strm.put_uint64(self.rdi)
        strm.put_uint64(self.r8)
        strm.put_uint64(self.r9)
        strm.put_uint64(self.r10)
        strm.put_uint64(self.r11)
        strm.put_uint64(self.r12)
        strm.put_uint64(self.r13)
        strm.put_uint64(self.r14)
        strm.put_uint64(self.r15)
        strm.put_uint64(self.rip)
        # Pad out the floating point registers
        end = self.sizeof() + initial_offset
        while strm.tell() < end:
            strm.put_uint8(0)

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        w = 13
        d.write_attr_hex64(w, self, 'p1_home')
        d.write_attr_hex64(w, self, 'p2_home')
        d.write_attr_hex64(w, self, 'p3_home')
        d.write_attr_hex64(w, self, 'p4_home')
        d.write_attr_hex64(w, self, 'p5_home')
        d.write_attr_hex64(w, self, 'p6_home')
        d.write_attr_hex32(w, self, 'context_flags')
        d.write_attr_hex32(w, self, 'mx_csr')

        if self.context_flags & ThreadContext_x86_64.Control:
            d.write_attr_hex32(w, self, 'cs')

        if self.context_flags & ThreadContext_x86_64.Segments:
            d.write_attr_hex16(w, self, 'ds')
            d.write_attr_hex16(w, self, 'es')
            d.write_attr_hex16(w, self, 'fs')
            d.write_attr_hex16(w, self, 'gs')

        if self.context_flags & ThreadContext_x86_64.Control:
            d.write_attr_hex16(w, self, 'ss')
            d.write_attr_hex32(w, self, 'eflags')

        if self.context_flags & ThreadContext_x86_64.Debug:
            d.write_attr_hex64(w, self, 'dr0')
            d.write_attr_hex64(w, self, 'dr1')
            d.write_attr_hex64(w, self, 'dr2')
            d.write_attr_hex64(w, self, 'dr3')
            d.write_attr_hex64(w, self, 'dr6')
            d.write_attr_hex64(w, self, 'dr7')

        if self.context_flags & ThreadContext_x86_64.Integer:
            d.write_attr_hex64(w, self, 'rax')
            d.write_attr_hex64(w, self, 'rcx')
            d.write_attr_hex64(w, self, 'rdx')
            d.write_attr_hex64(w, self, 'rbx')

        if self.context_flags & ThreadContext_x86_64.Control:
            d.write_attr_hex64(w, self, 'rsp')

        if self.context_flags & ThreadContext_x86_64.Integer:
            d.write_attr_hex64(w, self, 'rbp')
            d.write_attr_hex64(w, self, 'rsi')
            d.write_attr_hex64(w, self, 'rdi')
            d.write_attr_hex64(w, self, 'r8')
            d.write_attr_hex64(w, self, 'r9')
            d.write_attr_hex64(w, self, 'r10')
            d.write_attr_hex64(w, self, 'r11')
            d.write_attr_hex64(w, self, 'r12')
            d.write_attr_hex64(w, self, 'r13')
            d.write_attr_hex64(w, self, 'r14')
            d.write_attr_hex64(w, self, 'r15')

        if self.context_flags & ThreadContext_x86_64.Control:
            d.write_attr_hex64(w, self, 'rip')


class Thread(object):
    '''
        struct MINIDUMP_THREAD {
          ULONG32                      ThreadId;
          ULONG32                      SuspendCount;
          ULONG32                      PriorityClass;
          ULONG32                      Priority;
          ULONG64                      Teb;
          MINIDUMP_MEMORY_DESCRIPTOR   Stack;
          MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
        };
    '''

    @classmethod
    def sizeof(cls):
        return 48

    def __init__(self, ThreadId, SuspendCount=0, PriorityClass=0, Priority=0,
                 Teb=0, Stack=None, ThreadContext=None, Registers=None):
        self.ThreadId = ThreadId
        self.SuspendCount = SuspendCount
        self.PriorityClass = PriorityClass
        self.Priority = Priority
        self.Teb = Teb
        if Stack is None:
            self.Stack = MemoryDescriptor(0, LocationDescriptor())
        else:
            self.Stack = Stack
        if ThreadContext is None:
            self.ThreadContext = LocationDescriptor()
        else:
            self.ThreadContext = ThreadContext
        self.Registers = Registers

    @classmethod
    def decode(cls, data, thread_context_cls):
        obj = cls(data.get_uint32(), data.get_uint32(), data.get_uint32(),
                  data.get_uint32(), data.get_uint64(),
                  MemoryDescriptor.decode(data),
                  LocationDescriptor.decode(data))
        if thread_context_cls:
            data.push_offset_and_seek(obj.ThreadContext.Rva)
            obj.Registers = thread_context_cls.decode(data)
            data.pop_offset_and_seek()
        return obj

    def encode(self, strm):
        strm.put_uint32(self.ThreadId)
        strm.put_uint32(self.SuspendCount)
        strm.put_uint32(self.PriorityClass)
        strm.put_uint32(self.Priority)
        strm.put_uint64(self.Teb)
        self.Stack.encode(strm)
        self.ThreadContext.encode(strm)

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        w = 16
        d.write_attr_hex32(w, self, 'ThreadId')
        d.write_attr_hex32(w, self, 'SuspendCount')
        d.write_attr_hex32(w, self, 'PriorityClass')
        d.write_attr_hex32(w, self, 'Priority')
        d.write_attr_hex64(w, self, 'Teb')
        flat_d = d.set_flat(True)
        flat_d.write_attr_dump(w, self, 'Stack')
        flat_d.write_attr_dump(w, self, 'ThreadContext')
        d.write_attr_dump(w, self, 'Registers')


class ThreadList(object):
    '''
        struct MINIDUMP_THREAD_LIST {
          ULONG32         NumberOfThreads;
          # Possibly pad extra 4 bytes
          MINIDUMP_THREAD Threads[];
        };
    '''
    def __init__(self, NumberOfThreads=0, Threads=None):
        self.NumberOfThreads = NumberOfThreads
        if Threads is None:
            self.Threads = []
        else:
            self.Threads = Threads

    @classmethod
    def decode(cls, data, size, thread_context_cls):
        NumberOfThreads = data.get_uint32()
        if 4 + NumberOfThreads * Thread.sizeof() < size:
            data.get_uint32()
        Threads = []
        for _i in range(NumberOfThreads):
            thread = Thread.decode(data, thread_context_cls)
            Threads.append(thread)
        return cls(NumberOfThreads, Threads)

    def encode(self, strm, pad=False):
        strm.put_uint32(self.NumberOfThreads)
        if pad:
            strm.put_uint32(0)
        for thread in self.Threads:
            thread.encode(strm)

    def append(self, thread):
        self.Threads.append(thread)
        self.NumberOfThreads = len(self.Threads)

    def dump(self, d=None):
        if d is None:
            d = DumpOptions()
        w = 15
        d.write('MINIDUMP_THREAD_LIST:\n')
        d.write_attr_unsigned(w, self, 'NumberOfThreads')
        d.write_attr_dump(w, self, 'Threads')


class LinuxMap(object):
    def __init__(self, line):
        pass


class Minidump(object):
    '''A class that represents a windows minidump file.'''
    def __init__(self, path):
        self.path = path
        self.data = file_extract.FileExtract(open(path, 'rb'),
                                             byte_order='little',
                                             addr_size=4)
        self.header = Header.decode(self.data)
        self.directories = None
        self.system_info = None
        self.exceptions = None
        self.thread_list = None
        self.memory_list = None
        self.memory64_list = None
        self.memory_info_list = None
        self.module_list = None
        self.linux_maps = []

    def get_thread_stack_modules(self):
        '''
            Parse all thread stacks and grab any aligned pointers we find and
            look the addresses up and see which ones point to sections in
            modules. Return a list of Module objects that match. This will help
            debuggers only load the shared libraries that are needed for doing
            stack backtraces.
        '''
        module_list = self.get_module_list()

        path_to_module = {}
        thread_list = self.get_thread_list()
        if thread_list:
            for thread in thread_list.Threads:
                stack_data = thread.Stack.Memory.read_bytes(self.data)
                stack_size = stack_data.get_size()
                num_ptrs = stack_size / stack_data.get_addr_size()
                for i in range(num_ptrs):
                    ptr = stack_data.get_address()
                    module = module_list.find_module_for_address(ptr)
                    if module:
                        path = module.get_path()
                        if not path in path_to_module:
                            path_to_module[path] = module
        return path_to_module.values()

    def get_directories(self):
        if self.directories is None:
            self.directories = []
            if self.valid():
                self.data.push_offset_and_seek(self.header.StreamDirectoryRva)
                for _i in range(self.header.NumberOfStreams):
                    self.directories.append(Directory.decode(self.data))
                self.data.pop_offset_and_seek()
        return self.directories

    def find_directory(self, StreamType):
        dirs = self.get_directories()
        for dir in dirs:
            if dir.StreamType == StreamType:
                return dir
        return None

    def get_directory_data(self, StreamType):
        dir = self.find_directory(StreamType)
        if dir:
            self.data.seek(dir.Location.Rva)
            return (self.data, dir.Location.DataSize)
        return (None, 0)

    def get_exceptions(self):
        if self.exceptions is None:
            self.exceptions = []
            for dir in self.get_directories():
                if dir.StreamType == ExceptionStream:
                    self.data.seek(dir.Location.Rva)
                    self.exceptions.append(ExceptionInfo(self.data))
        return self.exceptions

    def get_thread_list(self):
        if self.thread_list is None:
            thread_ctx_cls = None
            system_info = self.get_system_info()
            if system_info:
                if system_info.ProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64:
                    thread_ctx_cls = ThreadContext_x86_64
                elif system_info.ProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL:
                    thread_ctx_cls = ThreadContext_x86
                elif system_info.ProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 or system_info.ProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64_BP:
                    thread_ctx_cls = ThreadContext_ARM64
                elif system_info.ProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM:
                    thread_ctx_cls = ThreadContext_ARM
                else:
                    raise ValueError('unsupported thread registers for architure')
            (data, size) = self.get_directory_data(ThreadListStream)
            if data is not None:
                self.thread_list = ThreadList.decode(data, size,
                                                     thread_ctx_cls)
        return self.thread_list

    def get_memory_list(self):
        if self.memory_list is None:
            (data, size) = self.get_directory_data(MemoryListStream)
            if data is not None:
                self.memory_list = MemoryList.decode(data, size)
        return self.memory_list

    def get_memory64_list(self):
        if self.memory64_list is None:
            (data, size) = self.get_directory_data(Memory64ListStream)
            if data is not None:
                self.memory64_list = Memory64List.decode(data, size)
        return self.memory64_list

    def get_memory_info_list(self):
        if self.memory_info_list is None:
            (data, size) = self.get_directory_data(MemoryInfoListStream)
            if data is not None:
                self.memory_info_list = MemoryInfoList(data)
        return self.memory_info_list

    def get_module_list(self):
        if self.module_list is None:
            (data, size) = self.get_directory_data(ModuleListStream)
            if data is not None:
                self.module_list = ModuleList.decode(data, size)
        return self.module_list

    def get_system_info(self):
        if self.system_info is None:
            (data, size) = self.get_directory_data(SystemInfoStream)
            if data is not None:
                self.system_info = SystemInfo.decode(data)
        return self.system_info

    def valid(self):
        return self.header is not None and self.header.valid()

    def get_facebook_build_id(self):
        (data, size) = self.get_directory_data(FacebookAppBuildID)
        if data:
            return data.get_uint32()
        return None

    def get_facebook_app_data(self):
        (data, size) = self.get_directory_data(FacebookAppCustomData)
        if data:
            json_str = data.get_c_string()
            dec = json.JSONDecoder()
            (app_data, json_len) = dec.raw_decode(json_str)
            return app_data
        return None

    def get_facebook_device_fingerprint(self):
        app_data = self.get_facebook_app_data()
        if app_data and 'global' in app_data:
            g = app_data['global']
            if 'Fingerprint' in g:
                return g['Fingerprint']
        return None

    def get_facebook_device_hash(self):
        fingerprint = self.get_facebook_device_fingerprint()
        if fingerprint:
            return hashlib.sha1(fingerprint.encode("ascii")).hexdigest()
        return None

    def dump(self, options=None, d=None):
        if d is None:
            d = DumpOptions()

        if not self.valid():
            d.write('error: invalid minidump file\n')
            return

        system_info = self.get_system_info()
        if options and options.arch is not None:
            if system_info is not None:
                if system_info.ProcessorArchitecture != options.arch:
                    d.write("error: skipping this minidump file -- architecture %#8.8x != %#8.8x (%s)\n" % (system_info.ProcessorArchitecture, options.arch, self.path))
                    return

        if options and options.module_summary:
            module_list = self.get_module_list()
            if module_list:
                module_list.dump_summary(d)
                d.write('\n')
            return
        if options and options.lookup_addr is not None:
            module_list = self.get_module_list()
            if module_list:
                m = module_list.find_module_for_address(options.lookup_addr)
                if m:
                    m.dump_summary(d=d)
                    d.write('\n')
                else:
                    d.write('error: no module contains %#x\n' % (
                            options.lookup_addr))
            return
        if options and options.module_dups:
            module_list = self.get_module_list()
            path_to_load_addrs = {}
            if module_list:
                for module in module_list.Modules:
                    path = module.get_path()
                    if path in path_to_load_addrs:
                        path_to_load_addrs[path].append(module)
                    else:
                        path_to_load_addrs[path] = [module]
            for path in path_to_load_addrs:
                path_modules = path_to_load_addrs[path]
                count = len(path_modules)
                if count > 1:
                    d.write('"%s" loaded %i times:\n' % (path, count))
                    for module in path_modules:
                        module.dump_summary(d)
            return

        self.header.dump(d)
        dirs = self.get_directories()
        d.write('\nMINIDUMP_DIRECTORY[%u]:\n' % (
            self.header.NumberOfStreams))
        Directory.dump_header(d)
        for dir in dirs:
            dir.dump(d.set_flat(True))
            # self.data.seek(dir.Location.Rva)
            # self.data.read_data(dir.Location.DataSize).dump(
            #     offset=dir.Location.Rva)
        d.write('\n')

        if system_info:
            system_info.dump(d)
            d.write('\n')

        thread_list = self.get_thread_list()
        if thread_list:
            thread_list.dump(d)
            d.write('\n')

        memory_list = self.get_memory_list()
        if memory_list:
            memory_list.dump(d)
            d.write('\n')

        memory64_list = self.get_memory64_list()
        if memory64_list:
            memory64_list.dump(d)
            d.write('\n')

        memory_info_list = self.get_memory_info_list()
        if memory_info_list:
            memory_info_list.dump(d)
            d.write('\n')

        module_list = self.get_module_list()
        if module_list:
            module_list.dump(d)
            d.write('\n')

        exceptions = self.get_exceptions()
        for ex in exceptions:
            ex.dump(d)
            d.write('\n')
        (data, size) = self.get_directory_data(BreakpadInfo)
        if data:
            d.write('BreakpadInfo:\n')
            d.write(data.get_c_string())
            d.write('\n')
        (data, size) = self.get_directory_data(BreakpadAssertionInfo)
        if data:
            d.write('Assertion Info:\n')
            d.write(data.get_c_string())
            d.write('\n')
        (data, size) = self.get_directory_data(BreakpadLinuxCPUInfo)
        if data:
            d.write('/proc/cpuinfo:\n')
            d.write(data.get_c_string())
            d.write('\n')
        (data, size) = self.get_directory_data(BreakpadLinuxProcStatus)
        if data:
            d.write('/proc/<pid>/status:\n')
            d.write(data.get_c_string())
            d.write('\n')
        (data, size) = self.get_directory_data(BreakpadLinuxLSBRelease)
        if data:
            d.write('/etc/lsb-release:\n')
            d.write(data.get_c_string())
            d.write('\n')
        (data, size) = self.get_directory_data(BreakpadLinuxCMDLine)
        if data:
            d.write('/proc/<pid>/cmdline:\n')
            d.write(data.get_c_string())
            d.write('\n\n')
        (data, size) = self.get_directory_data(BreakpadLinuxEnviron)
        if data:
            d.write('/proc/<pid>/environ:\n')
            d.write(data.get_c_string())
            d.write('\n\n')
        # (data, size) = self.get_directory_data(BreakpadLinuxAuxv)
        # if data:
        #     d.write('/proc/<pid>/auxv:\n')
        #     d.write(data)
        #     d.write('\n')
        (data, size) = self.get_directory_data(BreakpadLinuxMaps)
        if data:
            d.write('/proc/<pid>/maps:\n')
            d.write(data.get_c_string())
            d.write('\n')
        # (data, size) = self.get_directory_data(BreakpadLinuxDSODebug)
        # if data:
        #     d.write('BreakpadLinuxDSODebug:\n')
        #     d.write(data)
        #     d.write('\n')
        (data, size) = self.get_directory_data(FacebookAppCustomData)
        if data:
            d.write('Facebook App Custom Data:\n')
            json_str = data.get_c_string()
            (custom_data, json_len) = json.JSONDecoder().raw_decode(json_str)
            pprint.PrettyPrinter(indent=4,stream=d).pprint(custom_data)
            d.write('\n')
        (data, size) = self.get_directory_data(FacebookAppBuildID)
        if data:
            d.write('Facebook build-id:\n')
            d.write('%i\n' % (data.get_uint32()))
            d.write('\n')
        (data, size) = self.get_directory_data(FacebookAppVersionName)
        if data:
            d.write('Facebook App Version:\n')
            d.write(data.get_c_string())
            d.write('\n\n')
        (data, size) = self.get_directory_data(FacebookJavaStack)
        if data:
            d.write('Facebook Java Stack:\n')
            d.write(data.get_c_string())
            d.write('\n')
        (data, size) = self.get_directory_data(FacebookDalvikInfo)
        if data:
            d.write('FacebookDalvikInfo:\n')
            d.write(data.get_c_string())
            d.write('\n')
        (data, size) = self.get_directory_data(FacebookUnwindSymbols)
        if data:
            d.write('FacebookUnwindSymbols:\n')
            d.write(data.get_c_string())
            d.write('\n')
        (data, size) = self.get_directory_data(FacebookDumpErrorLog)
        if data:
            d.write('Facebook Dump Error Log:\n')
            d.write(data.get_c_string())
            d.write('\n')
        (data, size) = self.get_directory_data(FacebookAppStateLog)
        if data:
            d.write('Facebook App State Log:\n')
            d.write(data.get_c_string())
            d.write('\n')
        (data, size) = self.get_directory_data(FacebookAbortReason)
        if data:
            d.write('Facebook Abort Reason:\n')
            d.write(data.get_c_string())
            d.write('\n')
        (data, size) = self.get_directory_data(FacebookThreadName)
        if data:
            d.write('Facebook Thread Name:\n')
            d.write(data.get_c_string())
            d.write('\n\n')
        (data, size) = self.get_directory_data(FacebookLogcat)
        if data:
            d.write('Facebook Logcat:\n')
            d.write(data.get_c_string())
            d.write('\n')
        (data, size) = self.get_directory_data(FacebookStreamMarkers)
        if data:
            d.write('Facebook Stream Markers:\n')
            d.write('  start = %#16.16x\n' % (data.get_uint64()))
            d.write('    end = %#16.16x\n' % (data.get_uint64()))
            d.write('\n')
        (data, size) = self.get_directory_data(FacebookUnwindStackSymbols)
        if data:
            d.write('Facebook Unwind Stack Symbols:\n')
            data.read_data(size).dump(num_per_line=16, f=d)
            d.write('\n')

class Generator(object):
    '''A class for producing minidump files.'''
    def __init__(self, system_info=None, ProcessId=0):
        self.header = Header(Signature=Header.Magic, Version=0xa793)
        self.misc_info = MiscInfo(ProcessId=ProcessId)
        if system_info is None:
            self.system_info = SystemInfo()
        else:
            self.system_info = system_info
        self.thread_list = ThreadList()
        self.module_list = ModuleList()
        self.memory_list = MemoryList()
        self.memory64_list = Memory64List()
        self.stream_to_string = {}

    def add_thread(self, thread):
        self.thread_list.append(thread)

    def add_module(self, module):
        self.module_list.append(module)

    def add_memory(self, memory):
        self.memory_list.append(memory)

    def add_memory64(self, memory):
        self.memory64_list.append(memory)

    def add_stream_as_string(self, StreamType, Str):
        self.stream_to_string[StreamType] = Str

    def add_lldb_thread(self, thread, thread_ctx_cls):
        import lldb
        frame = thread.GetFrameAtIndex(0)
        sp = frame.GetSP()
        stack_region = lldb.SBMemoryRegionInfo()
        stack = MemoryDescriptor(0, LocationDescriptor())
        if thread.GetProcess().GetMemoryRegionInfo(sp, stack_region).Success():
            stack_base = stack_region.GetRegionBase()
            stack_end = stack_region.GetRegionEnd()
            stack.StartOfMemoryRange = stack_base
            stack.Memory.DataSize = stack_end - stack_base
        context_loc = LocationDescriptor()
        thread = Thread(thread.GetThreadID(), 0, 0, 0, 0, stack, context_loc,
                        thread_ctx_cls())
        reg_sets = frame.GetRegisters()
        for reg_set in reg_sets:
            for reg in reg_set:
                name = thread_ctx_cls.fix_lldb_register_name(reg.GetName())
                if hasattr(thread.Registers, name):
                    setattr(thread.Registers, name, int(reg.GetValue(), 0))
        self.threads.append(thread)

    def save(self, path, pad):
        data = file_extract.FileEncode(byte_order='little',
                                       addr_size=self.system_info.get_addr_size())
        self.encode(data, pad)
        with open(path, "wb") as f:
            f.write(data.file.getvalue())
            f.close()

    def encode(self, data, pad):
        byte_order = data.get_byte_order()
        addr_size = data.get_addr_size()
        directory_list = []

        system_info_data = file_extract.FileEncode(byte_order=byte_order, addr_size=addr_size)
        self.system_info.encode(system_info_data)
        # print("SystemInfoStream data:")
        # system_info_data.dump()
        directory_list.append((SystemInfoStream, system_info_data))

        misc_info_data = file_extract.FileEncode(byte_order=byte_order, addr_size=addr_size)
        self.misc_info.encode(misc_info_data)
        # print("MiscInfoStream data:")
        # misc_info_data.dump()
        directory_list.append((MiscInfoStream, misc_info_data))

        if self.thread_list.NumberOfThreads > 0:
            thread_list_data = file_extract.FileEncode(byte_order=byte_order, addr_size=addr_size)
            self.thread_list.encode(thread_list_data, pad)
            directory_list.append((ThreadListStream, thread_list_data))

        if self.module_list.NumberOfModules > 0:
            module_list_data = file_extract.FileEncode(byte_order=byte_order, addr_size=addr_size)
            self.module_list.encode(module_list_data, pad)
            # print("ModuleListStream data:")
            # module_list_data.dump()
            directory_list.append((ModuleListStream, module_list_data))

        if self.memory_list.NumberOfMemoryRanges > 0:
            memory_list_data = file_extract.FileEncode(byte_order=byte_order, addr_size=addr_size)
            self.memory_list.encode(memory_list_data, pad)
            directory_list.append((MemoryListStream, memory_list_data))

        if self.memory64_list.NumberOfMemoryRanges > 0:
            memory64_list_data = file_extract.FileEncode(byte_order=byte_order, addr_size=addr_size)
            self.memory64_list.encode(memory64_list_data, pad)
            directory_list.append((Memory64ListStream, memory64_list_data))

        for StreamType in self.stream_to_string:
            stream_data = file_extract.FileEncode(byte_order=byte_order, addr_size=addr_size)
            stream_data.put_c_string(self.stream_to_string[StreamType])
            directory_list.append((StreamType, stream_data))

        self.header.NumberOfStreams = len(directory_list)
        # Make directory info immediately follow the header.
        self.header.StreamDirectoryRva = Header.sizeof()
        # Write the header to the output
        self.header.encode(data)
        FirstStreamDataRva = (self.header.StreamDirectoryRva +
                              self.header.NumberOfStreams * Directory.sizeof())

        StreamDataRva = FirstStreamDataRva
        for (stream_type, stream_data) in directory_list:
            stream_bytes = stream_data.file.getvalue()
            DataSize = len(stream_bytes)
            stream_loc = LocationDescriptor(DataSize, StreamDataRva)
            StreamDataRva += DataSize
            dir = Directory(stream_type, stream_loc)
            # Write the directory info to the output
            dir.encode(data)

        ActualFirstStreamDataRva = data.tell()
        if ActualFirstStreamDataRva != FirstStreamDataRva:
            print('error: FirstStreamDataRva was calculated to be %#x when it'
                  ' is %#x' % (FirstStreamDataRva, ActualFirstStreamDataRva))

        stream_offsets = {}
        for (stream_type, stream_data) in directory_list:
            stream_offsets[stream_type] = data.tell()
            data.file.write(stream_data.file.getvalue())

        if self.system_info.CSDVersion is not None:
            CSDVersionRVA = data.tell()
            self.system_info.CSDVersion.encode(data)
            RVAOffset = stream_offsets[SystemInfoStream] + 24
            data.fixup_uint_size(4, CSDVersionRVA, RVAOffset)

        # Write out thread stacks and registers if needed and fixup offsets
        if self.thread_list.NumberOfThreads > 0:
            FirstContextRVAOffset = (stream_offsets[ThreadListStream] + 4 +
                                     Thread.sizeof() -
                                     LocationDescriptor.sizeof())
            if pad:
                FirstContextRVAOffset += 4
            for (i, thread) in enumerate(self.thread_list.Threads):
                if thread.Registers is not None:
                    ActualRVA = data.tell()
                    thread.Registers.encode(data)
                    ActualSize = data.tell() - ActualRVA
                    ContextRVAOffset = FirstContextRVAOffset + Thread.sizeof() * i
                    data.fixup_uint_size(4, ActualSize, ContextRVAOffset)
                    data.fixup_uint_size(4, ActualRVA, ContextRVAOffset + 4)

        # Write out any data for module name and update the RVAs in each
        # Module in the module list we already wrote out
        if self.module_list.NumberOfModules > 0:
            # Skip the length field in the ModuleList to point to the first byte
            # in the Module
            FirstRVAOffset = stream_offsets[ModuleListStream] + 4
            if pad:
                FirstRVAOffset += 4
            for (i, module) in enumerate(self.module_list.Modules):
                ModuleRVA = FirstRVAOffset + Module.sizeof() * i
                # Write out the module name and fixup Module.ModuleNameRva in the module
                # list we already wrote out
                ModuleNameRva = data.tell()
                md_str = String(module.ModuleName)
                md_str.encode(data)
                data.fixup_uint_size(4, ModuleNameRva, ModuleRVA + Module.offsetof('ModuleNameRva'))
                # Write out the CvRecord data and fixup the Module.CvRecord LocationDescriptor
                # in the module list we already wrote out
                if module.CvRecord:
                    module.CvRecord.encode_object(data, ModuleRVA + Module.offsetof('CvRecord'))


        # Write out any bytes for memory bytes and update the RVAs in
        # memory list we already wrote out
        if self.memory_list.NumberOfMemoryRanges > 0:
            FirstRVAOffset = stream_offsets[MemoryListStream] + 4 + 12
            if pad:
                FirstRVAOffset += 4
            for (i, memory) in enumerate(self.memory_list.MemoryRanges):
                if memory.Bytes is None:
                    continue
                ActualRVA = data.tell()
                data.file.write(memory.Bytes)
                data.fixup_uint_size(4, ActualRVA,
                        FirstRVAOffset + MemoryDescriptor.sizeof() * i)

        # Write out any bytes for memory 64 bytes and update the Base in
        # memory 64 list we already wrote out
        if self.memory64_list.NumberOfMemoryRanges > 0:
            # Fixup the BaseRva in the Memory64List
            BaseRVAOffset = stream_offsets[Memory64ListStream] + 8
            BaseRva = data.tell()
            print('BaseRva = %#x (offset is %#x)' % (BaseRva, BaseRVAOffset))
            data.fixup_uint_size(8, BaseRva, BaseRVAOffset)

            for (i, memory) in enumerate(self.memory64_list.MemoryRanges):
                if memory.Bytes is None:
                    continue
                data.file.write(memory.Bytes)


def main(argv):

    parser = optparse.OptionParser(
        description='Dump windows minidump files.',
        prog='minidump.py',
        usage='minidump.py [options] <minidump-path> [<minidump-path> ...]',
        add_help_option=True)

    parser.add_option(
        '--verbose',
        action='store_true',
        dest='verbose',
        default=False,
        help='Enable verbose logging.')

    parser.add_option(
        '--module-summary',
        action='store_true',
        dest='module_summary',
        default=False,
        help='Dump a summary of the modules in the minidump file.')

    parser.add_option(
        '--module-dups',
        action='store_true',
        dest='module_dups',
        default=False,
        help='Dump a summary of any modules that are loaded multiple times in the minidump file.')

    parser.add_option(
        '--lookup',
        dest='lookup_addr',
        type='int',
        default=None,
        help='Lookup an address to find which module it belongs to.')

    parser.add_option(
        '--arch',
        type='int',
        dest='arch',
        default = None,
        help='Only dump the minidump if the processor architecture matches this integer value.')

    (options, args) = parser.parse_args(argv)
    for path in args:
        md = Minidump(path)
        if md.valid():
            md.dump(options, DumpOptions(flat=False))
        else:
            print("invalid")


if __name__ == '__main__':
    main(sys.argv[1:])


class MinidumpCommand:
    program = 'minidump'

    @classmethod
    def register_lldb_command(cls, debugger, module_name):
        parser = cls.create_options()
        cls.__doc__ = parser.format_help()
        # Add any commands contained in this module to LLDB
        command = 'command script add -c %s.%s %s' % (module_name,
                                                      cls.__name__,
                                                      cls.program)
        debugger.HandleCommand(command)
        print('The "{0}" command has been installed, type "help {0}" or "{0} '
              '--help" for detailed help.'.format(cls.program))

    @classmethod
    def create_options(cls):
        usage = "usage: %prog [options]"
        description = ('Windows minidump export utility.')
        parser = optparse.OptionParser(description=description,
                                       prog=cls.program,
                                       usage=usage)
        parser.add_option(
            '-v',
            '--verbose',
            action='store_true',
            dest='verbose',
            help='Enable verbose logging.',
            default=False)
        parser.add_option(
            '-o', '--outfile',
            type='string',
            dest='outfile',
            help='The path to the minidump file to create.')

        return parser

    def get_short_help(self):
        return "Windows minidump exporting utility"

    def get_long_help(self):
        return self.help_string

    def __init__(self, debugger, unused):
        self.parser = self.create_options()
        self.help_string = self.parser.format_help()

    def __call__(self, debugger, command, exe_ctx, result):
        import lldb
        # Use the Shell Lexer to properly parse up command options just like a
        # shell would
        command_args = shlex.split(command)
        try:
            (options, args) = self.parser.parse_args(command_args)
        except:
            result.SetError("option parsing failed")
            return

        target = exe_ctx.GetTarget()
        if not target.IsValid():
            print >>result, 'error: invalid target'
            return

        platform = target.GetPlatform()

        process = exe_ctx.GetProcess()
        if not process.GetState() == lldb.eStateStopped:
            print >>result, "error: process must be stopped"
            return
        pid = process.GetProcessID()
        print >> result, "Saving mindump for process %i" % (pid)
        dmp = Generator()
        (arch, vendor, os) = target.GetTriple().split('-')
        print >> result, "arch = %s" % (arch)
        print >> result, "vendor = %s" % (vendor)
        print >> result, "os = %s" % (os)
        thread_ctx_cls = None
        if arch == 'x86_64':
            thread_ctx_cls = ThreadContext_x86_64
            dmp.system_info.ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64
        elif arch == 'x86':
            thread_ctx_cls = ThreadContext_x86
            dmp.system_info.ProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL
        elif arch.startswith('arm64'):
            thread_ctx_cls = ThreadContext_ARM64
            dmp.system_info.ProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM64
        elif arch.startswith('arm'):
            thread_ctx_cls = ThreadContext_ARM
            dmp.system_info.ProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM
        else:
            print >> result, "error: unsupported architecture %s" % (arch)
        dmp.system_info.CSDVersion = String(platform.GetOSDescription())
        dmp.system_info.MajorVersion = platform.GetOSMajorVersion()
        dmp.system_info.MinorVersion = platform.GetOSMinorVersion()
        dmp.system_info.BuildNumber = platform.GetOSUpdateVersion()
        if platform.GetName() == 'host':
            dmp.system_info.NumberOfProcessors = multiprocessing.cpu_count()
        if os == 'macosx':
            dmp.system_info.PlatformId = VER_PLATFORM_MACOSX
        elif os == 'ios' or os == 'tvos' or os == 'watchos':
            dmp.system_info.PlatformId = VER_PLATFORM_IOS
        elif os == 'linux':
            dmp.system_info.PlatformId = VER_PLATFORM_LINUX
        elif os == 'windows':
            dmp.system_info.PlatformId = VER_PLATFORM_WIN32_WINDOWS
        elif os == 'android':
            dmp.system_info.PlatformId = VER_PLATFORM_ANDROID
        else:
            print >> result, "error: unsupported os %s" % (os)
        for thread in process:
            dmp.add_lldb_thread(thread, thread_ctx_cls)

        dump_opts = DumpOptions(f=result)
        dmp.system_info.dump(dump_opts)
        for thread in dmp.threads:
            thread.dump(dump_opts)


def __lldb_init_module(debugger, dict):
    # Register all classes that have a register_lldb_command method
    for _name, cls in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(cls) and callable(getattr(cls,
                                                     "register_lldb_command",
                                                     None)):
            cls.register_lldb_command(debugger, __name__)

