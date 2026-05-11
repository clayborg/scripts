#!/usr/bin/env python3
from ast import List
import binascii
from collections import defaultdict
from enum import IntEnum, IntFlag
import json
import optparse
import os
import io
import subprocess
import sys
import tempfile
import uuid
import zlib

# Local imports
import dwarf.context
import dwarf.options
from dwarf.ranges import AddressRange, AddressRangeList
from file_extract import FileExtract, FileEncode

# typedef uint32_t Elf32_Addr
# typedef uint32_t Elf32_Off
# typedef uint16_t Elf32_Half
# typedef uint32_t Elf32_Word
# typedef uint64_t Elf64_Addr
# typedef uint64_t Elf64_Off
# typedef uint16_t Elf64_Half
# typedef uint32_t Elf64_Word
# typedef uint64_t Elf64_Xword


# e_ident size and indices.
class EI(IntEnum):
    MAG0 = 0        # File identification index.
    MAG1 = 1        # File identification index.
    MAG2 = 2        # File identification index.
    MAG3 = 3        # File identification index.
    CLASS = 4       # File class.
    DATA = 5        # Data encoding.
    VERSION = 6     # File version.
    OSABI = 7       # OS/ABI identification.
    ABIVERSION = 8  # ABI version.

    def __str__(self):
        return 'EI_' + self.name


EI_PAD = 9         # Start of padding bytes.
EI_NIDENT = 16     # Number of bytes in e_ident.


# File types
class ET(IntEnum):
    NONE = 0
    REL = 1
    EXEC = 2
    DYN = 3
    CORE = 4
    LOPROC = 0xff00
    HIPROC = 0xffff

    def __str__(self):
        return 'ET_' + self.name


# Versioning
class EV(IntEnum):
    NONE = 0
    CURRENT = 1

    def __str__(self):
        return 'EV_' + self.name


# Machine architectures
class EM(IntEnum):
    EM_NONE = 0   # No machine
    EM_M32 = 1   # AT&T WE 32100
    EM_SPARC = 2   # SPARC
    EM_386 = 3   # Intel 386
    EM_68K = 4   # Motorola 68000
    EM_88K = 5   # Motorola 88000
    EM_IAMCU = 6   # Intel MCU
    EM_860 = 7   # Intel 80860
    EM_MIPS = 8   # MIPS R3000
    EM_S370 = 9   # IBM System/370
    EM_MIPS_RS3_LE = 10  # MIPS RS3000 Little-endian
    EM_PARISC = 15  # Hewlett-Packard PA-RISC
    EM_VPP500 = 17  # Fujitsu VPP500
    EM_SPARC32PLUS = 18  # Enhanced instruction set SPARC
    EM_960 = 19  # Intel 80960
    EM_PPC = 20  # PowerPC
    EM_PPC64 = 21  # PowerPC64
    EM_S390 = 22  # IBM System/390
    EM_SPU = 23  # IBM SPU/SPC
    EM_V800 = 36  # NEC V800
    EM_FR20 = 37  # Fujitsu FR20
    EM_RH32 = 38  # TRW RH-32
    EM_RCE = 39  # Motorola RCE
    EM_ARM = 40  # ARM
    EM_ALPHA = 41  # DEC Alpha
    EM_SH = 42  # Hitachi SH
    EM_SPARCV9 = 43  # SPARC V9
    EM_TRICORE = 44  # Siemens TriCore
    EM_ARC = 45  # Argonaut RISC Core
    EM_H8_300 = 46  # Hitachi H8/300
    EM_H8_300H = 47  # Hitachi H8/300H
    EM_H8S = 48  # Hitachi H8S
    EM_H8_500 = 49  # Hitachi H8/500
    EM_IA_64 = 50  # Intel IA-64 processor architecture
    EM_MIPS_X = 51  # Stanford MIPS-X
    EM_COLDFIRE = 52  # Motorola ColdFire
    EM_68HC12 = 53  # Motorola M68HC12
    EM_MMA = 54  # Fujitsu MMA Multimedia Accelerator
    EM_PCP = 55  # Siemens PCP
    EM_NCPU = 56  # Sony nCPU embedded RISC processor
    EM_NDR1 = 57  # Denso NDR1 microprocessor
    EM_STARCORE = 58  # Motorola Star*Core processor
    EM_ME16 = 59  # Toyota ME16 processor
    EM_ST100 = 60  # STMicroelectronics ST100 processor
    EM_TINYJ = 61  # Advanced Logic Corp. TinyJ embedded processor family
    EM_X86_64 = 62  # AMD x86-64 architecture
    EM_PDSP = 63  # Sony DSP Processor
    EM_PDP10 = 64  # Digital Equipment Corp. PDP-10
    EM_PDP11 = 65  # Digital Equipment Corp. PDP-11
    EM_FX66 = 66  # Siemens FX66 microcontroller
    EM_ST9PLUS = 67  # STMicroelectronics ST9+ 8/16 bit microcontroller
    EM_ST7 = 68  # STMicroelectronics ST7 8-bit microcontroller
    EM_68HC16 = 69  # Motorola MC68HC16 Microcontroller
    EM_68HC11 = 70  # Motorola MC68HC11 Microcontroller
    EM_68HC08 = 71  # Motorola MC68HC08 Microcontroller
    EM_68HC05 = 72  # Motorola MC68HC05 Microcontroller
    EM_SVX = 73  # Silicon Graphics SVx
    EM_ST19 = 74  # STMicroelectronics ST19 8-bit microcontroller
    EM_VAX = 75  # Digital VAX
    EM_CRIS = 76  # Axis Communications 32-bit embedded processor
    EM_JAVELIN = 77  # Infineon Technologies 32-bit embedded processor
    EM_FIREPATH = 78  # Element 14 64-bit DSP Processor
    EM_ZSP = 79  # LSI Logic 16-bit DSP Processor
    EM_MMIX = 80  # Donald Knuth's educational 64-bit processor
    EM_HUANY = 81  # Harvard University machine-independent object files
    EM_PRISM = 82  # SiTera Prism
    EM_AVR = 83  # Atmel AVR 8-bit microcontroller
    EM_FR30 = 84  # Fujitsu FR30
    EM_D10V = 85  # Mitsubishi D10V
    EM_D30V = 86  # Mitsubishi D30V
    EM_V850 = 87  # NEC v850
    EM_M32R = 88  # Mitsubishi M32R
    EM_MN10300 = 89  # Matsushita MN10300
    EM_MN10200 = 90  # Matsushita MN10200
    EM_PJ = 91  # picoJava
    EM_OPENRISC = 92  # OpenRISC 32-bit embedded processor
    EM_ARC_COMPACT = 93  # ARC International ARCompact processor
    EM_XTENSA = 94  # Tensilica Xtensa Architecture
    EM_VIDEOCORE = 95  # Alphamosaic VideoCore processor
    EM_TMM_GPP = 96  # Thompson Multimedia General Purpose Processor
    EM_NS32K = 97  # National Semiconductor 32000 series
    EM_TPC = 98  # Tenor Network TPC processor
    EM_SNP1K = 99  # Trebia SNP 1000 processor
    EM_ST200 = 100  # STMicroelectronics (www.st.com) ST200
    EM_IP2K = 101  # Ubicom IP2xxx microcontroller family
    EM_MAX = 102  # MAX Processor
    EM_CR = 103  # National Semiconductor CompactRISC microprocessor
    EM_F2MC16 = 104  # Fujitsu F2MC16
    EM_MSP430 = 105  # Texas Instruments embedded microcontroller msp430
    EM_BLACKFIN = 106  # Analog Devices Blackfin (DSP) processor
    EM_SE_C33 = 107  # S1C33 Family of Seiko Epson processors
    EM_SEP = 108  # Sharp embedded microprocessor
    EM_ARCA = 109  # Arca RISC Microprocessor
    EM_UNICORE = 110  # Microprocessor series from PKU-Unity Ltd.
    EM_EXCESS = 111  # eXcess: 16/32/64-bit configurable embedded CPU
    EM_DXP = 112  # Icera Semiconductor Inc. Deep Execution Processor
    EM_ALTERA_NIOS2 = 113  # Altera Nios II soft-core processor
    EM_CRX = 114  # National Semiconductor CompactRISC CRX
    EM_XGATE = 115  # Motorola XGATE embedded processor
    EM_C166 = 116  # Infineon C16x/XC16x processor
    EM_M16C = 117  # Renesas M16C series microprocessors
    EM_DSPIC30F = 118  # Microchip Technology dsPIC30F Digital Signal Controller
    EM_CE = 119  # Freescale Communication Engine RISC core
    EM_M32C = 120  # Renesas M32C series microprocessors
    EM_TSK3000 = 131  # Altium TSK3000 core
    EM_RS08 = 132  # Freescale RS08 embedded processor
    EM_SHARC = 133  # Analog Devices SHARC family of 32-bit DSP processors
    EM_ECOG2 = 134  # Cyan Technology eCOG2 microprocessor
    EM_SCORE7 = 135  # Sunplus S+core7 RISC processor
    EM_DSP24 = 136  # New Japan Radio (NJR) 24-bit DSP Processor
    EM_VIDEOCORE3 = 137  # Broadcom VideoCore III processor
    EM_LATTICEMICO32 = 138  # RISC processor for Lattice FPGA architecture
    EM_SE_C17 = 139  # Seiko Epson C17 family
    EM_TI_C6000 = 140  # The Texas Instruments TMS320C6000 DSP family
    EM_TI_C2000 = 141  # The Texas Instruments TMS320C2000 DSP family
    EM_TI_C5500 = 142  # The Texas Instruments TMS320C55x DSP family
    EM_MMDSP_PLUS = 160  # STMicroelectronics 64bit VLIW Data Signal Processor
    EM_CYPRESS_M8C = 161  # Cypress M8C microprocessor
    EM_R32C = 162  # Renesas R32C series microprocessors
    EM_TRIMEDIA = 163  # NXP Semiconductors TriMedia architecture family
    EM_HEXAGON = 164  # Qualcomm Hexagon processor
    EM_8051 = 165  # Intel 8051 and variants
    EM_STXP7X = 166  # STMicroelectronics STxP7x RISC processors
    EM_NDS32 = 167  # Andes Technology compact code size embedded RISC
    EM_ECOG1 = 168  # Cyan Technology eCOG1X family
    EM_ECOG1X = 168  # Cyan Technology eCOG1X family
    EM_MAXQ30 = 169  # Dallas Semiconductor MAXQ30 Core Micro-controllers
    EM_XIMO16 = 170  # New Japan Radio (NJR) 16-bit DSP Processor
    EM_MANIK = 171  # M2000 Reconfigurable RISC Microprocessor
    EM_CRAYNV2 = 172  # Cray Inc. NV2 vector architecture
    EM_RX = 173  # Renesas RX family
    EM_METAG = 174  # Imagination Technologies META processor architecture
    EM_MCST_ELBRUS = 175  # MCST Elbrus general purpose hardware architecture
    EM_ECOG16 = 176  # Cyan Technology eCOG16 family
    EM_CR16 = 177  # National Semiconductor CompactRISC CR16 16-bit microprocessor
    EM_ETPU = 178  # Freescale Extended Time Processing Unit
    EM_SLE9X = 179  # Infineon Technologies SLE9X core
    EM_L10M = 180  # Intel L10M
    EM_K10M = 181  # Intel K10M
    EM_AARCH64 = 183  # ARM AArch64
    EM_AVR32 = 185  # Atmel Corporation 32-bit microprocessor family
    EM_STM8 = 186  # STMicroeletronics STM8 8-bit microcontroller
    EM_TILE64 = 187  # Tilera TILE64 multicore architecture family
    EM_TILEPRO = 188  # Tilera TILEPro multicore architecture family
    EM_CUDA = 190  # NVIDIA CUDA architecture
    EM_TILEGX = 191  # Tilera TILE-Gx multicore architecture family
    EM_CLOUDSHIELD = 192  # CloudShield architecture family
    EM_COREA_1ST = 193  # KIPO-KAIST Core-A 1st generation processor family
    EM_COREA_2ND = 194  # KIPO-KAIST Core-A 2nd generation processor family
    EM_ARC_COMPACT2 = 195  # Synopsys ARCompact V2
    EM_OPEN8 = 196  # Open8 8-bit RISC soft processor core
    EM_RL78 = 197  # Renesas RL78 family
    EM_VIDEOCORE5 = 198  # Broadcom VideoCore V processor
    EM_78KOR = 199  # Renesas 78KOR family
    EM_56800EX = 200  # Freescale 56800EX Digital Signal Controller (DSC)
    EM_BA1 = 201  # Beyond BA1 CPU architecture
    EM_BA2 = 202  # Beyond BA2 CPU architecture
    EM_XCORE = 203  # XMOS xCORE processor family
    EM_MCHP_PIC = 204  # Microchip 8-bit PIC(r) family
    EM_INTEL205 = 205  # Reserved by Intel
    EM_INTEL206 = 206  # Reserved by Intel
    EM_INTEL207 = 207  # Reserved by Intel
    EM_INTEL208 = 208  # Reserved by Intel
    EM_INTEL209 = 209  # Reserved by Intel
    EM_KM32 = 210  # KM211 KM32 32-bit processor
    EM_KMX32 = 211  # KM211 KMX32 32-bit processor
    EM_KMX16 = 212  # KM211 KMX16 16-bit processor
    EM_KMX8 = 213  # KM211 KMX8 8-bit processor
    EM_KVARC = 214  # KM211 KVARC processor
    EM_CDP = 215  # Paneve CDP architecture family
    EM_COGE = 216  # Cognitive Smart Memory Processor
    EM_COOL = 217  # iCelero CoolEngine
    EM_NORC = 218  # Nanoradio Optimized RISC
    EM_CSR_KALIMBA = 219  # CSR Kalimba architecture family
    EM_AMDGPU = 224  # AMD GPU architecture
    EM_RISCV = 0x00f3   # RISCV

    def __str__(self):
        return self.name


# EI_CLASS - Object file classes.
class EC(IntEnum):
    ELFCLASSNONE = 0
    ELFCLASS32 = 1  # 32-bit object file
    ELFCLASS64 = 2  # 64-bit object file

    def __str__(self):
        return self.name


# EI_DATA - Object file byte orderings.
class ED(IntEnum):
    ELFDATANONE = 0  # Invalid data encoding.
    ELFDATA2LSB = 1  # Little-endian object file
    ELFDATA2MSB = 2  # Big-endian object file

    def __str__(self):
        return self.name


# OS ABI identification.
class ELFOSABI(IntEnum):
    NONE = 0           # UNIX System V ABI
    HPUX = 1           # HP-UX operating system
    NETBSD = 2         # NetBSD
    GNU = 3            # GNU/Linux
    LINUX = 3          # Historical alias for ELFOSABI_GNU.
    HURD = 4           # GNU/Hurd
    SOLARIS = 6        # Solaris
    AIX = 7            # AIX
    IRIX = 8           # IRIX
    FREEBSD = 9        # FreeBSD
    TRU64 = 10         # TRU64 UNIX
    MODESTO = 11       # Novell Modesto
    OPENBSD = 12       # OpenBSD
    OPENVMS = 13       # OpenVMS
    NSK = 14           # Hewlett-Packard Non-Stop Kernel
    AROS = 15          # AROS
    FENIXOS = 16       # FenixOS
    CLOUDABI = 17      # Nuxi CloudABI
    C6000_ELFABI = 64  # Bare-metal TMS320C6000
    AMDGPU_HSA = 64    # AMD HSA runtime
    C6000_LINUX = 65   # Linux TMS320C6000
    ARM = 97           # ARM
    STANDALONE = 255   # Standalone (embedded) application

    def __str__(self):
        return 'ELFOSABI_' + self.name

    # We might parse ELF with OS ABIs we don't have above. We need to support
    # displaying these unknown OS ABI values.
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


# Section header types
class SHT(IntEnum):
    NULL = 0            # No associated section (inactive entry).
    PROGBITS = 1        # Program-defined contents.
    SYMTAB = 2          # Symbol table.
    STRTAB = 3          # String table.
    RELA = 4            # Relocation entries; explicit addends.
    HASH = 5            # Symbol hash table.
    DYNAMIC = 6         # Information for dynamic linking.
    NOTE = 7            # Information about the file.
    NOBITS = 8          # Data occupies no space in the file.
    REL = 9             # Relocation entries; no explicit addends.
    SHLIB = 10          # Reserved.
    DYNSYM = 11         # Symbol table.
    INIT_ARRAY = 14     # Pointers to initialization functions.
    FINI_ARRAY = 15     # Pointers to termination functions.
    PREINIT_ARRAY = 16  # Pointers to pre-init functions.
    GROUP = 17          # Section group.
    SYMTAB_SHNDX = 18   # Indices for SHN_XINDEX entries.
    SHT_RELR = 19
    LOOS = 0x60000000
    HIOS = 0x6fffffff
    # LOPROC = 0x70000000
    # HIPROC = 0x7fffffff
    LOUSER = 0x80000000
    HIUSER = 0xffffffff
    ANDROID_REL = 0x60000001
    ANDROID_RELA = 0x60000002
    GNU_ATTRIBUTES = 0x6ffffff5
    GNU_HASH = 0x6ffffff6
    GNU_verdef = 0x6ffffffd
    GNU_verneed = 0x6ffffffe
    GNU_versym = 0x6fffffff
    # ARM_EXIDX = 0x70000001
    # ARM_PREEMPTMAP = 0x70000002
    # ARM_ATTRIBUTES = 0x70000003
    # ARM_DEBUGOVERLAY = 0x70000004
    # ARM_OVERLAYSECTION = 0x70000005
    # HEX_ORDERED = 0x70000000
    # MIPS_REGINFO = 0x70000006
    # MIPS_OPTIONS = 0x7000000d
    # MIPS_DWARF = 0x7000001e
    # MIPS_ABIFLAGS = 0x7000002a
    LLVM_ODRTAB = 0x6fff4c00
    LLVM_LINKER_OPTIONS = 0x6fff4c01
    LLVM_ADDRSIG = 0x6fff4c03
    LLVM_DEPENDENT_LIBRARIES = 0x6fff4c04
    LLVM_SYMPART = 0x6fff4c05
    LLVM_PART_EHDR = 0x6fff4c06
    LLVM_PART_PHDR = 0x6fff4c07
    LLVM_BB_ADDR_MAP_V0 = 0x6fff4c08
    LLVM_CALL_GRAPH_PROFILE = 0x6fff4c09
    LLVM_BB_ADDR_MAP = 0x6fff4c0a
    LLVM_OFFLOADING = 0x6fff4c0b
    LLVM_LTO = 0x6fff4c0c
    ANDROID_RELR = 0x6fffff00

    # AARCH64_AUTH_RELR = 0x70000004
    # AARCH64_MEMTAG_GLOBALS_STATIC = 0x70000007
    # AARCH64_MEMTAG_GLOBALS_DYNAMIC = 0x70000008
    # X86_64_UNWIND = 0x70000001
    # MSP430_ATTRIBUTES = 0x70000003
    # RISCV_ATTRIBUTES = 0x70000003
    # CSKY_ATTRIBUTES = 0x70000001
    # HEXAGON_ATTRIBUTES = 0x70000003

    def __str__(self):
        return 'SHT_' + self.name

    # We might parse ELF with SHT_XXXX defines we don't have above. We need to
    # support displaying these unknown values;
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
            new_member._name_ = '%4.4x' % value
            new_member._value_ = value
            pseudo_member = cls._value2member_map_.setdefault(value, new_member)
        return pseudo_member


# Special Section Indexes
SHN_UNDEF = 0
SHN_LORESERVE = 0xff00
SHN_LOPROC = 0xff00
SHN_HIPROC = 0xff1f
SHN_ABS = 0xfff1
SHN_COMMON = 0xfff2
SHN_HIRESERVE = 0xffff
SHN_XINDEX = 0xffff

# The size (in bytes) of symbol table entries.
SYMENTRY_SIZE32 = 16  # 32-bit symbol entry size
SYMENTRY_SIZE64 = 24  # 64-bit symbol entry size.


# Symbol bindings.
class STB(IntEnum):
    LOCAL = 0    # Local symbol, not visible outside obj file containing def
    GLOBAL = 1   # Global symbol, visible to all object files being combined
    WEAK = 2     # Weak symbol, like global but lower-precedence
    GNU_UNIQUE = 10
    LOOS = 10    # Lowest operating system-specific binding type
    HIOS = 12    # Highest operating system-specific binding type
    LOPROC = 13  # Lowest processor-specific binding type
    HIPROC = 15  # Highest processor-specific binding type

    @classmethod
    def max_width(cls):
        return 14

    def __str__(self):
        return 'STB_' + self.name

# Symbol types.
class STT(IntEnum):
    NOTYPE = 0      # Symbol's type is not specified
    OBJECT = 1      # Symbol is a data object (variable, array, etc.)
    FUNC = 2        # Symbol is executable code (function, etc.)
    SECTION = 3     # Symbol refers to a section
    FILE = 4        # Local, absolute symbol that refers to a file
    COMMON = 5      # An uninitialized common block
    TLS = 6         # Thread local data object
    GNU_IFUNC = 10  # GNU indirect function
    LOOS = 10       # Lowest operating system-specific symbol type
    HIOS = 12       # Highest operating system-specific symbol type
    LOPROC = 13     # Lowest processor-specific symbol type
    HIPROC = 15     # Highest processor-specific symbol type

    @classmethod
    def max_width(cls):
        return 13

    def __str__(self):
        return 'STT_' + self.name


class STV(IntEnum):
    DEFAULT = 0     # Visibility is specified by binding type
    INTERNAL = 1    # Defined by processor supplements
    HIDDEN = 2      # Not visible to other components
    PROTECTED = 3   # Visible in other components but not preemptable

    def __str__(self):
        return 'STV_' + self.name


# Symbol number.
STN_UNDEF = 0


class PT(IntEnum):
    NULL = 0             # Unused segment.
    LOAD = 1             # Loadable segment.
    DYNAMIC = 2          # Dynamic linking information.
    INTERP = 3           # Interpreter pathname.
    NOTE = 4             # Auxiliary information.
    SHLIB = 5            # Reserved.
    PHDR = 6             # The program header table itself.
    TLS = 7              # The thread-local storage template.
    LOOS = 0x60000000    # Lowest operating system-specific pt entry type.
    HIOS = 0x6fffffff    # Highest operating system-specific pt entry type.
    LOPROC = 0x70000000  # Lowest processor-specific program hdr entry type.
    HIPROC = 0x7fffffff  # Highest processor-specific program hdr entry type.
    GNU_EH_FRAME = 0x6474e550
    GNU_PROPERTY = 0x6474e553
    GNU_STACK = 0x6474e551
    GNU_RELRO = 0x6474e552
    ARM_UNWIND = 0x70000001

    @classmethod
    def from_object(cls, value):
        # construct the PT enum value from the given object. The object can be
        # an int or a string. If it's a string, it can optionally start with
        # 'PT_'.
        if isinstance(value, int):
            return cls(value)
        elif isinstance(value, str):
            if value.startswith('PT_'):
                value = value[3:]
            return cls[value]
        elif isinstance(value, cls):
            return value
        raise ValueError('Invalid value type: %s. Must be int, str, or %s instance.' % (type(value), cls.__name__))

    @classmethod
    def max_width(cls):
        return 15

    def __str__(self):
        return 'PT_' + self.name

    @classmethod
    def _missing_(cls, value):
        if isinstance(value, int):
            return cls.create_pseudo_member_(value)
        return None  # will raise the ValueError in Enum.__new__

    @classmethod
    def create_pseudo_member_(cls, value):
        pseudo_member = cls._value2member_map_.get(value, None)
        if pseudo_member is None:
            new_member = int.__new__(cls, value)
            new_member._name_ = '_unknown_%4.4x' % value
            new_member._value_ = value
            pseudo_member = cls._value2member_map_.setdefault(value, new_member)
        return pseudo_member


class PF(IntEnum):
    X = 1  # Execute
    W = 2  # Write
    R = 4  # Read

    def __str__(self):
        return 'PF_' + self.name


# Note types for "LINUX" or "CORE" notes
class NT_LINUX(IntEnum):
    PRSTATUS = 1
    PRFPREG = 2
    PRPSINFO = 3
    TASKSTRUCT = 4
    AUXV = 6
    SIGINFO = 0x53494749
    FILE = 0x46494c45
    PRXFPREG = 0x46e62b7f
    PPC_VMX = 0x100
    PPC_SPE = 0x101
    PPC_VSX = 0x102
    PPC_TAR = 0x103
    PPC_PPR	= 0x104
    PPC_DSCR = 0x105
    PPC_EBB = 0x106
    PPC_PMU = 0x107
    PPC_TM_CGPR = 0x108
    PPC_TM_CFPR = 0x109
    PPC_TM_CVMX = 0x10a
    PPC_TM_CVSX = 0x10b
    PPC_TM_SPR = 0x10c
    PPC_TM_CTAR = 0x10d
    PPC_TM_CPPR = 0x10e
    PPC_TM_CDSCR = 0x10f
    PPC_PKEY = 0x110
    PPC_DEXCR = 0x111
    PPC_HASHKEYR = 0x112

    _386_TLS = 0x200
    _386_IOPERM = 0x201
    X86_XSTATE = 0x202
    CET_STATE = 0x203  # Old binutils treats 0x203 as a CET state
    X86_SHSTK = 0x204
    X86_XSAVE_LAYOUT = 0x205

    S390_HIGH_GPRS = 0x300
    S390_TIMER = 0x301
    S390_TODCMP = 0x302
    S390_TODPREG = 0x303
    S390_CTRS = 0x304
    S390_PREFIX = 0x305
    S390_LAST_BREAK = 0x306
    S390_SYSTEM_CALL = 0x307
    S390_TDB = 0x308
    S390_VXRS_LOW = 0x309
    S390_VXRS_HIGH = 0x30a
    S390_GS_CB = 0x30b
    S390_GS_BC = 0x30c
    S390_RI_CB = 0x30d
    S390_PV_CPU_DATA = 0x30e

    ARM_VFP = 0x400
    ARM_TLS = 0x401
    ARM_HW_BREAK = 0x402
    ARM_HW_WATCH = 0x403
    ARM_SYSTEM_CALL = 0x404
    ARM_SVE	= 0x405
    ARM_PAC_MASK = 0x406
    ARM_PACA_KEYS = 0x407
    ARM_PACG_KEYS = 0x408
    ARM_TAGGED_ADDR_CTRL = 0x409
    ARM_PAC_ENABLED_KEYS = 0x40a
    ARM_SSVE = 0x40b
    ARM_ZA = 0x40c
    ARM_ZT = 0x40d
    ARM_FPMR = 0x40e
    ARM_POE = 0x40f
    ARM_GCS = 0x410

    METAG_CBUF = 0x500
    METAG_RPIPE = 0x501
    METAG_TLS = 0x502

    ARC_V2 = 0x600

    VMCOREDD = 0x700

    MIPS_DSP = 0x800
    MIPS_FP_MODE = 0x801
    MIPS_MSA = 0x802

    RISCV_CSR = 0x900
    RISCV_VECTOR = 0x901
    RISCV_TAGGED_ADDR_CTRL = 0x902
    RISCV_USER_CFI = 0x903

    LOONGARCH_CPUCFG = 0xa00
    LOONGARCH_CSR = 0xa01
    LOONGARCH_LSX = 0xa02
    LOONGARCH_LASX = 0xa03
    LOONGARCH_LBT = 0xa04
    LOONGARCH_HW_BREAK = 0xa05
    LOONGARCH_HW_WATCH = 0xa06

    @classmethod
    def from_object(cls, value):
        # construct the NT enum value from the given object. The object can be
        # an int or a string. If it's a string, it can optionally start with
        # 'NT_'.
        if isinstance(value, int):
            return cls(value)
        elif isinstance(value, str):
            if value.startswith('NT_'):
                value = value[3:]
            return cls[value]
        elif isinstance(value, cls):
            return value
        raise ValueError('Invalid value type: %s. Must be int, str, or %s instance.' % (type(value), cls.__name__))

    def __str__(self):
        if self.name.startswith('_'):
            return 'NT' + self.name
        else:
            return 'NT_' + self.name

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
            new_member._name_ = '%#8.8x' % value
            new_member._value_ = value
            pseudo_member = cls._value2member_map_.setdefault(value, new_member)
        return pseudo_member

# Note types for "GNU" notes
class NT_GNU(IntEnum):
    ABI_TAG = 1
    HWCAP = 2
    BUILD_ID = 3
    GOLD_VERSION = 4
    PROPERTY_TYPE_0 = 5

    @classmethod
    def from_object(cls, value):
        # construct the NT enum value from the given object. The object can be
        # an int or a string. If it's a string, it can optionally start with
        # 'NT_GNU_'.
        if isinstance(value, int):
            return cls(value)
        elif isinstance(value, str):
            if value.startswith('NT_GNU_'):
                value = value[3:]
            return cls[value]
        elif isinstance(value, cls):
            return value
        raise ValueError('Invalid value type: %s. Must be int, str, or %s instance.' % (type(value), cls.__name__))

    def __str__(self):
        return 'NT_GNU_' + self.name

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
            new_member._name_ = '%#8.8x' % value
            new_member._value_ = value
            pseudo_member = cls._value2member_map_.setdefault(value, new_member)
        return pseudo_member


# NT_AUXV defines
class AT(IntEnum):
    NULL = 0               # End of auxv.
    IGNORE = 1             # Ignore entry.
    EXECFD = 2             # File descriptor of program.
    PHDR = 3               # Program headers.
    PHENT = 4              # Size of program header.
    PHNUM = 5              # Number of program headers.
    PAGESZ = 6             # Page size.
    BASE = 7               # Interpreter base address.
    FLAGS = 8              # Flags.
    ENTRY = 9              # Program entry point.
    NOTELF = 10            # Set if program is not an ELF.
    UID = 11               # UID.
    EUID = 12              # Effective UID.
    GID = 13               # GID.
    EGID = 14              # Effective GID.
    CLKTCK = 17            # Clock frequency (e.g. times(2)).
    PLATFORM = 15          # String identifying platform.
    HWCAP = 16             # Machine dependent hints about processor capabilities.
    FPUCW = 18             # Used FPU control word.
    DCACHEBSIZE = 19       # Data cache block size.
    ICACHEBSIZE = 20       # Instruction cache block size.
    UCACHEBSIZE = 21       # Unified cache block size.
    IGNOREPPC = 22         # Entry should be ignored.
    SECURE = 23            # Boolean, was exec setuid-like?
    BASE_PLATFORM = 24     # String identifying real platforms.
    RANDOM = 25            # Address of 16 random bytes.
    HWCAP2 = 26            # Extension of AT_HWCAP.
    RSEQ_FEATURE_SIZE = 27 # rseq supported feature size.
    RSEQ_ALIGN = 28        # rseq allocation alignment.
    HWCAP3 = 29            # extension of AT_HWCAP.
    HWCAP4 = 30            # extension of AT_HWCAP.
    EXECFN = 31            # Filename of executable.
    SYSINFO = 32           # Pointer to the global system page used for sys calls
    SYSINFO_EHDR = 33
    L1I_CACHESHAPE = 34    # Shapes of the caches.
    L1D_CACHESHAPE = 35
    L2_CACHESHAPE = 36
    L3_CACHESHAPE = 37
    MINSIGSTKSZ = 51
    __MAX_WIDTH = 0
    def __str__(self):
        return 'AT_' + self.name


    @classmethod
    def from_object(cls, value):
        # construct the AT enum value from the given object. The object can be
        # an int or a string. If it's a string, it can optionally start with
        # 'AT_'.
        if isinstance(value, int):
            return cls(value)
        elif isinstance(value, str):
            if value.startswith('AT_'):
                value = value[3:]
            return cls[value]
        elif isinstance(value, cls):
            return value
        raise ValueError('Invalid value type: %s. Must be int, str, or %s instance.' % (type(value), cls.__name__))


    @classmethod
    def max_width(cls):
        if cls.__MAX_WIDTH == 0:
            cls.__MAX_WIDTH = max(len(m.name) for m in cls) + 3
        return cls.__MAX_WIDTH

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
            new_member._name_ = '%#8.8x' % value
            new_member._value_ = value
            pseudo_member = cls._value2member_map_.setdefault(value, new_member)
        return pseudo_member


class SHF(IntFlag):
    WRITE = 0x1  # Section data should be writable during execution.
    ALLOC = 0x2  # Section occupies memory during program execution.
    EXECINSTR = 0x4  # Section contains executable machine instructions.
    MERGE = 0x10  # The data in this section may be merged.
    STRINGS = 0x20  # The data in this section is null-terminated strings.
    INFO_LINK = 0x40 # A field in this section holds a section header index.
    LINK_ORDER = 0x80 # Adds special ordering requirements for link editors.
    OS_NONCONFORMING = 0x100 # This section requires special OS-specific
                             # processing to avoid incorrect behavior.
    GROUP = 0x200 # This section is a member of a section group.
    TLS = 0x400 # This section holds Thread-Local Storage.
    COMPRESSED = 0x800 # Identifies a section containing compressed data.
    GNU_RETAIN = 0x200000

    def __repr__(self):
        if self.value == 0:
            return ''
        return '|'.join(
                'SHF_' + m.name
                for m in self.__class__
                    if m.value & self.value
                )
    __str__ = __repr__


SHF_MASKOS = 0x0ff00000
SHF_MASKPROC = 0xf0000000
SHF_MASK = 0x000fffff


# ELF Compression Types (CompressedHeader.ch_type)
ELFCOMPRESS_ZLIB = 1

def offsetToAlign(align, value):
    delta = value % align
    if delta == 0:
        return 0
    return align - delta


def sizeof_fmt(num):
    for unit in ['B', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(num) < 1024.0:
            return "%3.1f%s" % (num, unit)
        num /= 1024.0
    return "%.1f%s" % (num, 'Y')


def get_percentage(part, total):
    return (float(part) / float(total)) * 100.0


def find_diff_offset(b1: bytes, b2: bytes) -> int | None:
    """Finds the offset of the first differing byte."""
    for i, (byte1, byte2) in enumerate(zip(b1, b2)):
        if byte1 != byte2:
            return i
    # If one is a prefix of the other, the diff is at the end of the shorter one
    if len(b1) != len(b2):
        return min(len(b1), len(b2))
    return None

def object_to_bytes(obj) -> bytes:
    '''
    Convert an object to bytes. The object can be a bytes object which requires
    no conversion, a string (which is interpreted as hex), or a list of strings
    (which are concatenated and interpreted as hex).
    '''
    if isinstance(obj, bytes):
        return obj
    if isinstance(obj, str):
        try:
            return bytes.fromhex(obj)
        except ValueError:
            return obj.encode('utf-8')
    elif isinstance(obj, list):
        return b"".join([bytes.fromhex(x) for x in obj])
    raise ValueError('Unsupported object type: %s' % type(obj))

class FunctionInfo:
    '''A class that accumulates function info from a variety of sources'''
    def __init__(self):
        self.addr_to_entry = {}

    def add_arm_thumb(self, addr, size=None, name=None, source=None):
        '''If an address is encoded where bit zero means thumb, then we
           can deduce the "isa" from bit zero'''
        isa = None
        if addr & 1:
            isa = 'thumb'
        else:
            isa = 'arm'
        addr = addr & 0xfffffffe
        if name and name.startswith('$'):
            isa_char = name[1]
            if isa_char == 'a':
                isa = 'arm'
            elif isa_char == 't':
                isa = 'thumb'
            elif isa_char == 'd':
                # Ignore data
                return
            else:
                raise ValueError('unexpected $ char %s in %s' % (isa_char,
                                                                 name))
        self.add(addr, size=size, name=name, source=source, isa=isa)

    def add(self, addr, size=0, name=None, source=None, isa=None):
        if addr in self.addr_to_entry:
            e = self.addr_to_entry[addr]
            # Some sources might not have thumb bit set (ARM unwind)
            # so always add it if we find it
            if isa:
                if e.isa is None:
                    e.isa = isa
                elif e.isa != isa:
                    print('warning: isa mismatch for addr=%#x: %s (%s) != %s '
                          '(%s) for symbol %s (%s) keeping original isa %s' % (
                                addr, e.isa, e.sources[-1], isa, source,
                                str(e.names), name, e.isa))
            if size:
                e_size = e.range.size()
                if e_size == 0:
                    e.range.set_size(size)
                elif e_size != size:
                    # if it is from the same source, then trust the smaller
                    # size. We have seen EH frame broken up into two
                    # overlapping ranges in libart.so...
                    if source in e.sources:
                        if size < e_size:
                            e.range.set_size(size)
                    else:
                        print('warning: size mismatch for addr=%#x: %u (%s) !='
                              ' %u (%s) for symbol %s keeping original size %u'
                              % (addr, e_size, e.sources[-1], size, source,
                                 str(e.names), e_size))
            if name is not None:
                if name not in e.names:
                    e.names.append(name)
            if source is not None and source not in e.sources:
                e.sources.append(source)
        else:
            self.addr_to_entry[addr] = FunctionInfo.Entry(addr,
                                                          size=size,
                                                          name=name,
                                                          source=source,
                                                          isa=isa)

    def dump(self, verbose, f=sys.stdout):
        sorted_addrs = self.addr_to_entry.keys()
        sorted_addrs.sort()
        sorted_entries = []
        for addr in sorted_addrs:
            entry = self.addr_to_entry[addr]
            sorted_entries.append(entry)
        prev_entry = None
        for entry in sorted_entries:
            if prev_entry:
                if prev_entry.range.intersects(entry.range):
                    if verbose:
                        f.write('warning: overlapping entries, first range '
                                'will be truncated to match second entry\'s '
                                'address:\n')
                        prev_entry.dump(f=f)
                        entry.dump(f=f)
                    prev_entry.range.hi = entry.range.lo
            prev_entry = entry
        for entry in sorted_entries:
            entry.dump(f=f)

    class Entry:
        def __init__(self, addr, size=0, name=None, source=None, isa=None):
            self.range = AddressRange(addr, addr + size)
            self.names = []
            if name:
                self.names.append(name)
            self.sources = [source]
            self.isa = isa

        def dump(self, f=sys.stdout):
            self.range.dump(f=f)
            if self.names:
                if len(self.names) > 1:
                    f.write(' names=[')
                else:
                    f.write(' name=')
                for (i, name) in enumerate(self.names):
                    if i:
                        f.write(',')
                    f.write('"%s"' % (name))
                if len(self.names) > 1:
                    f.write(']')

            if self.sources:
                f.write(' [')
                for (i, source) in enumerate(self.sources):
                    if i:
                        f.write(', ')
                    f.write(source)
                f.write(']')

            if self.isa is not None:
                f.write(' (isa=%s)' % (self.isa))
            #f.write(' (isa=%s)' % (self.isa))
            f.write('\n')


class DT(IntEnum):
    NULL = 0  # Marks end of dynamic array.
    NEEDED = 1  # String table offset of needed library.
    PLTRELSZ = 2  # Size of relocation entries in PLT.
    PLTGOT = 3  # Address associated with linkage table.
    HASH = 4  # Address of symbolic hash table.
    STRTAB = 5  # Address of dynamic string table.
    SYMTAB = 6  # Address of dynamic symbol table.
    RELA = 7  # Address of relocation table (Rela entries).
    RELASZ = 8  # Size of Rela relocation table.
    RELAENT = 9  # Size of a Rela relocation entry.
    STRSZ = 10  # Total size of the string table.
    SYMENT = 11  # Size of a symbol table entry.
    INIT = 12  # Address of initialization function.
    FINI = 13  # Address of termination function.
    SONAME = 14  # String table offset of a shared objects name.
    RPATH = 15  # String table offset of library search path.
    SYMBOLIC = 16  # Changes symbol resolution algorithm.
    REL = 17  # Address of relocation table (Rel entries).
    RELSZ = 18  # Size of Rel relocation table.
    RELENT = 19  # Size of a Rel relocation entry.
    PLTREL = 20  # Type of relocation entry used for linking.
    DEBUG = 21  # Reserved for debugger.
    TEXTREL = 22  # Relocations exist for non-writable segments.
    JMPREL = 23  # Address of relocations associated with PLT.
    BIND_NOW = 24  # Process all relocations before execution.
    INIT_ARRAY = 25  # Pointer to array of initialization functions.
    FINI_ARRAY = 26  # Pointer to array of termination functions.
    INIT_ARRAYSZ = 27  # Size of DT_INIT_ARRAY.
    FINI_ARRAYSZ = 28  # Size of DT_FINI_ARRAY.
    RUNPATH = 29  # String table offset of lib search path.
    FLAGS = 30  # Flags.
    PREINIT_ARRAY = 32
    PREINIT_ARRAYSZ = 33
    MAXPOSTAGS = 34
    GNU_HASH = 0x6FFFFEF5
    TLSDESC_PLT = 0x6FFFFEF6  # Location of PLT entry for TLS resolver calls.
    TLSDESC_GOT = 0x6FFFFEF7  # Location of GOT entry.
    RELACOUNT = 0x6FFFFFF9  # ELF32_Rela count.
    RELCOUNT = 0x6FFFFFFA  # ELF32_Rel count.
    FLAGS_1 = 0X6FFFFFFB  # Flags_1.
    VERSYM = 0x6FFFFFF0  # The address of .gnu.version section.
    VERDEF = 0X6FFFFFFC  # The address of the version definition table.
    VERDEFNUM = 0X6FFFFFFD  # The number of entries in DT_VERDEF.
    VERNEED = 0X6FFFFFFE  # The address of the version Dependency table.
    VERNEEDNUM = 0X6FFFFFFF  # The number of entries in DT_VERNEED.

    def __str__(self):
        return "DT_" + self.name

    @classmethod
    def max_width(cls):
        return 18

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
            new_member._name_ = '%#4.4x' % value
            new_member._value_ = value
            pseudo_member = cls._value2member_map_.setdefault(value, new_member)
        return pseudo_member

# DT_FLAGS bits
class DF(IntFlag):
    ORIGIN = 0x1
    SYMBOLIC = 0x2
    TEXTREL = 0x4
    BIND = 0x8
    STATIC = 0x10

    def __repr__(self):
        if self.value == 0:
            return '0'
        return '|'.join(
                'DF_' + m.name
                for m in self.__class__
                    if m.value & self.value
                )
    __str__ = __repr__


# DT_FLAGS_1 bits
class DF_1(IntFlag):
    NOW = 0x1
    GLOBAL = 0x2
    GROUP = 0x4
    NODELETE = 0x8
    LOADFLTR = 0x10
    INITFIRST = 0x20
    NOOPEN = 0x40
    ORIGIN = 0x80
    DIRECT = 0x100
    INTERPOSE = 0x400
    NODEFLIB = 0x800
    NODUMP = 0x1000
    CONFALT = 0x2000
    ENDFILTEE = 0x4000
    DISPRELDNE = 0x8000
    DISPRELPND = 0x10000
    NODIRECT = 0x20000
    IGNMULDEF = 0x40000
    NOKSYMS = 0x80000
    NOHDR = 0x100000
    EDITED = 0x200000
    NORELOC = 0x400000
    SYMINTPOSE = 0x800000
    GLOBAUDIT = 0x1000000
    SINGLETON = 0x2000000

    def __repr__(self):
        if self.value == 0:
            return '0'
        return '|'.join(
                'DF_1_' + m.name
                for m in self.__class__
                    if m.value & self.value
                )
    __str__ = __repr__


class Header:
    '''Represents the ELF header for an ELF file'''
    def __init__(self, elf=None, e_ident=None, e_type=0, e_machine=0,
                 e_version=0, e_entry=0, e_phoff=0, e_shoff=0, e_flags=0,
                 e_ehsize=0, e_phentsize=0, e_phnum=0, e_shentsize=0,
                 e_shnum=0, e_shstrndx=0):
        self.elf = elf
        if e_ident is None:
            self.e_ident = [0x7f, 0x45, 0x4c, 0x46, EC.ELFCLASS32,
                            ED.ELFDATA2LSB, 0x01, ELFOSABI.NONE, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        else:
            self.e_ident = e_ident
        self.e_type = e_type
        self.e_machine = e_machine
        self.e_version = e_version
        self.e_entry = e_entry
        self.e_phoff = e_phoff
        self.e_shoff = e_shoff
        self.e_flags = e_flags
        self.e_ehsize = e_ehsize
        self.e_phentsize = e_phentsize
        self.e_phnum = e_phnum
        self.e_shentsize = e_shentsize
        self.e_shnum = e_shnum
        self.e_shstrndx = e_shstrndx

    @classmethod
    def is_elf_file(cls, data):
        data.seek(0)
        e_ident = data.get_n_uint8(4)
        return (len(e_ident) == 4 and
                e_ident[EI.MAG0] == 0x7f and
                e_ident[EI.MAG1] == ord('E') and
                e_ident[EI.MAG2] == ord('L') and
                e_ident[EI.MAG3] == ord('F'))

    @classmethod
    def decode(cls, elf):
        data = elf.data
        data.seek(0)
        e_ident = data.get_n_uint8(EI_NIDENT)
        if (len(e_ident) != EI_NIDENT or
                e_ident[EI.MAG0] != 0x7f or
                e_ident[EI.MAG1] != ord('E') or
                e_ident[EI.MAG2] != ord('L') or
                e_ident[EI.MAG3] != ord('F')):
            return None
        if e_ident[EI.DATA] == ED.ELFDATA2LSB:
            data.set_byte_order('little')
        elif e_ident[EI.DATA] == ED.ELFDATA2MSB:
            data.set_byte_order('big')
        else:
            return None
        if e_ident[EI.CLASS] == EC.ELFCLASS32:
            data.set_addr_size(4)
        elif e_ident[EI.CLASS] == EC.ELFCLASS64:
            data.set_addr_size(8)
        else:
            return None
        e_type = data.get_uint16()
        e_machine = data.get_uint16()
        e_version = data.get_uint32()
        e_entry = data.get_address()
        e_phoff = data.get_address()
        e_shoff = data.get_address()
        e_flags = data.get_uint32()
        e_ehsize = data.get_uint16()
        e_phentsize = data.get_uint16()
        e_phnum = data.get_uint16()
        e_shentsize = data.get_uint16()
        e_shnum = data.get_uint16()
        e_shstrndx = data.get_uint16()

        if (e_phnum == 0xFFFF or
            e_shnum == SHN_UNDEF or
            e_shstrndx == SHN_XINDEX):
            # We need to read the section header at index zero to get info for
            # fields that don't have enough room
            elf.data.push_offset_and_seek(e_shoff)
            section_zero = SectionHeader(elf, 0)
            elf.data.pop_offset_and_seek()
            if e_phnum == 0xFFFF:
                e_phnum = section_zero.sh_info
            if e_shnum == SHN_UNDEF:
                e_shnum = section_zero.sh_size
            if e_shstrndx == SHN_XINDEX:
                e_shstrndx = section_zero.sh_link

        return cls(elf=elf,
                   e_ident=e_ident,
                   e_type=e_type,
                   e_machine=e_machine,
                   e_version=e_version,
                   e_entry=e_entry,
                   e_phoff=e_phoff,
                   e_shoff=e_shoff,
                   e_flags=e_flags,
                   e_ehsize=e_ehsize,
                   e_phentsize=e_phentsize,
                   e_phnum=e_phnum,
                   e_shentsize=e_shentsize,
                   e_shnum=e_shnum,
                   e_shstrndx=e_shstrndx)

    def encode(self, strm):
        for i in range(EI_NIDENT):
            strm.put_uint8(self.e_ident[i])
        strm.put_uint16(self.e_type)
        strm.put_uint16(self.e_machine)
        strm.put_uint32(self.e_version)
        strm.put_address(self.e_entry)
        strm.put_address(self.e_phoff)
        strm.put_address(self.e_shoff)
        strm.put_uint32(self.e_flags)
        strm.put_uint16(self.e_ehsize)
        strm.put_uint16(self.e_phentsize)
        strm.put_uint16(self.e_phnum)
        strm.put_uint16(self.e_shentsize)
        strm.put_uint16(self.e_shnum)
        strm.put_uint16(self.e_shstrndx)

    def encode_yaml(self, f):
        if self.e_ident is None:
            raise ValueError('e_ident is required to encode ELF header to YAML')
        f.write('--- !ELF\n')
        f.write('FileHeader:\n')
        f.write('  Class:           %s\n' % (EC(self.e_ident[EI.CLASS])))
        if self.e_ident[EI.OSABI] != ELFOSABI.NONE:
            f.write('  OSABI: %s\n' % (ELFOSABI(self.e_ident[EI.OSABI])))
        if self.e_ident[EI.ABIVERSION] != 0:
            f.write('  ABIVersion: %u\n' % (self.e_ident[EI.ABIVERSION]))
        f.write('  Data:            %s\n' % (ED(self.e_ident[EI.DATA])))
        f.write('  Type:            %s\n' % (ET(self.e_type)))
        f.write('  Machine:         %s\n' % (EM(self.e_machine)))
        if self.e_entry != 0:
            f.write('  Entry:           0x%16.16x\n' % (self.e_entry))

    def get_arch(self):
        if self.e_machine == EM.EM_X86_64:
            return 'x86_64'
        elif self.e_machine == EM.EM_ARM:
            return 'arm'
        elif self.e_machine == EM.EM_386:
            return 'x86'
        elif self.e_machine == EM.EM_AARCH64:
            return 'arm64'
        else:
            return str(EM(self.e_machine))
        # raise ValueError('unhandled e_machine to architecture name for %s' % (
        #                  EM(self.e_machine)))

    def is_arm(self):
        return self.e_machine == EM.EM_ARM

    def get_size(self):
        return 40 + 3 * self.get_addr_size()

    def dump(self, f=sys.stdout):
        f.write('ELF Header:\n')
        for i in range(EI_PAD):
            ei_str = str(EI(i))
            if i == EI.OSABI:
                f.write('e_ident[%-13s] = 0x%2.2x %s\n' % (
                        ei_str, self.e_ident[i],
                        ELFOSABI(self.e_ident[i])))
            elif i == EI.MAG1 or i == EI.MAG2 or i == EI.MAG3:
                f.write("e_ident[%-13s] = 0x%2.2x '%c'\n" % (
                        ei_str, self.e_ident[i],
                        self.e_ident[i]))
            elif i == EI.CLASS:
                f.write('e_ident[%-13s] = 0x%2.2x %s\n' % (
                        ei_str, self.e_ident[i],
                        EC(self.e_ident[i])))
            elif i == EI.DATA:
                f.write('e_ident[%-13s] = 0x%2.2x %s\n' % (
                        ei_str, self.e_ident[i],
                        ED(self.e_ident[i])))
            else:
                f.write('e_ident[%-13s] = 0x%2.2x\n' % (
                        ei_str, self.e_ident[i]))
        f.write('e_type      = 0x%4.4x %s\n' % (self.e_type, ET(self.e_type)))
        f.write('e_machine   = 0x%4.4x %s\n' % (self.e_machine, EM(self.e_machine)))
        f.write('e_version   = 0x%8.8x\n' % (self.e_version))
        addr_size = self.get_addr_size()
        if addr_size == 4:
            f.write('e_entry     = 0x%8.8x\n' % (self.e_entry))
            f.write('e_phoff     = 0x%8.8x\n' % (self.e_phoff))
            f.write('e_shoff     = 0x%8.8x\n' % (self.e_shoff))
        elif addr_size == 8:
            f.write('e_entry     = 0x%16.16x\n' % (self.e_entry))
            f.write('e_phoff     = 0x%16.16x\n' % (self.e_phoff))
            f.write('e_shoff     = 0x%16.16x\n' % (self.e_shoff))
        f.write('e_flags     = 0x%8.8x\n' % (self.e_flags))
        f.write('e_ehsize    = 0x%4.4x\n' % (self.e_ehsize))
        f.write('e_phentsize = 0x%4.4x\n' % (self.e_phentsize))
        if self.e_phnum >= 0xFFFF:
            f.write('e_phnum     = 0xFFFF (0x%4.4x)\n' % (self.e_phnum))
        else:
            f.write('e_phnum     = 0x%4.4x\n' % (self.e_phnum))
        f.write('e_shentsize = 0x%4.4x\n' % (self.e_shentsize))
        if self.e_shnum >= 0xFFFF:
            f.write('e_shnum     = SHN_UNDEF (0x%4.4x)\n' % (self.e_shnum))
        else:
            f.write('e_shnum     = 0x%4.4x\n' % (self.e_shnum))
        if self.e_shstrndx >= 0xFFFF:
            f.write('e_shstrndx  = SHN_XINDEX (0x%4.4x)\n' % (self.e_shstrndx))
        else:
            f.write('e_shstrndx  = 0x%4.4x\n' % (self.e_shstrndx))

    def clear(self):
        self.e_ident = None
        self.e_type = 0
        self.e_machine = 0
        self.e_version = 0
        self.e_entry = 0
        self.e_phoff = 0
        self.e_shoff = 0
        self.e_flags = 0
        self.e_ehsize = 0
        self.e_phentsize = 0
        self.e_phnum = 0
        self.e_shentsize = 0
        self.e_shnum = 0
        self.e_shstrndx = 0

    def get_addr_size(self):
        if self.e_ident:
            if self.e_ident[EI.CLASS] == EC.ELFCLASS32:
                return 4
            elif self.e_ident[EI.CLASS] == EC.ELFCLASS64:
                return 8
        return 0

    def get_byte_order(self):
        if self.e_ident:
            if self.e_ident[EI.DATA] == ED.ELFDATA2LSB:
                return 'little'
            elif self.e_ident[EI.DATA] == ED.ELFDATA2MSB:
                return 'big'
        return 0


class CompressedHeader:
    '''
    struct Elf32_Chdr {
      uint32_t ch_type;
      uint32_t ch_size;
      uint32_t ch_addralign;
    };

    struct Elf64_Chdr {
      uint32_t ch_type;
      uint32_t ch_reserved;
      uint64_t ch_size;
      uint64_t ch_addralign;
    };
    '''
    def __init__(self, data):
        self.name = ''
        addr_size = data.get_addr_size()
        self.ch_type = data.get_uint32()
        if addr_size == 4:
            self.byte_size = 12
            self.ch_size = data.get_uint32()
            self.ch_addralign = data.get_uint32()
        else:
            self.byte_size = 24
            self.ch_reserved = data.get_uint32()
            self.ch_size = data.get_uint64()
            self.ch_addralign = data.get_uint64()

    def dump(self, f=sys.stdout):
        f.write('ch_type      = 0x%8.8x\n' % (self.ch_type))
        if self.byte_size == 12:
            f.write('ch_size      = 0x%8.8x\n' % (self.ch_size))
            f.write('ch_addralign = 0x%8.8x\n' % (self.ch_addralign))
        else:
            f.write('ch_reserved  = 0x%8.8x\n' % (self.ch_reserved))
            f.write('ch_size      = %#16.16x\n' % (self.ch_size))
            f.write('ch_addralign = %#16.16x\n' % (self.ch_addralign))


class SectionHeader:
    '''
    struct Elf32_Shdr {
      uint32_t sh_name;      // Section name (index into string table)
      uint32_t sh_type;      // Section type (SHT_*)
      uint32_t sh_flags;     // Section flags (SHF_*)
      uint32_t sh_addr;      // Address where section is to be loaded
      uint32_t sh_offset;    // File offset of section data, in bytes
      uint32_t sh_size;      // Size of section, in bytes
      uint32_t sh_link;      // Section type-specific header table index link
      uint32_t sh_info;      // Section type-specific extra information
      uint32_t sh_addralign; // Section address alignment
      uint32_t sh_entsize;   // Size of records contained within the section
    };

    // Section header for ELF64 - same fields as ELF32, different types.
    struct Elf64_Shdr {
      uint32_t sh_name;
      uint32_t sh_type;
      uint64_t sh_flags;
      uint64_t sh_addr;
      uint64_t sh_offset;
      uint64_t sh_size;
      uint32_t sh_link;
      uint32_t sh_info;
      uint64_t sh_addralign;
      uint64_t sh_entsize;
    };
    '''
    def __init__(self, elf, index):
        self.index = index
        self.elf = elf
        self.name = ''
        data = elf.data
        self.sh_name = data.get_uint32()
        self.sh_type = data.get_uint32()
        self.sh_flags = data.get_address()
        self.sh_addr = data.get_address()
        self.sh_offset = data.get_address()
        self.sh_size = data.get_address()
        self.sh_link = data.get_uint32()
        self.sh_info = data.get_uint32()
        self.sh_addralign = data.get_address()
        self.sh_entsize = data.get_address()

    @classmethod
    def encode(cls, strm, shstrtab, name='', type=SHT.NULL, flags=0, addr=0,
               offset=0, size=0, link=0, info=0, addr_align=0, entsize=0):
        strm.put_uint32(shstrtab.get(name))
        strm.put_uint32(type)
        strm.put_address(flags)
        strm.put_address(addr)
        strm.put_address(offset)
        strm.put_address(size)
        strm.put_uint32(link)
        strm.put_uint32(info)
        strm.put_address(addr_align)
        strm.put_address(entsize)

    def contains(self, addr):
        return self.sh_addr <= addr and addr < (self.sh_addr + self.sh_size)

    def dump(self, flat, f=sys.stdout):
        if flat:
            addr_size = self.elf.get_addr_size()
            if self.index == 0:
                f.write('Section Headers:\n')
                if addr_size == 4:
                    f.write(('Index   sh_name    sh_type           sh_flags   '
                             'sh_addr    sh_offset  sh_size    sh_link    '
                             'sh_info    sh_addrali sh_entsize\n'))
                    f.write(('======= ---------- ----------------- ---------- '
                             '---------- ---------- ---------- ---------- '
                             '---------- ---------- ----------\n'))
                else:
                    f.write(('Index   sh_name    sh_type           '
                             'sh_flags           sh_addr            '
                             'sh_offset          sh_size            '
                             'sh_link    sh_info    sh_addr_a          '
                             'sh_entsize\n'))
                    f.write(('======= ---------- ----------------- '
                             '------------------ ------------------ '
                             '------------------ ------------------ '
                             '---------- ---------- ------------------ '
                             '------------------\n'))

            f.write('[%5u] ' % (self.index))
            f.write('0x%8.8x %-18s' % (self.sh_name, SHT(self.sh_type)))
            if addr_size == 4:
                format = '0x%8.8x 0x%8.8x 0x%8.8x 0x%8.8x '
            else:
                format ='0x%16.16x 0x%16.16x 0x%16.16x 0x%16.16x '
            f.write(format % (self.sh_flags, self.sh_addr, self.sh_offset,
                              self.sh_size))
            # if addr_size == 4:
            #     f.write('0x%8.8x 0x%8.8x 0x%8.8x 0x%8.8x ' % (
            #             self.sh_flags, self.sh_addr, self.sh_offset,
            #             self.sh_size))
            # else:
            #     f.write('0x%16.16x 0x%16.16x 0x%16.16x 0x%16.16x ' % (
            #             self.sh_flags, self.sh_addr, self.sh_offset,
            #             self.sh_size))
            f.write('0x%8.8x 0x%8.8x ' % (self.sh_link, self.sh_info))
            if addr_size == 4:
                f.write('0x%8.8x 0x%8.8x ' % (self.sh_addralign,
                                              self.sh_entsize))
            else:
                f.write('0x%16.16x 0x%16.16x ' % (self.sh_addralign,
                                                  self.sh_entsize))
            f.write(self.name)
            if self.sh_flags:
                f.write(' (')
                f.write(str(SHF(self.sh_flags)))
                f.write(')')
        else:
            f.write('Section[%u]:\n' % (self.index))
            if self.name:
                f.write('sh_name      = 0x%8.8x "%s"\n' % (self.sh_name,
                                                           self.name))
            else:
                f.write('sh_name      = 0x%8.8x\n' % (self.sh_name))
                f.write('sh_type      = 0x%8.8x %s\n' %
                        (self.sh_type, SHT(self.sh_type)))
            addr_size = self.elf.get_addr_size()
            if addr_size == 4:
                f.write('sh_flags     = 0x%8.8x\n' % (self.sh_flags))
                f.write('sh_addr      = 0x%8.8x\n' % (self.sh_addr))
                f.write('sh_offset    = 0x%8.8x\n' % (self.sh_offset))
                f.write('sh_size      = 0x%8.8x\n' % (self.sh_size))
            elif addr_size == 8:
                f.write('sh_flags     = 0x%16.16x\n' % (self.sh_flags))
                f.write('sh_addr      = 0x%16.16x\n' % (self.sh_addr))
                f.write('sh_offset    = 0x%16.16x\n' % (self.sh_offset))
                f.write('sh_size      = 0x%16.16x\n' % (self.sh_size))
                f.write('sh_link      = 0x%8.8x\n' % (self.sh_link))
                f.write('sh_info      = 0x%8.8x\n' % (self.sh_info))
            if addr_size == 4:
                f.write('sh_addralign = 0x%8.8x\n' % (self.sh_size))
                f.write('sh_entsize   = 0x%8.8x\n' % (self.sh_entsize))
            elif addr_size == 8:
                f.write('sh_addralign = 0x%16.16x\n' % (self.sh_size))
                f.write('sh_entsize   = 0x%16.16x\n' % (self.sh_entsize))

    def get_contents(self, offset=None, size=None):
        '''Get the section contents as a python string'''
        if self.sh_size == 0 or self.sh_type == SHT.NOBITS:
            return None
        data = self.elf.data
        if not data:
            return None
        data.push_offset_and_seek(self.sh_offset)
        if self.sh_flags & SHF.COMPRESSED:
            header = CompressedHeader(data)
            if header.ch_type == ELFCOMPRESS_ZLIB:
                compressed_bytes = data.read_size(
                        self.sh_size - header.byte_size)
                bytes = zlib.decompress(compressed_bytes)
                data.pop_offset_and_seek()
                if offset is not None:
                    if size is not None:
                        return bytes[offset:offset+size]
                    else:
                        return bytes[offset:]
                return bytes
            else:
                raise ValueError('unhandled SHF_COMPRESSED ch_type %#8.8x' % (
                                 header.ch_type))
        else:
            read_size = self.sh_size
            if offset is not None:
                if offset >= read_size:
                    return None
                data.seek(offset, file_extract.SEEK_CUR)
                read_size -= offset
            if size is not None:
                if read_size > size:
                    read_size = size
            bytes = data.read_size(read_size)
            data.pop_offset_and_seek()
            return bytes
        return None

    def get_contents_as_extractor(self):
        bytes = self.get_contents()
        return self.elf.create_extractor(io.BytesIO(bytes))


class ProgramHeader:
    '''
        struct Elf32_Phdr {
          uint32_t p_type;   // Type of segment
          uint32_t p_offset; // File offset where segment is located
          uint32_t p_vaddr;  // Virtual address of beginning of segment
          uint32_t p_paddr;  // Physical address of beginning of segment
          uint32_t p_filesz; // Number of bytes in file image of segment
          uint32_t p_memsz;  // Number of bytes in mem image of segment
          uint32_t p_flags;  // Segment flags
          uint32_t p_align;  // Segment alignment constraint
        };

        // Program header for ELF64.
        struct Elf64_Phdr {
          uint32_t p_type;   // Type of segment
          uint32_t p_flags;  // Segment flags
          uint64_t p_offset; // File offset where segment is located
          uint64_t p_vaddr;  // Virtual address of beginning of segment
          uint64_t p_paddr;  // Physical addr of beginning of segment
          uint64_t p_filesz; // Num. of bytes in file image of segment
          uint64_t p_memsz;  // Num. of bytes in mem image of segment
          uint64_t p_align;  // Segment alignment constraint
        };
    '''
    def __init__(self, elf=None, index=0, p_type=0, p_offset=0, p_vaddr=0,
                 p_paddr=0, p_filesz=0, p_memsz=0, p_flags=0, p_align=0,
                 data=None):
        self.elf = elf
        self.index = index
        self.p_type = p_type
        self.p_offset = p_offset
        self.p_vaddr = p_vaddr
        self.p_paddr = p_paddr
        self.p_filesz = p_filesz
        self.p_memsz = p_memsz
        self.p_flags = p_flags
        self.p_align = p_align
        self.data = data  # used for generating ELF files
        self.contained_sections = []  # used for generating ELF files

    def get_size(self):
        if self.elf.get_addr_size() == 4:
            return 32
        else:
            return 56

    @classmethod
    def from_dict(cls, elf, d):
        # Used when importing from a JSON file.

        # The data field can stored as a hex string in the JSON file, so we need
        # to convert it back to bytes.
        if 'data' in d:
            d['data'] = object_to_bytes(d['data'])
        # Convert the p_type if needed.
        if 'p_type' in d:
            d['p_type'] = PT.from_object(d['p_type'])

        notes = []
        addr_size = elf.get_addr_size()
        offset_size = addr_size
        byte_order = elf.get_byte_order()
        note_dicts = d.get('notes')
        if note_dicts is not None:
            # Remove the 'notes' field from the dict since it's not a field in
            # the program header.
            del d['notes']
            # Convert all notes from dicts to Note objects and encode their
            # contents to bytes for the program header data.
            for note_dict in note_dicts:
                note = Note.from_dict(elf, note_dict)
                note.dump(options=None)  # REMOVE THIS LINE
                notes.append(note)
            # Append all note bytes together for the program header data.
            strm = elf.create_encoder()
            for note in notes:
                note.encode(strm)
            d['data'] = strm.getvalue()

        return cls(**d)

    @classmethod
    def decode(cls, elf, index):
        data = elf.data
        addr_size = elf.get_addr_size()
        if addr_size == 4:
            p_type = data.get_uint32()
            p_offset = data.get_uint32()
            p_vaddr = data.get_uint32()
            p_paddr = data.get_uint32()
            p_filesz = data.get_uint32()
            p_memsz = data.get_uint32()
            p_flags = data.get_uint32()
            p_align = data.get_uint32()
        elif addr_size == 8:
            p_type = data.get_uint32()
            p_flags = data.get_uint32()
            p_offset = data.get_uint64()
            p_vaddr = data.get_uint64()
            p_paddr = data.get_uint64()
            p_filesz = data.get_uint64()
            p_memsz = data.get_uint64()
            p_align = data.get_uint64()
        return cls(elf=elf, index=index, p_type=p_type, p_offset=p_offset,
                   p_vaddr=p_vaddr, p_paddr=p_paddr, p_filesz=p_filesz,
                   p_memsz=p_memsz, p_flags=p_flags, p_align=p_align)

    def encode(self, strm):
        addr_size = self.elf.get_addr_size()
        if addr_size == 4:
            strm.put_uint32(self.p_type)
            strm.put_uint32(self.p_offset)
            strm.put_uint32(self.p_vaddr)
            strm.put_uint32(self.p_paddr)
            strm.put_uint32(self.p_filesz)
            strm.put_uint32(self.p_memsz)
            strm.put_uint32(self.p_flags)
            strm.put_uint32(self.p_align)
        elif addr_size == 8:
            strm.put_uint32(self.p_type)
            strm.put_uint32(self.p_flags)
            strm.put_uint64(self.p_offset)
            strm.put_uint64(self.p_vaddr)
            strm.put_uint64(self.p_paddr)
            strm.put_uint64(self.p_filesz)
            strm.put_uint64(self.p_memsz)
            strm.put_uint64(self.p_align)

    def get_contained_sections(self):
        if self.contained_sections is None:
            self.contained_sections = []
            for section in self.elf.get_section_headers():
                if self.contains_vaddr_in_memory(section.sh_addr):
                    self.contained_sections.append(section)
        return self.contained_sections

    def encode_yaml(self, f):
        f.write('  - Type:            %s\n' % (PT(self.p_type)))
        if self.p_flags:
            f.write('    Flags:           [ ')
            flags = []
            for flag in PF:
                if self.p_flags & flag:
                    flags.append(str(PF(flag)))
            f.write(', '.join(flags))
            f.write(' ]\n')
        sections = self.get_contained_sections()
        if sections:
            f.write('    FirstSec:        %s\n' % (sections[0].name))
            f.write('    LastSec:         %s\n' % (sections[-1].name))
        if self.p_vaddr != 0:
            f.write('    VAddr:           0x%x\n' % (self.p_vaddr))
        if self.p_paddr != 0:
            f.write('    PAddr:           0x%x\n' % (self.p_paddr))
        if self.p_align != 0:
            f.write('    Align:           0x%x\n' % (self.p_align))
        if self.p_filesz != 0:
            f.write('    FileSize:        0x%x\n' % (self.p_filesz))
        if self.p_memsz != 0:
            f.write('    MemSize:         0x%x\n' % (self.p_memsz))
        if self.p_offset != 0:
            f.write('    Offset:          0x%x\n' % (self.p_offset))

    def encode_yaml_section_data(self, f):
        if not self.get_contained_sections():
            # No contained sections. Check if this program header has data and if so, encode it as a hex string.
            bytes = self.get_contents()
            if bytes:
                f.write('  - Type:            Fill\n')
                f.write('    Pattern:         %s\n' % (bytes.hex()))
                f.write('    Size:            0x%x\n' % (len(bytes)))
                f.write('    Offset:          0x%x\n' % (self.p_offset))
                return True
        return False

    def get_contents(self):
        '''Get the program header contents as a bytes'''
        elf = self.elf
        if elf.memory_addr is not None:
            load_bias = elf.memory_addr - elf.get_base_address()
            data_addr = self.p_vaddr + load_bias
            return elf.core_elf.read_memory_as_bytes(data_addr, self.p_memsz)
        if self.p_filesz > 0 and self.p_offset > 0:
            data = elf.data
            if data:
                data.push_offset_and_seek(self.p_offset)
                bytes = data.read_size(self.p_filesz)
                data.pop_offset_and_seek()
                return bytes
        return None

    def is_all_zeros(self):
        '''Get the contents of the program header and check if they are all zeroes'''
        if self.p_filesz == 0 and self.p_memsz > 0:
            return True  # This is a zero filled section with no data
        if self.p_filesz > 0 and self.p_offset > 0:
            data = self.elf.data
            if data:
                data.push_offset_and_seek(self.p_offset)
                total_size = self.p_filesz
                chunk_size = 1024
                for offset in range(0, total_size, chunk_size):
                    bytes_left = total_size - offset
                    size = chunk_size if bytes_left >= chunk_size else bytes_left
                    bytes = data.read_size(size)
                    if not all(byte == 0 for byte in bytes):
                        return False
                data.pop_offset_and_seek()
            return True
        return False

    def get_contents_as_extractor(self):
        bytes = self.get_contents()
        return self.elf.create_extractor(io.BytesIO(bytes))

    def contains_vaddr_in_file(self, vaddr):
        return self.p_vaddr <= vaddr and vaddr < (self.p_vaddr + self.p_filesz)

    def contains_vaddr_in_memory(self, vaddr):
        return self.p_vaddr <= vaddr and vaddr < (self.p_vaddr + self.p_memsz)

    @classmethod
    def dump_header(self, f=sys.stdout):
        f.write(('Index   p_type          p_flags    '
                    'p_offset           p_vaddr            '
                    'p_paddr            p_filesz           '
                    'p_memsz            p_align\n'))
        f.write(('======= --------------- ---------- '
                    '------------------ ------------------ '
                    '------------------ ------------------ '
                    '------------------ ------------------\n'))

    def dump(self, flat, f=sys.stdout, suffix=None):
        if flat:
            f.write(('[%5u] %-*s 0x%8.8x 0x%16.16x 0x%16.16x 0x%16.16x '
                     '0x%16.16x 0x%16.16x 0x%16.16x') % (
                            self.index, PT.max_width(),
                            PT(self.p_type), self.p_flags,
                            self.p_offset, self.p_vaddr, self.p_paddr,
                            self.p_filesz, self.p_memsz, self.p_align))
        else:
            f.write('Program Header[%u]:\n' % (self.index))
            f.write('p_type   = 0x%8.8x %s\n' % (self.p_type, PT(self.p_type)))
            f.write('p_flags  = 0x%8.8x\n' % (self.p_flags))
            f.write('p_offset = 0x%16.16x\n' % (self.p_offset))
            f.write('p_vaddr  = 0x%16.16x\n' % (self.p_vaddr))
            f.write('p_paddr  = 0x%16.16x\n' % (self.p_paddr))
            f.write('p_filesz = 0x%16.16x\n' % (self.p_filesz))
            f.write('p_memsz  = 0x%16.16x\n' % (self.p_memsz))
            f.write('p_align  = 0x%16.16x' % (self.p_align))
        if suffix is not None:
            f.write(suffix)

    def __str__(self):
        s = io.StringIO()
        self.dump(flat=False, f=s)
        return s.getvalue()

def st_shndx_to_str(st_shndx):
    if st_shndx == SHN_ABS:
        return 'SHN_ABS'
    if st_shndx == SHN_COMMON:
        return 'SHN_COMMON'
    return '%i' % (st_shndx)

class Symbol:
    def __init__(self, index, addr_size, data, strtab, elf, addr_mask):
        '''
        struct Elf32_Sym {
        uint32_t st_name;  // Symbol name (index into string table)
        uint32_t st_value; // Value or address associated with the symbol
        uint32_t st_size;  // Size of the symbol
        uint8_t  st_info;  // Symbol's type and binding attributes
        uint8_t  st_other; // Must be zero; reserved
        uint16_t st_shndx; // Section index symbol is defined in
        };

        // Symbol table entries for ELF64.
        struct Elf64_Sym {
        uint32_t st_name;  // Symbol name (index into string table)
        uint8_t  st_info;  // Symbol's type and binding attributes
        uint8_t  st_other; // Must be zero; reserved
        uint16_t st_shndx; // Section index symbol is defined in
        uint64_t st_value; // Value or address associated with the symbol
        uint64_t st_size;  // Size of the symbol
        };
        '''
        self.index = index
        if addr_size == 4:
            self.st_name = data.get_uint32()
            self.st_value = data.get_uint32()
            self.st_size = data.get_uint32()
            self.st_info = data.get_uint8()
            self.st_other = data.get_uint8()
            self.st_shndx = data.get_uint16()
        elif addr_size == 8:
            self.st_name = data.get_uint32()
            self.st_info = data.get_uint8()
            self.st_other = data.get_uint8()
            self.st_shndx = data.get_uint16()
            self.st_value = data.get_uint64()
            self.st_size = data.get_uint64()
        self.name = strtab.get_string(self.st_name)
        section_headers = elf.get_section_headers()
        if self.value_is_address():
            self.section = section_headers[self.st_shndx]
        else:
            self.section = None
        if self.value_is_address():
            self.addr = self.st_value
            if addr_mask:
                self.addr &= addr_mask
        else:
            self.addr = None

    @staticmethod
    def compare_ranges(s1, s2):
        if s1.st_value != s2.st_value:
            return -1 if s1.st_value < s2.st_value else 1
        if s1.st_size != s2.st_size:
            return -1 if s1.st_size > s2.st_size else 1
        if s1.name != s2.name:
            return -1 if s1.name < s2.name else 1
        return 0

    @staticmethod
    def range(s):
        return AddressRange(s.st_value, s.st_value+s.st_size)

    def get_name(self):
        '''Common object file format symbol method.'''
        return self.name

    def get_address(self):
        '''Common object file format symbol method.'''
        return self.addr

    def get_size(self):
        '''Common object file format symbol method.'''
        return self.st_size

    def get_section_index(self):
        '''Common object file format symbol method.'''
        if self.value_is_address():
            return self.st_shndx
        return None

    def is_function(self):
        '''Common object file format symbol method.'''
        return self.get_type() == STT.FUNC

    def value_is_address(self):
        return SHN_UNDEF < self.st_shndx and self.st_shndx < SHN_LORESERVE

    def get_binding(self):
        return STB(self.st_info >> 4)

    def get_type(self):
        return STT(self.st_info & 0x0f)

    def contains(self, addr):
        if not self.value_is_address():
            return False
        return self.st_value <= addr and addr < (self.st_value + self.st_size)

    @classmethod
    def dump_header(cls, f=sys.stdout):
        f.write('Symbols:\n')
        f.write(('Index   st_name    st_value           st_size            '
                 'st_info                             st_other st_shndx   '
                 'Name\n'))
        f.write(('======= ---------- ------------------ ------------------ '
                 '----------------------------------- -------- ---------- '
                 '===========================\n'))

    def dump(self, flat, f=sys.stdout, eol=True):
        if flat:
            if self.name:
                f.write(('[%5u] 0x%8.8x 0x%16.16x 0x%16.16x 0x%2.2x '
                         '(%-*s %-*s) 0x%2.2x     %10s %s') % (
                                self.index, self.st_name, self.st_value,
                                self.st_size, self.st_info,
                                STB.max_width(),
                                self.get_binding(),
                                STT.max_width(),
                                self.get_type(), self.st_other,
                                st_shndx_to_str(self.st_shndx), self.name))
            else:
                f.write(('[%5u] 0x%8.8x 0x%16.16x 0x%16.16x 0x%2.2x '
                         '(%-*s %-*s) 0x%2.2x     %10s') % (
                                self.index, self.st_name, self.st_value,
                                self.st_size, self.st_info,
                                STB.max_width(),
                                self.get_binding(),
                                STT.max_width(),
                                self.get_type(), self.st_other,
                                st_shndx_to_str(self.st_shndx)))
        else:
            f.write('Symbol[%u]:\n' % (self.index))
            if self.name:
                f.write('st_name  = 0x%8.8x "%s"\n' % (self.st_name,
                                                       self.name))
            else:
                f.write('st_name  = 0x%8.8x\n' % (self.st_name))
            f.write('st_value = 0x%16.16x\n' % (self.st_value))
            f.write('st_size  = 0x%16.16x\n' % (self.st_size))
            f.write('st_info  = 0x%2.2x (%s %s)\n' % (
                    self.st_info, self.get_binding(),
                    SymbolType(self.get_type())))
            f.write('st_other = 0x%2.2x\n' % (self.st_other))
            f.write('st_shndx = 0x%4.4x (%u)\n' % (self.st_shndx,
                                                   self.st_shndx))
        if eol:
            f.write('\n')


class Dumper:
    def __init__(self, f, addr_size, name_width=None):
        self.f = f
        self.addr_size = addr_size
        self.name_width = name_width

    def name(self, name):
        if self.name_width is not None:
            self.f.write('%*s = ' % (self.name_width, name))
        else:
            self.f.write('%s = ' % (name))

    def hex(self, value=0, name=None):
        if name:
            self.name(name)
        self.f.write('%#x' % (value))
        if name:
            self.f.write('\n')

    def hex8(self, value=0, name=None):
        if name:
            self.name(name)
        self.f.write('%#2.2x' % (value))
        if name:
            self.f.write('\n')

    def hex16(self, value=0, name=None):
        if name:
            self.name(name)
        self.f.write('%#4.4x' % (value))
        if name:
            self.f.write('\n')

    def hex32(self, value=0, name=None):
        if name:
            self.name(name)
        self.f.write('%#8.8x' % (value))
        if name:
            self.f.write('\n')

    def hex64(self, value=0, name=None):
        if name:
            self.name(name)
        self.f.write('%#16.16x' % (value))
        if name:
            self.f.write('\n')

    def address(self, value=0, name=None):
        if self.addr_size == 4:
            self.hex32(value, name)
        else:
            self.hex64(value, name)

    def c_string(self, value='', name=None):
        if name:
            self.name(name)
        self.f.write('"%s"' % (value))
        if name:
            self.f.write('\n')


class NT_FILE:
    '''Represents an entry in the NT_FILE array in a core file.'''
    def __init__(self, start, end, file_ofs, path):
        self.start = start
        self.end = end
        self.file_ofs = file_ofs
        self.path = path

    @classmethod
    def from_dict(cls, elf, d):
        # Used when importing from a JSON file.
        return cls(**d)

    def dump(self, f=sys.stdout):
        f.write('[0x%16.16x - 0x%16.16x) 0x%16.16x %s\n' %
                (self.start, self.end, self.file_ofs, self.path))

class NT_FILES:
    '''Represents the NT_FILE array in a core file.'''
    def __init__(self, count, page_size, nt_files):
        self.count = count
        self.page_size = page_size
        self.nt_files: list[NT_FILE] = nt_files

    @classmethod
    def from_dict(cls, elf, d):
        # Used when importing from a JSON file.
        count = d['count']
        page_size = d['page_size']
        entries = d['entries']
        nt_files = []
        for entry in entries:
            nt_file = NT_FILE.from_dict(elf, entry)
            nt_files.append(nt_file)
        return cls(count, page_size, nt_files)

    @classmethod
    def decode(cls, data):
        count = data.get_address()
        page_size = data.get_address()
        nt_files = []
        for i in range(count):
            start = data.get_address()
            end = data.get_address()
            file_ofs = data.get_address()
            nt_files.append(NT_FILE(start, end, file_ofs, None))
        for i in range(count):
            nt_files[i].path = data.get_c_string()
        return cls(count, page_size, nt_files)

    def encode(self, strm: FileEncode):
        strm.put_address(self.count)
        strm.put_address(self.page_size)
        for nt_file in self.nt_files:
            strm.put_address(nt_file.start)
            strm.put_address(nt_file.end)
            strm.put_address(nt_file.file_ofs)
        for nt_file in self.nt_files:
            strm.put_c_string(nt_file.path)

    def dump(self, f=sys.stdout):
        d = Dumper(f, 8)
        d.address(name='count', value=self.count)
        d.address(name='page_size', value=self.page_size)
        f.write('Index Address Range                '
                '             file_ofs           path\n')
        f.write('===== ----------------------------------------- '
                '------------------ '
                '-------------------------------------\n')

        for i, nt_file in enumerate(self.nt_files):
            f.write('[%3u] ' % (i))
            nt_file.dump(f)
        f.write('\n')

    def get_entry_containing_address(self, addr) -> None | NT_FILE:
        for nt_file in self.nt_files:
            if nt_file.start <= addr and addr < nt_file.end:
                return nt_file
        return None

    def get_end_address_of_consecutive_ranges(self, other_nt_file: NT_FILE):
        n = len(self.nt_files)
        for i, nt_file in enumerate(self.nt_files):
            if nt_file.start == other_nt_file.start:
                while i + 1 < n:
                    curr = self.nt_files[i]
                    next = self.nt_files[i+1]
                    if curr.path != next.path:
                        break
                    if curr.end != next.start:
                        break
                    i += 1
                return self.nt_files[i].end

    def get_elf_header_entry(self, elf):
        # Get the address in the memory where the ELF header is.

        # First try the program header address of the main exectuble
        auxv_note = elf.get_note(['CORE', 'LINUX'], NT_LINUX.AUXV)
        addr = auxv_note.get(AT.PHDR)
        if addr is None:
            # Fall back to the entry point address
            addr = auxv_note.get(AT.ENTRY)
        if addr is None:
            return None
        return self.get_entry_containing_address(addr)


class PRPSINFO:
    def __init__(self, pr_state=0, pr_sname=0, pr_zomb=0, pr_nice=0, pr_flag=0,
                 pr_uid=0, pr_gid=0, pr_pid=0, pr_ppid=0, pr_pgrp=0, pr_sid=0,
                 pr_fname='', pr_psargs='', addr_size=8):
        self.pr_state = pr_state
        self.pr_sname = pr_sname
        self.pr_zomb = pr_zomb
        self.pr_nice = pr_nice
        self.pr_flag = pr_flag
        self.pr_uid = pr_uid
        self.pr_gid = pr_gid
        self.pr_pid = pr_pid
        self.pr_ppid = pr_ppid
        self.pr_pgrp = pr_pgrp
        self.pr_sid = pr_sid
        self.pr_fname = pr_fname
        self.pr_psargs = pr_psargs
        self.addr_size = addr_size

    @classmethod
    def from_dict(cls, elf, d):
        # Used when importing from a JSON file.
        return cls(**d)

    @classmethod
    def decode(cls, data):
        addr_size = data.get_addr_size()

        pr_state = data.get_uint8()
        pr_sname = data.get_uint8()
        pr_zomb = data.get_uint8()
        pr_nice = data.get_uint8()
        if addr_size == 8:
            data.align_to(8)
        pr_flag = data.get_address();

        # 16 bit on 32 bit platforms, 32 bit on 64 bit platforms
        id_size = addr_size >> 1
        pr_uid = data.get_uint_size(id_size, None)
        pr_gid = data.get_uint_size(id_size, None)

        pr_pid = data.get_uint32()
        pr_ppid = data.get_uint32()
        pr_pgrp = data.get_uint32()
        pr_sid = data.get_uint32()

        pr_fname = data.get_fixed_length_c_string(16)
        pr_psargs = data.get_fixed_length_c_string(80)

        return PRPSINFO(pr_state, pr_sname, pr_zomb, pr_nice, pr_flag, pr_uid,
                        pr_gid, pr_pid, pr_ppid, pr_pgrp, pr_sid, pr_fname,
                        pr_psargs, addr_size)

    def encode(self, strm: FileEncode):
        strm.put_uint8(self.pr_state)
        strm.put_uint8(self.pr_sname)
        strm.put_uint8(self.pr_zomb)
        strm.put_uint8(self.pr_nice)
        if self.addr_size == 8:
            strm.align_to(8)
        strm.put_address(self.pr_flag)

        # 16 bit on 32 bit platforms, 32 bit on 64 bit platforms
        id_size = self.addr_size >> 1
        strm.put_uint_size(id_size, self.pr_uid)
        strm.put_uint_size(id_size, self.pr_gid)

        strm.put_uint32(self.pr_pid)
        strm.put_uint32(self.pr_ppid)
        strm.put_uint32(self.pr_pgrp)
        strm.put_uint32(self.pr_sid)

        strm.put_fixed_length_c_string(self.pr_fname, 16)
        strm.put_fixed_length_c_string(self.pr_psargs, 80)

    def dump(self, f=sys.stdout):
        d = Dumper(f, self.addr_size)
        d.hex8(name='pr_state', value=self.pr_state)
        d.hex8(name='pr_sname', value=self.pr_sname)
        d.hex8(name='pr_zomb', value=self.pr_zomb)
        d.hex8(name='pr_nice', value=self.pr_nice)
        d.address(name='pr_flag', value=self.pr_flag)
        if self.addr_size == 4:
            d.hex16(name='pr_uid', value=self.pr_uid)
            d.hex16(name='pr_gid', value=self.pr_gid)
        else:
            d.hex32(name='pr_uid', value=self.pr_uid)
            d.hex32(name='pr_gid', value=self.pr_gid)
        d.hex32(name='pr_pid', value=self.pr_pid)
        d.hex32(name='pr_ppid', value=self.pr_ppid)
        d.hex32(name='pr_pgrp', value=self.pr_pgrp)
        d.hex32(name='pr_sid', value=self.pr_sid)
        d.c_string(name='pr_fname', value=self.pr_fname)
        d.c_string(name='pr_psargs', value=self.pr_psargs)


class PRSTATUS:
    def __init__(self, si_signo=0, si_code=0, si_errno=0, pr_cursig=0,
                 pr_sigpend=0, pr_sighold=0, pr_pid=0, pr_ppid=0, pr_pgrp=0,
                 pr_sid=0, pr_utime_tv_sec=0, pr_utime_tv_usec=0,
                 pr_stime_tv_sec=0, pr_stime_tv_usec=0,
                 pr_cutime_tv_sec=0, pr_cutime_tv_usec=0,
                 pr_cstime_tv_sec=0, pr_cstime_tv_usec=0,
                 reg_data=None, addr_size=8):
        self.si_signo = si_signo
        self.si_code = si_code
        self.si_errno = si_errno
        self.pr_cursig = pr_cursig
        self.pr_sigpend = pr_sigpend
        self.pr_sighold = pr_sighold
        self.pr_pid = pr_pid
        self.pr_ppid = pr_ppid
        self.pr_pgrp = pr_pgrp
        self.pr_sid = pr_sid
        self.pr_utime_tv_sec = pr_utime_tv_sec
        self.pr_utime_tv_usec = pr_utime_tv_usec
        self.pr_stime_tv_sec = pr_stime_tv_sec
        self.pr_stime_tv_usec = pr_stime_tv_usec
        self.pr_cutime_tv_sec = pr_cutime_tv_sec
        self.pr_cutime_tv_usec = pr_cutime_tv_usec
        self.pr_cstime_tv_sec = pr_cstime_tv_sec
        self.pr_cstime_tv_usec = pr_cstime_tv_usec
        self.reg_data = reg_data
        self.addr_size = addr_size

    @classmethod
    def from_dict(cls, elf, d):
        # Used when importing from a JSON file.

        # Fix up the register data field, which can be stored as a hex string or
        # a list of hex strings in the JSON file, so we need to convert it back
        # to bytes.
        d['reg_data'] = object_to_bytes(d['reg_data'])
        return cls(**d)


    @classmethod
    def decode(cls, data):
        si_signo = data.get_uint32()
        si_code = data.get_uint32()
        si_errno = data.get_uint32()
        pr_cursig = data.get_uint16()
        data.get_uint16()  # pad
        pr_sigpend = data.get_address()
        pr_sighold = data.get_address()
        pr_pid = data.get_uint32()
        pr_ppid = data.get_uint32()
        pr_pgrp = data.get_uint32()
        pr_sid = data.get_uint32()
        pr_utime_tv_sec = data.get_address()
        pr_utime_tv_usec = data.get_address()
        pr_stime_tv_sec = data.get_address()
        pr_stime_tv_usec = data.get_address()
        pr_cutime_tv_sec = data.get_address()
        pr_cutime_tv_usec = data.get_address()
        pr_cstime_tv_sec = data.get_address()
        pr_cstime_tv_usec = data.get_address()
        pos = data.tell()
        size = data.get_size()
        reg_data = data.read_data(size - pos)
        addr_size = data.get_addr_size()
        return PRSTATUS(si_signo, si_code, si_errno, pr_cursig, pr_sigpend,
                        pr_sighold, pr_pid, pr_ppid, pr_pgrp, pr_sid,
                        pr_utime_tv_sec, pr_utime_tv_usec,
                        pr_stime_tv_sec, pr_stime_tv_usec,
                        pr_cutime_tv_sec, pr_cutime_tv_usec,
                        pr_cstime_tv_sec, pr_cstime_tv_usec,
                        reg_data, addr_size)

    def encode(self, strm):
        strm.put_uint32(self.si_signo)
        strm.put_uint32(self.si_code)
        strm.put_uint32(self.si_errno)
        strm.put_uint16(self.pr_cursig)
        strm.put_uint16(0)  # pad
        strm.put_address(self.pr_sigpend)
        strm.put_address(self.pr_sighold)
        strm.put_uint32(self.pr_pid)
        strm.put_uint32(self.pr_ppid)
        strm.put_uint32(self.pr_pgrp)
        strm.put_uint32(self.pr_sid)
        strm.put_address(self.pr_utime_tv_sec)
        strm.put_address(self.pr_utime_tv_usec)
        strm.put_address(self.pr_stime_tv_sec)
        strm.put_address(self.pr_stime_tv_usec)
        strm.put_address(self.pr_cutime_tv_sec)
        strm.put_address(self.pr_cutime_tv_usec)
        strm.put_address(self.pr_cstime_tv_sec)
        strm.put_address(self.pr_cstime_tv_usec)
        strm.file.write(self.reg_data)

    def dump(self, f=sys.stdout):
        d = Dumper(f, self.addr_size)
        d.hex32(name='si_signo', value=self.si_signo)
        d.hex32(name='si_code', value=self.si_code)
        d.hex32(name='si_errno', value=self.si_errno)
        d.hex16(name='pr_cursig', value=self.pr_cursig)
        d.address(name='pr_sigpend', value=self.pr_sigpend)
        d.address(name='pr_sighold', value=self.pr_sighold)
        d.hex32(name='pr_pid', value=self.pr_pid)
        d.hex32(name='pr_ppid', value=self.pr_ppid)
        d.hex32(name='pr_pgrp', value=self.pr_pgrp)
        d.hex32(name='pr_sid', value=self.pr_sid)
        d.address(name='pr_utime.tv_sec', value=self.pr_utime_tv_sec)
        d.address(name='pr_utime.tv_usec', value=self.pr_utime_tv_usec)
        d.address(name='pr_stime.tv_sec', value=self.pr_stime_tv_sec)
        d.address(name='pr_stime.tv_usec', value=self.pr_stime_tv_usec)
        d.address(name='pr_cutime.tv_sec', value=self.pr_cutime_tv_sec)
        d.address(name='pr_cutime.tv_usec', value=self.pr_cutime_tv_usec)
        d.address(name='pr_cstime.tv_sec', value=self.pr_cstime_tv_sec)
        d.address(name='pr_cstime.tv_usec', value=self.pr_cstime_tv_usec)
        f.write('register data:\n')
        self.reg_data.dump(num_per_line=32, f=f)


NT_GNU_ABI_TAG = 1
NT_GNU_ABI_OS_LINUX = 0
NT_GNU_ABI_OS_HURD = 1
NT_GNU_ABI_OS_SOLARIS = 2
NT_GNU_BUILD_ID_TAG = 3

class Note:
    '''Respresents an ELF note'''
    def __init__(self, name, type, data):
        self.name = name
        self.type = type
        self.data = data

    @classmethod
    def from_dict(cls, elf, d):
        note_name = d['name']
        note_type = d['type']
        note_class, note_type_enum = get_note_class_and_type(note_name, note_type)
        note_content_class = note_class.get_content_class()
        if note_class:
            note_data = None
            if 'content' in d:
                if note_content_class is None:
                    raise ValueError('note class %s does not have a content class' %
                                     (note_class.__name__))
                content = note_content_class.from_dict(elf, d['content'])
                encoder = elf.create_encoder()
                content.encode(encoder)
                encoder.file.seek(0)
                note_data = elf.create_extractor(encoder.file)
            elif 'data' in d:
                note_bytes = object_to_bytes(d['data'])
                note_data = elf.create_extractor(io.BytesIO(note_bytes))
            if note_data is None:
                raise ValueError('note dictionary must have either "content" or "data"')
            note = note_class(note_name, note_type_enum, note_data)
            return note
        raise ValueError('unhandled note type %s for note name %s' % (
                         note_type_enum, note_name))

    @classmethod
    def get_content_class(cls):
        return None

    def get_type_name(self):
        if self.name in ['CORE', 'LINUX']:
            return f' ({NT_LINUX(self.type)})'
        else:
            return ''

    @classmethod
    def decode(cls, data: FileExtract):
        namesz = data.get_uint32()
        if namesz == 0:
            return None
        descsz = data.get_uint32()
        note_type = data.get_uint32()
        name_pos = data.tell()
        # strip the NULL which is included in the namesz below
        note_name = data.read_size(namesz)[0:-1].decode('utf-8')
        data.seek((name_pos + namesz + 3) & ~3)
        note_data = data.read_data(descsz)
        return cls(note_name, note_type, note_data)

    def encode(self, strm: FileEncode):
        bytes = self.data.get_all_bytes()
        strm.put_uint32(len(self.name)+1)
        strm.put_uint32(len(bytes))
        strm.put_uint32(self.type)
        strm.put_c_string(self.name)
        strm.align_to(4)
        strm.file.write(bytes)
        strm.align_to(4)

    @classmethod
    def create_core_prstatus_regs_arm(cls, reg_values):
        strm = FileEncode(io.BytesIO(), 'little', 4)
        for (i, reg_value) in enumerate(reg_values):
            if i < 19:
                strm.put_uint32(reg_value)
            else:
                break
        while i < 19:
            strm.put_uint32(0)
            i += 1

    @classmethod
    def create_core_prstatus(cls, elf, prstatus):
        data = elf.create_encoder()
        prstatus.encode(data)
        return Note("CORE", NT_LINUX.PRSTATUS,
                    elf.create_extractor(io.BytesIO(data.file.getvalue())))

    def dump_header(self, options, f=sys.stdout):
        f.write('\nname = "%s", type = %#8.8x%s, size = 0x%8.8x\n' % (self.name, self.type, self.get_type_name(), self.data.get_size()))
        # Dump the size and binary if verbose is enabled.
        if options and options.verbose:
            self.data.dump(num_per_line=options.num_per_line if options else 32, f=f)

    def dump(self, options, f=sys.stdout, elf=None):
        self.data.seek(0)
        self.dump_header(options, f=f)
        # Bytes will have been dumped in dump_header if verbose is enabled.
        if options is None or not options.verbose:
            self.data.dump(num_per_line=options.num_per_line if options else 32, f=f)

    @classmethod
    def extract_notes(cls, data):
        notes = list()
        while 1:
            data.align_to(4)
            note = Note.decode(data)
            if note is None or note.name is None or len(note.name) == 0:
                break
            # Find the appropriate class to use for this note based on its name
            # and type, and create an instance of that class.
            note_class, note_type_enum = get_note_class_and_type(note.name, note.type)
            notes.append(note_class(note.name, note_type_enum, note.data))
        return notes

class Note_NT_PRPSINFO(Note):
    '''Represents an NT_PRPSINFO note in a core file.'''
    def __init__(self, name, type, data):
        super(Note_NT_PRPSINFO, self).__init__(name, type, data)
        self.prpsinfo = None

    @classmethod
    def get_content_class(cls):
        return PRPSINFO

    def get_content(self):
        if self.prpsinfo is None:
            self.prpsinfo = PRPSINFO.decode(self.data)
        return self.prpsinfo

    def dump(self, options, f=sys.stdout, elf=None):
        super().dump_header(options, f=f)
        self.get_content().dump(f=f)


class Note_NT_PRSTATUS(Note):
    '''Represents an NT_PRSTATUS note in a core file.'''
    def __init__(self, name, type, data, prstatus=None):
        super(Note_NT_PRSTATUS, self).__init__(name, type, data)
        self.prstatus = None

    @classmethod
    def get_content_class(cls):
        return PRSTATUS

    def get_prstatus(self):
        if self.prstatus is None:
            self.data.seek(0)
            self.prstatus = PRSTATUS.decode(self.data)
        return self.prstatus

    def dump(self, options, f=sys.stdout, elf=None):
        super().dump_header(options, f=f)
        self.get_prstatus().dump(f=f)

class Note_NT_FILE(Note):
    '''Represents an NT_FILE note in a core file.'''
    def __init__(self, name, type, data):
        super(Note_NT_FILE, self).__init__(name, type, data)
        self.nt_files = None

    @classmethod
    def get_content_class(cls):
        return NT_FILES

    def get_entries(self) -> NT_FILES:
        if self.nt_files is None:
            self.nt_files = NT_FILES.decode(self.data)
        return self.nt_files

    def dump(self, options, f=sys.stdout, elf=None):
        entries = self.get_entries()
        super().dump_header(options, f=f)
        self.get_entries().dump(f=f)

class AuxvEntry:
    def __init__(self, type, value):
        self.type = type
        self.value = value

class AuxVector:
    '''Represents the auxv array in a core file.'''
    def __init__(self, entries):
        self.entries = entries

    @classmethod
    def from_dict(cls, elf, d):
        # Used when importing from a JSON file.
        entries_dict = d['auxv']
        entries = []
        for at in entries_dict:
            entry = AuxvEntry(AT.from_object(at),
                              entries_dict[at])
            entries.append(entry)
        return cls(entries)

    @classmethod
    def decode(cls, data):
        entries = []
        while True:
            _type = data.get_address(None)
            if _type is None:
                break
            _value = data.get_address(None)
            if _value is None:
                break
            entries.append(AuxvEntry(AT(_type), _value))
            if _type == AT.NULL:
                break
        return cls(entries)

    def encode(self, strm: FileEncode):
        for entry in self.entries:
            strm.put_address(entry.type)
            strm.put_address(entry.value)

    def dump(self, f=sys.stdout, elf=None):
        for entry in self.entries:
            str = None
            if elf:
                if entry.type in [AT.EXECFN, AT.PLATFORM, AT.BASE_PLATFORM]:
                    str = elf.read_memory_as_c_string(entry.value)
            if str:
                f.write('    %-*s = %#16.16x "%s"\n' % (AT.max_width(),
                                                        entry.type,
                                                        entry.value, str))
            else:
                f.write('    %-*s = %#16.16x\n' % (AT.max_width(),
                                                   entry.type,
                                                   entry.value))
        f.write('\n')


class Note_NT_AUXV(Note):
    '''Represents an NT_AUXV note in a core file.'''
    def __init__(self, name, type, data):
        super(Note_NT_AUXV, self).__init__(name, type, data)
        self.auxv_entries = None

    @classmethod
    def get_content_class(cls):
        return AuxVector

    def get_entries(self):
        if self.auxv_entries is None:
            self.auxv_entries = AuxVector.decode(self.data)
        return self.auxv_entries

    def get(self, key) -> None | int:
        for entry in self.get_entries().entries:
            if entry.type == key:
                return entry.value
        return None

    def dump(self, options, f=sys.stdout, elf=None):
        entries = self.get_entries()
        super().dump_header(options, f=f)
        self.get_entries().dump(f=f, elf=elf)

class RT(IntEnum):
    CONSISTENT = 0  # Mapping change is complete.
    ADD = 1  # Beginning to add a new object.
    DELETE = 2  # Beginning to remove an object mapping.

    def __str__(self):
        return 'RT_' + self.name

class RMAP:
    '''
    A class the represents a "link_map" struct for the dynamic loader on linux.

    struct link_map {
      void *base_addr;
      const char *path;
      void *dyn_addr;
      struct link_map *next;
      struct link_map *prev;
    };
    '''
    def __init__(self, base_addr, elf_addr, path_ptr, path, dyn_addr, next, prev):
        self.base_addr = base_addr
        self.elf_addr = elf_addr
        self.path_ptr = path_ptr
        self.path = path
        self.dyn_addr = dyn_addr
        self.next = next
        self.prev = prev
        self.uuid = None
        self.elf_header_in_core_memory = False

    def dump(self, options, f=sys.stdout):
        if options.verbose:
            f.write('%#16.16x %#16.16x %#16.16x %#16.16x %#16.16x %#16.16x %-45s %s\n' % (self.base_addr, self.elf_addr, self.path_ptr, self.dyn_addr, self.next, self.prev, self.get_uuid_str(), self.path))
        else:
            in_mem = ' ' if self.elf_header_in_core_memory else '*'
            f.write('%#16.16x%s %-45s %s\n' % (self.elf_addr, in_mem, self.get_uuid_str(), self.path))

    def get_uuid_str(self):
        if self.uuid:
            s = self.uuid.hex().upper()
            n = len(self.uuid)
            if n == 20:
                return s[0:8] + '-' + s[8:12] + '-' + s[12:16] +  '-' + s[16:20] +  '-' + s[20:32] +  '-' + s[32:40]

        return ''

    @staticmethod
    def dump_header(options, f=sys.stdout):
        if options.verbose:
            f.write('base_addr          elf_addr           path               dyn_addr           next               prev               UUID                                          Path\n')
            f.write('------------------ ================== ------------------ ------------------ ------------------ ------------------ ============================================= =================================\n')
        else:
            f.write('Load Address        UUID                                          Path\n')
            f.write('------------------  --------------------------------------------- -------------------------------------\n')

    @classmethod
    def decode(cls, addr, core_elf):
        data: FileExtract = core_elf.read_memory_as_data(addr, 48)
        if data is None:
            return None

        base_addr = data.get_address()
        path_ptr = data.get_address()
        path = core_elf.read_memory_as_c_string(path_ptr)
        dyn_addr = data.get_address()
        next = data.get_address()
        prev = data.get_address()

        elf_addr = base_addr
        if base_addr == 0:
            # Fixup the main executable so we get the right load address
            # and path.
            exe_nt_file = core_elf.get_nt_file_entry_for_executable()
            if exe_nt_file:
                elf_addr = exe_nt_file.start
                path = exe_nt_file.path
        return cls(base_addr, elf_addr, path_ptr, path, dyn_addr, next, prev)

class RDEBUG:
    '''
    A class that represents the DT_DEBUG linked list of shared libraries in a
    linux process.

    struct r_debug {
        int r_version; /* Version number for this protocol.  */
        struct link_map *r_map; /* Head of the chain of loaded objects.  */
        void *r_brk;
        enum {
        /* This state value describes the mapping change taking place when
            the `r_brk' address is called.  */
        RT_CONSISTENT, /* Mapping change is complete.  */
        RT_ADD,        /* Beginning to add a new object.  */
        RT_DELETE,     /* Beginning to remove an object mapping.  */
        } r_state;
        void *r_ldbase;  /* Base address the linker is loaded at.  */
    };
    '''
    def __init__(self, addr, r_version, r_map, r_brk, r_state, r_ldbase, rmaps):
        self.addr = addr
        self.r_version = r_version
        self.r_map = r_map
        self.r_brk = r_brk
        self.r_state = r_state
        self.r_ldbase = r_ldbase
        self.rmaps = rmaps

    def dump(self, options, f=sys.stdout):
        f.write('Program executable and libraries in core file:\n')
        if options.verbose:
            f.write('_r_debug @ %#x:\n' % (self.addr))
            f.write('  r_version = %u\n' % (self.r_version))
            f.write('  r_map     = %#16.16x\n' % (self.r_map))
            f.write('  r_brk     = %#16.16x\n' % (self.r_brk))
            f.write('  r_state   = %s\n' % (RT(self.r_state)))
            f.write('  r_ldbase  = %#16.16x\n' % (self.r_ldbase))
            f.write('\n')
        RMAP.dump_header(options, f=f)
        for rmap in self.rmaps:
            rmap.dump(options, f=f)

    @classmethod
    def decode(cls, addr, core_elf):
        data: FileExtract = core_elf.read_memory_as_data(addr, 40)
        if data is None:
            return None
        r_version = data.get_uint32()
        data.align_to(data.get_addr_size())
        r_map = data.get_address()
        r_brk = data.get_address()
        r_state = data.get_uint32()
        data.align_to(data.get_addr_size())
        r_ldbase = data.get_address()

        maps = []
        map_ptr = r_map
        while True:
            rmap = RMAP.decode(map_ptr, core_elf)
            if rmap is None:
                break
            rmap.elf_header_in_core_memory = core_elf.get_program_headers_by_vaddr_in_file(rmap.elf_addr)
            if rmap.elf_header_in_core_memory:
                rmap_elf = core_elf.get_elf_from_core_memory(rmap.path, rmap.elf_addr)
                if rmap_elf:
                    gnu_build_id = rmap_elf.get_gnu_build_id()
                    if gnu_build_id:
                        rmap.uuid = gnu_build_id
            # rmap_elf = core_elf.get_elf_from_core_memory(rmap.path, rmap.base_addr)
            # if rmap_elf:
            #     gnu_build_id = rmap_elf.get_gnu_build_id()
            #     if gnu_build_id:
            #         rmap.uuid = gnu_build_id
            maps.append(rmap)
            map_ptr = rmap.next
        return cls(addr, r_version, r_map, r_brk, r_state, r_ldbase, maps)


def get_note_type_enum(note_name, note_type):
    '''Get the note IntEnum class to use for an ELF note with the given name and type.'''
    if note_name == 'CORE' or note_name == 'LINUX':
        return NT_LINUX.from_object(note_type)
    return note_type

nt_type_to_class = {
    NT_LINUX.PRSTATUS: Note_NT_PRSTATUS,
    NT_LINUX.PRPSINFO: Note_NT_PRPSINFO,
    NT_LINUX.FILE: Note_NT_FILE,
    NT_LINUX.AUXV: Note_NT_AUXV,
}

def get_note_class_and_type(note_name, note_type):
    '''Get the class and note type enum to use for an ELF note with the given name and type.'''
    note_type_enum = get_note_type_enum(note_name, note_type)
    if note_name == 'CORE' or note_name == 'LINUX':
        cls = nt_type_to_class.get(note_type_enum)
        if cls is not None:
            return (cls, note_type_enum)
    return (Note, note_type_enum)


class ELFDynamic:
    '''Represents and dynamic entry in the SHT_DYNAMIC section.'''
    def __init__(self, index, data):
        self.index = index
        self.d_tag = DT(data.get_address())
        self.d_val = data.get_address()

    def dump(self, elf, f=sys.stdout):
        f.write("[%3u] %-*s %#8.8x" % (self.index, DT.max_width(),
                                       self.d_tag, self.d_val))
        str = None
        desc = None
        bits = None
        if self.d_tag in [DT.NEEDED, DT.RPATH, DT.SONAME, DT.RUNPATH]:
            if elf.dynstr:
                str = elf.dynstr.get_string(self.d_val)
        elif self.d_tag == DT.FLAGS:
            desc = '%s' % (DF(self.d_val))
        elif self.d_tag == DT.FLAGS_1:
            desc = '%s' % (DF_1(self.d_val))

        if str is not None:
            f.write(' "%s"\n' % (str))
        elif desc is not None:
            f.write(' %s\n' % (desc))
        else:
            f.write('\n')


class StringTable:
    '''Represents and SHT_STRTAB string table'''
    def __init__(self, data):
        self.data = data

    def get_string(self, offset):
        if self.data:
            self.data.seek(offset)
            return self.data.get_c_string()
        return None


def elf_hash(s):
    """A python implementation of elf_hash(3)."""
    h = 0
    for c in s:
        h = (h << 4) + ord(c)
        t = (h & 0xF0000000)
        if t != 0:
            h = h ^ (t >> 24)
        h = h & ~t
    return h


def djb_hash(s):
    """A python implementation of the DJB hash."""
    h = 5381
    for c in s:
        h = h * 33 + ord(c)
    return h & 0xffffffff


class GNUHash:
    def __init__(self, elf):
        self.elf = elf
        self.section = elf.get_section_by_dynamic_tag(DT.GNU_HASH)
        if self.section is None:
            self.nbucket = 0
            self.symndx = 0
            self.maskwords = 0
            self.shift2 = 0
            self.addr_size = 0
        else:
            data = self.section.get_contents_as_extractor()
            self.nbucket = data.get_uint32()
            self.symndx = data.get_uint32()
            self.maskwords = data.get_uint32()
            self.shift2 = data.get_uint32()
            self.addr_size = data.get_addr_size()
        self.bloom = list()
        self.buckets = list()
        self.hashes = list()
        for i in range(self.maskwords):
            self.bloom.append(data.get_address())
        for i in range(self.nbucket):
            self.buckets.append(data.get_uint32())
        symtab = self.elf.get_dynsym()
        nhashes = len(symtab) - self.symndx
        for i in range(nhashes):
            self.hashes.append(data.get_uint32())

    def dump(self, f):
        f.write('nbucket   = %#8.8x (%u)\n' % (self.nbucket, self.nbucket))
        f.write('symndx    = %#8.8x (%u)\n' % (self.symndx, self.symndx))
        f.write('maskwords = %#8.8x (%u)\n' % (self.maskwords, self.maskwords))
        f.write('shift2    = %#8.8x (%u)\n' % (self.shift2, self.shift2))
        for i, bloom in enumerate(self.bloom):
            f.write('bloom[%2u] = %#8.8x\n' % (i, bloom))
        for i, bucket in enumerate(self.buckets):
            f.write('bucket[%2u] = %#8.8x\n' % (i, bucket))
        for i, hash in enumerate(self.hashes):
            f.write('hash[%2u] = %#8.8x\n' % (i, hash))

    def is_valid(self):
        return self.nbucket > 0

    def lookup(self, name):
        if not self.is_valid():
            return None
        symtab = self.elf.get_dynsym()
        h1 = djb_hash(name)
        h2 = h1 >> self.shift2
        # Test against the Bloom filter
        c = self.addr_size * 8
        n = (h1 / c) & self.maskwords
        bitmask = (1 << (h1 % c)) | (1 << (h2 % c))
        if (self.bloom[n] & bitmask) != bitmask:
            return None
        # Locate the hash chain, and corresponding hash value element
        n = self.buckets[h1 % self.nbucket]
        if n == 0:  # Empty hash chain, symbol not present
            return None
        # Walk the chain until the symbol is found or the chain is exhausted.
        sym_idx = n
        h1 &= ~1
        while True:
            symbol = symtab[sym_idx]
            hash_idx = sym_idx - self.symndx
            h2 = self.hashes[hash_idx]
            if h1 == (h2 & ~1) and symbol.name == name:
                return symbol
            # Done if at end of chain */
            if h2 & 1:
                break
            sym_idx += 1
        return None


def prel31_to_addr(prel31):
    value = prel31 & 0x7fffffff
    sign_bit = 0x40000000
    return (value & (sign_bit - 1)) - (value & sign_bit)


class ARMUnwind:
    def __init__(self, elf):
        self.elf = elf
        self.exidx = []
        (self.arm_exidx_data,
         self.arm_exidx_addr) = elf.get_section_data_and_addr('.ARM.exidx')
        (self.arm_extab_data,
         self.arm_extab_addr) = elf.get_section_data_and_addr('.ARM.extab')
        while self.arm_exidx_data is not None:
            offset = self.arm_exidx_data.tell()
            file_addr = self.arm_exidx_addr + offset
            prel31 = self.arm_exidx_data.get_uint32(None)
            if prel31 is None:
                break
            addr = prel31_to_addr(prel31)
            func_addr = file_addr + addr
            data = self.arm_exidx_data.get_uint32()
            # print('file_addr=%#x, addr=%#x, func_addr=%#x, data=%#8.8x' %
            #       (file_addr, addr, func_addr, data))
            self.exidx.append(ARMUnwind.Entry(file_addr, func_addr, data))

    def get_function_info(self, func_info):
        for entry in self.exidx:
            func_info.add(entry.func_addr, source='.ARM.exidx')

    class Entry:
        def __init__(self, file_addr, func_addr, data):
            self.file_addr = file_addr
            self.func_addr = func_addr
            self.data = data

        def __lt__(self, rhs):
            return self.func_addr < rhs.func_addr


class Hash:
    def __init__(self, elf):
        self.elf = elf
        self.section = elf.get_section_by_dynamic_tag(DT.HASH)
        if self.section is None:
            self.nbucket = 0
            self.nchain = 0
        else:
            data = self.section.get_contents_as_extractor()
            self.nbucket = data.get_uint32()
            self.nchain = data.get_uint32()
        self.buckets = list()
        self.chain = list()
        for i in range(self.nbucket):
            self.buckets.append(data.get_uint32())
        for i in range(self.nchain):
            self.chain.append(data.get_uint32())

    def is_valid(self):
        return self.nbucket > 0

    def lookup(self, name):
        if not self.is_valid():
            return None
        x = elf_hash(name)
        y = self.buckets[x % self.nbucket]
        symtab = self.elf.get_dynsym()
        if len(symtab) != self.nchain:
            symtab = self.elf.get_symtab()
            if len(symtab) != self.nchain:
                return None
        while y != 0:
            symbol = symtab[y]
            if symbol.name == name:
                return symbol
            y = self.chain[y]
        return None


class SymbolTree():
    def __init__(self, range=None, symbol=None, symbols=None, children=None, addr_to_child_idx=None):
        self.range = AddressRange(0, 0xffffffffffffffff) if range is None else range
        self.symbols = [] if symbols is None else symbols
        self.children = [] if children is None else children
        self.addr_to_child_idx = {} if addr_to_child_idx is None else addr_to_child_idx
        if symbol:
            self.symbols.append(symbol)

    def finalize(self):
        self.symbols.sort(cmp=Symbol.compare_ranges)
        for child in self.children:
            child.finalize()

    def add_child(self, range, symbol):
        self.addr_to_child_idx[range.lo] = len(self.children)
        self.children.append(SymbolTree(range=range, symbol=symbol))

    def get_child_with_start_addr(self, start_addr):
        if start_addr not in self.addr_to_child_idx:
            return None
        return self.children[self.addr_to_child_idx[start_addr]]

    def add(self, range, symbol, depth=0):
        if self.range.contains(range):
            if self.range == range:
                self.symbols.append(symbol)
                return True
            child = self.get_child_with_start_addr(range.lo)
            if child:
                if child.add(range, symbol, depth+1):
                    return True
            self.add_child(range, symbol)
            return True
        if not self.range.intersects(range):
            return False
        if range.contains(self.range):
            sym_tree = SymbolTree(range=self.range,
                                  symbols=self.symbols,
                                  children=self.children,
                                  addr_to_child_idx=self.addr_to_child_idx)
            self.range = range
            self.symbols = [symbol]
            self.children = []
            self.addr_to_child_idx = {}
            self.addr_to_child_idx[sym_tree.range.lo] = len(self.children)
            self.children.append(sym_tree)
            return True
        return False

    def dump(self, f, depth=0):
        prev_symbol = None
        prev_range = None
        for symbol in self.symbols:
            range = Symbol.range(symbol)
            if prev_symbol:
                if prev_range != range and prev_range.intersects(range):
                    f.write('error: symbols overlap:\n')
                    prev_symbol.dump(flat=True, f=f)
                    symbol.dump(flat=True, f=f)
            prev_symbol = symbol
            prev_range = range

        if depth==0:
            for child in self.children:
                child.dump(f, depth+1)
        elif depth > 1 or self.children:
            if depth == 1:
                f.write('error: symbols contain other symbols:\n')
            for symbol in self.symbols:
                if depth > 0:
                    f.write(' ' * (depth*2))
                symbol.dump(flat=True, f=f)
            for child in self.children:
                child.dump(f, depth+1)


def calculate_symbol_checks(elf, sym_tree, symbols):
    for s in symbols:
        if s.st_shndx == 0 or s.st_shndx >= SHN_LORESERVE:
            continue
        stt = s.get_type()
        if stt == STT.SECTION or stt == STT.NOTYPE:
            continue
        section = elf.get_section_by_shndx(s.st_shndx)
        if (section.sh_flags & SHF.EXECINSTR) == 0:
            continue
        # print('Processing: ')
        # s.dump(flat=True, f=sys.stdout)
        sym_tree.add(Symbol.range(s), s)
        # print('SymbolTree: ')
        # sym_tree.dump(sys.stdout)
        # print('')


class File:
    '''Represents and ELF file'''
    def __init__(self, path=None, header=None, data=None, memory_addr=None, core_elf=None):
        self.path = path
        self.file_off = 0
        self.error = None
        self.header = None
        # If this ELF file is being loaded from memory, this will be valid.
        self.memory_addr = memory_addr
        #  If the core file ELF created this ELF from memory, this is the core ELF file.
        self.core_elf = core_elf
        if header is not None:
            self.header = header
            header.elf = self
        if data is not None:
            self.data = data
            if self.header is None:
                self.header = Header.decode(self)
        elif path is not None:
            if os.path.exists(path):
                f = open(self.path, 'rb')
                self.data = FileExtract(f, '=')
                self.header = Header.decode(self)
                if self.header is None:
                    self.data = None
            else:
                self.error = 'error: file "%s" doesn\'t not exist' % (path)
        self.section_headers = None
        self.program_headers = None
        self.symtab = None
        self.dynsym = None
        self.symbols = None
        self.dynamic = None
        self.dynstr = None
        self.dwarf = -1
        self.dwp_elf = None
        self.hash = -1
        self.notes = None

    def __str__(self):
        return self.description()

    __repr__ = __str__

    def description(self, show_offset=True):
        if show_offset:
            return '%#8.8x: %s (%s)' % (self.file_off, self.path, self.get_arch())
        return '%s (%s)' % (self.path, self.get_arch())

    def get_address_mask(self):
        '''Return an integer that will act as a mask for any addresses.

        ARM binaries usually have bit zero set if the function is a thumb
        function, so this will need to be masked off of any addresses.
        '''
        if self.is_arm():
            return 0xFFFFFFFE
        return None

    def get_uuid_bytes(self):
        build_id = self.get_note("GNU", NT_LINUX.GNU_BUILD_ID_TAG)
        if build_id:
            build_id.data.seek(0)
            return build_id.data.read_size(build_id.data.get_size())
        return None

    def get_base_address(self):
        ph = self.get_program_header_by_type(PT.LOAD)
        if ph:
            return ph.p_vaddr
        return None

    def create_extractor(self, file) -> FileExtract:
        '''
        Create and return a FileExtract() object that can be used to read the
        contents of this ELF file with the same byte order and address size as
        this ELF file.
        '''
        return FileExtract(file,
                           byte_order=self.get_byte_order(),
                           addr_size=self.get_addr_size(),
                           offset_size=self.get_addr_size())

    def create_encoder(self, file=None) -> FileEncode:
        '''
        Create and return a FileEncode() object that can be used to write out a
        new ELF data with the same byte order and address size as this ELF
        file.
        '''
        if file is None:
            file = io.BytesIO()
        return FileEncode(file,
                          byte_order=self.get_byte_order(),
                          addr_size=self.get_addr_size(),
                          offset_size=self.get_addr_size())

    def get_notes(self):
        if self.notes is not None:
            return self.notes
        self.notes = []
        # Always try to grab notes from program headers first.
        for ph in self.get_program_headers_by_type(PT.NOTE):
            data = ph.get_contents_as_extractor()
            notes = Note.extract_notes(data)
            if notes:
                self.notes.extend(notes)
        if len(self.notes) == 0:
            # Fall back to grabbing notes from section headers.
            sections = self.get_sections_by_type(SHT.NOTE)
            if sections:
                for section in sections:
                    data = section.get_contents_as_extractor()
                    notes = Note.extract_notes(data)
                    if notes:
                        self.notes.extend(notes)
        return self.notes

    def get_elf_from_core_memory(self, path, base_addr):
        nt_file_note = self.get_note(['CORE', 'LINUX'], NT_LINUX.FILE)
        if nt_file_note is None:
            return None
        nt_files = nt_file_note.get_entries()
        nt_file = nt_files.get_entry_containing_address(base_addr)
        if nt_file:
            start_addr = nt_file.start
            end_addr = nt_files.get_end_address_of_consecutive_ranges(nt_file)
            path = nt_file.path
        else:
            ph = self.get_program_headers_by_vaddr_in_file(base_addr)
            if ph is None:
                return None
            start_addr = ph.p_vaddr
            end_addr = start_addr + ph.p_memsz
        elf_data = self.read_memory_as_data(start_addr, end_addr - start_addr)
        if elf_data is None:
            return None

        return File(path=path, header=None, data=elf_data, memory_addr=start_addr, core_elf=self)

    def get_nt_file_entry_for_executable(self):
        nt_file_note = self.get_note(['CORE', 'LINUX'], NT_LINUX.FILE)
        if nt_file_note is None:
            return None
        nt_files = nt_file_note.get_entries()
        return nt_files.get_elf_header_entry(self)

    def dump_core_info(self, options, f=sys.stdout):
        nt_file_note = self.get_note(['CORE', 'LINUX'], NT_LINUX.FILE)
        if nt_file_note is None:
            f.write('error: no NT_FILE note was found')
            return
        nt_files = nt_file_note.get_entries()
        exe_nt_file = nt_files.get_elf_header_entry(self)
        if exe_nt_file is None:
            f.write('error: not able to find the executable in NT_FILE\n')
            return
        f.write('\nNT_FILE entry for main executable:\n  ')
        exe_nt_file.dump(f=f)
        prpsinfo = self.get_note(['CORE', 'LINUX'], NT_LINUX.PRPSINFO)
        if prpsinfo:
            f.write('\nNT_PRPSINFO info:\n')
            f.write(f'  prpsinfo.pr_pid = {prpsinfo.get_content().pr_pid}\n')
            f.write(f'  prpsinfo.pr_fname = "{prpsinfo.get_content().pr_fname}"\n')
            f.write(f'  prpsinfo.pr_psargs = "{prpsinfo.get_content().pr_psargs}"\n')
            f.write('\n')
        elf_end_addr = nt_files.get_end_address_of_consecutive_ranges(exe_nt_file)
        elf_header_data = self.read_memory_as_data(exe_nt_file.start, elf_end_addr - exe_nt_file.start)
        if elf_header_data is None:
            f.write('error: Unable to read the executable ELF header from %#x\n' % (exe_nt_file.start))
            return
        exe_elf = File(path=exe_nt_file.path, header=None, data=elf_header_data, memory_addr=exe_nt_file.start, core_elf=self)
        if options.verbose:
            nt_files.dump(f=f)
            exe_elf.dump_file_summary(f=f)
            exe_elf.dump_program_headers(options, f=f)
        # Dump the auxilary vector as it has intersting core info.
        self.dump_auxv(options)
        r_debug_addr = exe_elf.get_first_dynamic_entry_value(DT.DEBUG)
        if r_debug_addr is None:
            f.write('error: Unable to the DT_DEBUG value from the ELF dynamic table.\n')
            return
        r_debug = RDEBUG.decode(r_debug_addr, self)
        r_debug.dump(options)




    def get_note(self, name_or_names, type):
        if isinstance(name_or_names, list):
            # name_or_names is a list of names
            for note in self.get_notes():
                if note.name in name_or_names and note.type == type:
                    note.data.seek(0)
                    return note
        else:
            # name_or_names is a single name
            for note in self.get_notes():
                if note.name == name_or_names and note.type == type:
                    note.data.seek(0)
                    return note
        return None

    def get_symbol_size(self):
        addr_size = self.get_addr_size()
        if addr_size == 4:
            return SYMENTRY_SIZE32
        elif addr_size == 8:
            return SYMENTRY_SIZE64
        raise ValueError('unsupported address size')

    def get_arch(self):
        '''Return the short architecture name for this ELF file'''
        if self.header:
            return self.header.get_arch()
        return None

    def get_byte_order(self):
        if self.header is not None:
            return self.header.get_byte_order()
        return '='

    def read_data_from_file_addr(self, addr, size):
        '''
            Given an address, find the file offset in the file for the
            file address by looking it up in the section info and read
            the data and return it as a file_extract.FileDecode() object
        '''
        if self.data is None:
            return None
        sections = self.get_section_headers()
        for section in sections:
            section_end_addr = section.sh_addr + section.sh_size
            if section.sh_addr <= addr and addr < section_end_addr:
                offset = addr - section.sh_addr
                self.data.push_offset_and_seek(section.sh_offset + offset)
                data = self.data.read_data(size)
                self.data.pop_offset_and_seek()
                return data
        return None

    def add_program_header(self, ph):
        if self.program_headers is None:
            self.program_headers = []
        if ph.data is None:
            ph.data = ph.get_contents()
        self.program_headers.append(ph)

    def add_notes_program_header(self, note):
        if self.program_headers is None:
            self.program_headers = []
        ph_encoder = self.create_encoder()
        note.encode(ph_encoder)
        ph = ProgramHeader(elf=self,
                           index=len(self.program_headers),
                           p_type=PT.NOTE,
                           data=ph_encoder.file.getvalue())
        self.program_headers.append(ph)

    def save(self, path):
        # Fixup things in the elf header first
        offset = self.header.get_size()
        self.header.e_phentsize = self.program_headers[0].get_size()
        self.header.e_phnum = len(self.program_headers)
        self.header.e_phoff = offset
        # Advance the offset so we can write out any program header data
        offset += self.header.e_phentsize * self.header.e_phnum
        for ph in self.program_headers:
            if ph.data is not None:
                if ph.p_align > 0:
                    align = ph.p_align
                else:
                    align = 0x1000
                ph.p_offset = offset + offsetToAlign(align, offset)
                ph.p_filesz = len(ph.data)
                offset += ph.p_filesz
        with open(path, 'wb') as out_file:
            data = self.create_encoder(out_file)
            self.header.encode(data)
            curr_offset = data.tell()
            if self.header.e_phoff != curr_offset:
                print('error: e_phoff is not correct is %#x, should be %#x' %
                      (curr_offset, self.header.e_phoff))
                return
            for ph in self.program_headers:
                ph.encode(data)
            for ph in self.program_headers:
                if ph.data:
                    data.file.seek(ph.p_offset, 0)
                    data.file.write(ph.data)

    def get_file_type(self):
        return 'elf'

    def is_valid(self):
        return self.header is not None

    @classmethod
    def create_simple_elf(cls, orig_elf, out_path, sect_bytes_dict):
        '''Create a simple ELF file with sections that contains the data found
        in the sect_bytes_dict. It uses "orig_elf" as the template ELF file for
        creating the new output ELF file.'''
        out_file = open(out_path, 'w')
        strm = orig_elf.create_encoder(out_file)
        sorted_section_names = sorted(sect_bytes_dict.keys())
        # We need one section for each section data + the section header
        # string table + the first SHT_NULL section
        num_section_headers = len(sorted_section_names) + 2
        # Section headers will start immediately after this header so the
        # section headers offset is the size in bytes of the ELF header.
        eh = orig_elf.header
        section_headers_offset = eh.e_ehsize
        # Write ELF header
        for e in eh.e_ident:
            strm.put_uint8(e)
        strm.put_uint16(eh.e_type)
        strm.put_uint16(eh.e_machine)
        strm.put_uint32(eh.e_version)
        strm.put_address(0)  # e_entry
        strm.put_address(0)  # e_phoff
        strm.put_address(section_headers_offset)  # e_shoff
        strm.put_uint32(eh.e_flags)
        strm.put_uint16(eh.e_ehsize)
        strm.put_uint16(eh.e_phentsize)
        strm.put_uint16(0)  # e_phnum
        strm.put_uint16(eh.e_shentsize)
        strm.put_uint16(num_section_headers)  # e_shnum
        strm.put_uint16(1)  # e_shstrndx

        # Create the section header string table contents
        shstrtab = file_extract.StringTable()
        shstrtab.insert(".shstrtab")
        for sect_name in sorted_section_names:
            shstrtab.insert(sect_name)

        # Encode the shstrtab data so we know how big it is
        shstrtab_data = orig_elf.create_encoder()
        shstrtab.encode(shstrtab_data)
        shstrtab_bytes = shstrtab_data.file.getvalue()
        # Write out section headers
        data_offset = (num_section_headers * eh.e_shentsize +
                       section_headers_offset)
        shstrtab_size = len(shstrtab_bytes)
        SectionHeader.encode(strm=strm, shstrtab=shstrtab, type=SHT.NULL)
        SectionHeader.encode(strm=strm,
                             shstrtab=shstrtab,
                             name=".shstrtab",
                             type=SHT.STRTAB,
                             offset=data_offset,
                             size=shstrtab_size,
                             addr_align=1)
        data_offset += shstrtab_size
        for sect_name in sorted_section_names:
            sect_bytes = sect_bytes_dict[sect_name]
            sect_bytes_len = len(sect_bytes)
            SectionHeader.encode(strm=strm,
                                 shstrtab=shstrtab,
                                 name=sect_name,
                                 type=SHT.PROGBITS,
                                 offset=data_offset,
                                 size=sect_bytes_len,
                                 addr_align=1)
            data_offset += sect_bytes_len
        # Write out section header string table data
        strm.file.write(shstrtab_bytes)
        for sect_name in sorted_section_names:
            sect_bytes = sect_bytes_dict[sect_name]
            strm.file.write(sect_bytes)

    def get_addr_size(self):
        if self.header is None:
            return 0
        else:
            return self.header.get_addr_size()

    def get_hash_table(self):
        if self.hash == -1:
            self.hash = Hash(self)
            if not self.hash.is_valid():
                self.hash = GNUHash(self)
                if not self.hash.is_valid():
                    self.hash = None
        return self.hash

    def get_section_data_and_addr(self, sect_name):
        sections = self.get_sections_by_name(sect_name)
        if len(sections) > 0:
            return (sections[0].get_contents_as_extractor(),
                    sections[0].sh_addr)
        return (None, None)

    def get_section_and_data(self, sect_name):
        sections = self.get_sections_by_name(sect_name)
        if len(sections) > 0:
            return (sections[0].get_contents_as_extractor(), sections[0])
        return (None, None)

    def get_debug_info_size(self):
        '''
            Get the size of all debug information sections.
        '''
        size = 0
        for section in self.get_section_headers():
            name = section.name
            if name.startswith(".debug_") or name.startswith(".apple_"):
                size += section.sh_size
        return size

    def get_unwind_data_and_addr(self, is_eh_frame):
        if is_eh_frame:
            return self.get_section_data_and_addr('.eh_frame')
        else:
            return self.get_section_data_and_addr('.debug_frame')

    def get_dwarf(self, is_dwo = False):
        if self.dwarf != -1:
            return self.dwarf
        self.dwarf = None
        suffix = ".dwo" if is_dwo else ""
        debug_abbrev_data = self.get_section_contents_by_name('.debug_abbrev' + suffix)
        if debug_abbrev_data is None and suffix == "":
            suffix = ".dwo"
            is_dwo = True
            debug_abbrev_data = self.get_section_contents_by_name('.debug_abbrev' + suffix)

        debug_info_data = self.get_section_contents_by_name('.debug_info' + suffix)
        if debug_abbrev_data or debug_info_data:
            debug_aranges_data = self.get_section_contents_by_name(
                    '.debug_aranges' + suffix)
            debug_line_data = self.get_section_contents_by_name('.debug_line' + suffix)
            debug_line_str_data = self.get_section_contents_by_name('.debug_line_str' + suffix)
            debug_names_data = self.get_section_contents_by_name('.debug_names')
            debug_ranges_data = self.get_section_contents_by_name(
                    '.debug_ranges' + suffix)
            if debug_ranges_data is None:
                debug_ranges_data = self.get_section_contents_by_name(
                    '.debug_rnglists' + suffix)
            debug_str_offsets_data = self.get_section_contents_by_name(
                    '.debug_str_offsets' + suffix)
            debug_addr_data = self.get_section_contents_by_name('.debug_addr' + suffix)
            debug_loc_data = self.get_section_contents_by_name('.debug_loc' + suffix)
            if debug_loc_data is None:
                debug_loc_data = self.get_section_contents_by_name('.debug_loclists' + suffix)
            debug_str_data = self.get_section_contents_by_name('.debug_str' + suffix)
            debug_types_data = self.get_section_contents_by_name(
                    '.debug_types' + suffix)
            debug_cu_index_data = None
            debug_tu_index_data = None
            dwp_dwarf = None
            if is_dwo:
                debug_cu_index_data = self.get_section_contents_by_name('.debug_cu_index')
                debug_tu_index_data = self.get_section_contents_by_name('.debug_tu_index')
            else:
                dwp_path = dwarf.context.DWARF.locate_dwp(self.path)
                if dwp_path:
                    self.dwp_elf = File(path=dwp_path)
                    dwp_dwarf = self.dwp_elf.get_dwarf(is_dwo=True)
            self.dwarf = dwarf.context.DWARF(objfile=self,
                                             dwp=dwp_dwarf,
                                             is_dwo=is_dwo,
                                             debug_abbrev=debug_abbrev_data,
                                             debug_addr=debug_addr_data,
                                             debug_aranges=debug_aranges_data,
                                             debug_info=debug_info_data,
                                             debug_line=debug_line_data,
                                             debug_line_str=debug_line_str_data,
                                             debug_names=debug_names_data,
                                             debug_loc=debug_loc_data,
                                             debug_ranges=debug_ranges_data,
                                             debug_str_offsets=debug_str_offsets_data,
                                             debug_str=debug_str_data,
                                             debug_types=debug_types_data,
                                             debug_cu_index=debug_cu_index_data,
                                             debug_tu_index=debug_tu_index_data)
        return self.dwarf

    def get_section_by_shndx(self, shndx):
        sections = self.get_section_headers()
        if shndx < len(sections):
            return sections[shndx]
        return None

    def get_sections_by_name(self, section_name):
        matching_sections = list()
        sections = self.get_section_headers()
        for section in sections:
            if section.name and section.name == section_name:
                matching_sections.append(section)
        return matching_sections

    def get_sections_by_type(self, sh_type):
        matching_sections = list()
        sections = self.get_section_headers()
        for section in sections:
            if section.sh_type == sh_type:
                matching_sections.append(section)
        return matching_sections

    def get_section_by_addr(self, sh_addr):
        sections = self.get_section_headers()
        for section in sections:
            if section.sh_addr == sh_addr:
                return section
        return None

    def get_executable_section_ranges(self, callback):
        '''Call the "callback" with each executable section address range.'''
        sections = self.get_section_headers()
        for sh in sections:
            if sh.sh_flags & SHF.EXECINSTR:
                callback(sh.sh_addr, sh.sh_addr + sh.sh_size)

    def get_section_by_dynamic_tag(self, d_tag):
        '''Many ELF dymnamic tags have values that are file addresses. These
        addresses are often the value of the section's sh_addr and can be
        looked up accordingly.'''
        d_val = self.get_first_dynamic_entry_value(d_tag)
        if d_val is None:
            return None
        return self.get_section_by_addr(d_val)

    def get_section_contents_by_name(self, section_name):
        sections = self.get_sections_by_name(section_name)
        if len(sections) > 0:
            return sections[0].get_contents_as_extractor()
        else:
            return None

    def get_section_headers(self) -> list[SectionHeader]:
        if self.section_headers is None:
            self.section_headers = list()
            if self.is_valid():
                if (self.header.e_shnum > 0 and
                    self.header.e_shentsize > 0 and
                    self.header.e_shoff > self.header.e_ehsize):
                    self.data.seek(self.header.e_shoff)
                    for section_index in range(self.header.e_shnum):
                        self.section_headers.append(
                                SectionHeader(self, section_index))
                    sh = self.section_headers[self.header.e_shstrndx]
                    shstrtab = StringTable(sh.get_contents_as_extractor())
                    for section_index in range(self.header.e_shnum):
                        section = self.section_headers[section_index]
                        section.name = shstrtab.get_string(section.sh_name)
        return self.section_headers

    def get_section_containing_address(self, addr) -> SectionHeader | None:
        sections = self.get_section_headers()
        for section in sections:
            if section.contains(addr):
                return section
        return None

    def get_program_headers(self) -> list[ProgramHeader]:
        if self.program_headers is None:
            self.program_headers = list()
            if self.is_valid():
                self.data.seek(self.header.e_phoff)
                for idx in range(self.header.e_phnum):
                    self.program_headers.append(ProgramHeader.decode(self,
                                                                     idx))
        return self.program_headers

    def get_program_headers_by_type(self, p_type) -> list[ProgramHeader]:
        matching_phs = []
        for ph in self.get_program_headers():
            if ph.p_type == p_type:
                matching_phs.append(ph)
        return matching_phs

    def get_program_headers_by_vaddr_in_file(self, vaddr) -> ProgramHeader | None:
        for ph in self.get_program_headers():
            if ph.contains_vaddr_in_file(vaddr):
                return ph
        return None

    def get_program_header_by_type(self, p_type, start_idx=0) -> ProgramHeader | None:
        '''
        Find the first program header with the specified type starting at the
        specified index.
        '''
        program_headers = self.get_program_headers()
        count = len(program_headers)
        if start_idx < count:
            for i in range(start_idx, count):
                if program_headers[i].p_type == p_type:
                    return program_headers[i]
        return None

    def read_memory_as_data(self, addr, size) -> FileExtract | None:
        '''
        Read the memory as bytes at the specified address and return it as a
        bytes FileExtract from a program header vaddr.
        '''
        if self.data is None:
            return None
        for ph in self.get_program_headers_by_type(PT.LOAD):
            if ph.contains_vaddr_in_file(addr):
                offset = addr - ph.p_vaddr
                # bytes_left = ph.p_filesz - offset
                # if bytes_left <= 0:
                #     return None
                # if size > bytes_left:
                #     size = bytes_left
                file_offset = offset + ph.p_offset
                self.data.push_offset_and_seek(file_offset)
                data = self.data.read_data(size)
                self.data.pop_offset_and_seek()
                return data
        return None

    def read_memory_as_bytes(self, addr, size) -> bytes | None:
        '''
        Read the memory as bytes at the specified address and return it as a
        bytes object from a program header vaddr.
        '''
        if self.data is None:
            return None
        for ph in self.get_program_headers_by_type(PT.LOAD):
            if ph.contains_vaddr_in_file(addr):
                offset = addr - ph.p_vaddr
                # bytes_left = ph.p_filesz - offset
                # if bytes_left <= 0:
                #     return None
                # if size > bytes_left:
                #     size = bytes_left
                file_offset = offset + ph.p_offset
                self.data.push_offset_and_seek(file_offset)
                bytes = self.data.read_size(size)
                self.data.pop_offset_and_seek()
                return bytes
        return None

    def read_memory_as_c_string(self, addr):
        '''
        Read a null-terminated C string from memory at the specified address
        from a program header vaddr.
        '''

        if self.data is None:
            return None
        for ph in self.get_program_headers_by_type(PT.LOAD):
            if ph.contains_vaddr_in_file(addr):
                offset = addr - ph.p_vaddr
                file_offset = offset + ph.p_offset
                self.data.push_offset_and_seek(file_offset)
                s = self.data.get_c_string()
                self.data.pop_offset_and_seek()
                return s
        return None


    def find_matching_program_header(self, other_phdr: ProgramHeader) -> ProgramHeader | None:
        phdrs = self.get_program_headers()
        for phdr in phdrs:
            if phdr.p_type != other_phdr.p_type:
                continue
            elif phdr.p_type == PT.LOAD:
                # Find a program header with the same p_vaddr for PT_LOAD
                if phdr.p_vaddr == other_phdr.p_vaddr:
                    return phdr
            else:
                print("Not comparing program header:\n {phdr1}")
        return None

    def get_symbols(self) -> list[Symbol]:
        '''Common object file format symbol method.'''
        if self.symbols is None and self.is_valid():
            self.symbols = list()
            self.dynsym = list()
            self.symtab = list()
            sections = self.get_section_headers()
            addr_size = self.get_addr_size()
            for section in sections:
                if section.sh_type not in [SHT.DYNSYM, SHT.SYMTAB]:
                    continue
                symtab_data = section.get_contents_as_extractor()
                sh = sections[section.sh_link]
                strtab = StringTable(sh.get_contents_as_extractor())
                symtab_data_size = symtab_data.get_size()
                num_symbols = symtab_data_size // self.get_symbol_size()
                addr_mask = self.get_address_mask()
                for i in range(num_symbols):
                    symbol = Symbol(i, addr_size, symtab_data, strtab, self,
                                    addr_mask)
                    if section.sh_type == SHT.DYNSYM:
                        self.dynsym.append(symbol)
                    else:
                        self.symtab.append(symbol)
                    self.symbols.append(symbol)
        return self.symbols

    def get_dynsym(self) -> list[Symbol]:
        '''Get only the dynamic symbol table. The dynamic symbol table is
           contained in the section whose type is SHT_DYNSYM.'''
        self.get_symbols()
        return self.dynsym

    def get_symtab(self) -> list[Symbol]:
        '''Get only the normal symbol table. The normal symbol table is
           contained in the section whose type is SHT_SYMTAB.'''
        self.get_symbols()
        return self.symtab

    def get_symtab_functions(self, sym_tree=None) -> SymbolTree:
        '''Get the symbol table functions'''
        if sym_tree is None:
            sym_tree = SymbolTree()
        calculate_symbol_checks(self, sym_tree, self.get_symtab())
        return sym_tree

    def get_dynsym_functions(self, sym_tree):
        '''Get the dynamic symbol table functions'''
        if sym_tree is None:
            sym_tree = SymbolTree()
        calculate_symbol_checks(self, sym_tree, self.get_dynsym())
        return sym_tree

    def get_dynamic(self) -> list[ELFDynamic]:
        '''Get the array of dynamic entries in this ELF file.'''
        if self.dynamic is None:
            self.dynamic = list()
            if self.is_valid():
                data = None
                ph = self.get_program_header_by_type(PT.DYNAMIC)
                if ph:
                    data = ph.get_contents_as_extractor()
                if data is None:
                    sections = self.get_section_headers()
                    for section in sections:
                        if section.sh_type == SHT.DYNAMIC:
                            sh = sections[section.sh_link]
                            self.dynstr = StringTable(sh.get_contents_as_extractor())
                            data = section.get_contents_as_extractor()
                            break
                if data is not None:
                    index = 0
                    while 1:
                        dynamic = ELFDynamic(index, data)
                        if dynamic.d_tag == DT.NULL:
                            break
                        self.dynamic.append(dynamic)
                        index += 1
        return self.dynamic

    def get_first_dynamic_entry_value(self, d_tag):
        '''Get the first dynamic entry's value whose tag is "d_tag"'''
        entries = self.get_dynamic()
        for dyn in entries:
            if dyn.d_tag == d_tag:
                return dyn.d_val
        return None

    def get_symbol_containing_address(self, addr):
        symbols = self.get_symbols()
        for symbol in symbols:
            if symbol.contains(addr):
                return symbol
        return None

    def lookup_address(self, addr, f=sys.stdout):
        f.write('Looking up 0x%x in "%s":\n' % (addr, self.path))
        section = self.get_section_containing_address(addr)
        if section:
            section.dump(flat=False, f=f)
            f.write('\n')
        symbol = self.get_symbol_containing_address(addr)
        if symbol:
            symbol.dump(flat=False, f=f)

    def dump_section_headers_with_type(self, options, sh_type,
                                       f=sys.stdout) -> bool:
        sh_type_enum = SHT(sh_type)
        f.write('Dumping section with type %s:\n' % (sh_type_enum))
        sections = self.get_section_headers()
        if sections:
            found = False
            for section in sections:
                if section.sh_type == sh_type:
                    found = True
                    section.dump(flat=False, f=f)
                    f.write('\n')
                    contents = section.get_contents()
                    if contents:
                        if sh_type == SHT.NOTE:
                            notes = Note.extract_notes(
                                    section.get_contents_as_extractor())
                            for note in notes:
                                note.dump(options, f=f)
                        else:
                            file_extract.dump_memory(section.sh_addr,
                                                     contents,
                                                     options.num_per_line, f)
            if found:
                return True
            f.write('error: no sections with type %s were found\n' % (sh_type_enum))
        else:
            f.write('error: no section headers\n')
        return False

    def dump_program_headers_with_type(self, options, type,
                                       f=sys.stdout):
        p_type = PT(type)
        f.write('Dumping program headers with type %s:\n' % (p_type))
        program_headers = self.get_program_headers()
        if program_headers:
            found = False
            for ph in program_headers:
                if ph.p_type == p_type:
                    found = True
                    ph.dump(flat=False, f=f)
                    f.write('\n')
                    contents = ph.get_contents()
                    if contents:
                        if p_type == PT.NOTE:
                            notes = Note.extract_notes(
                                    ph.get_contents_as_extractor())
                            for note in notes:
                                note.dump(options, f=f, elf=self)
                        else:
                            file_extract.dump_memory(ph.p_vaddr, contents,
                                                     options.num_per_line, f)
            if found:
                return True
            f.write('error: no program headers with type %s were found\n' % (p_type))
        else:
            f.write('error: no program headers')
        return False

    def dump_file_summary(self, f=sys.stdout):
        f.write('ELF: %s (%s)\n' % (self.path, self.get_arch()))

    def is_arm(self):
        return self.header.is_arm()

    def encode_yaml(self, f):
        self.header.encode_yaml(f)
        f.write('ProgramHeaders:\n')
        headers = self.get_program_headers()
        for ph in headers:
            ph.encode_yaml(f)
        f.write('Sections:\n')
        sections = self.get_section_headers()
        real_sections_added = False
        if sections:
            for section in sections:
                pass # section.encode_yaml(f)
        else:
            # No sections, but program headers can contain data which we can
            # use Fake sections to represent the data in the program headers.
            for ph in headers:
                ph.encode_yaml_section_data(f)

        if not real_sections_added:
            f.write('  - Type:            SectionHeaderTable\n')
            f.write('    NoHeaders:       true\n')

    def dump_program_headers(self, options, f=sys.stdout):
        f.write('Program headers:\n')
        ProgramHeader.dump_header(f=f)
        program_headers = self.get_program_headers()
        for program_header in program_headers:
            program_header.dump(flat=True, f=f)
            f.write('\n')
        f.write('\n')

    def dump_auxv(self, options, f=sys.stdout):
        note = self.get_note(['CORE', 'LINUX'], NT_LINUX.AUXV)
        if note:
            note.dump(options, elf=self)
        else:
            print('error: no NT_AUXV found in notes')

    def dump(self, options, f=sys.stdout):
        if not options.api:
            self.dump_file_summary(f=f)
        if self.is_valid():
            if options.dump_header:
                self.header.dump(f)
                if options.dump_program_headers:
                    f.write('\n')
            if options.dump_program_headers:
                self.dump_program_headers(options, f=f)
            if options.dump_section_headers:
                sections = self.get_section_headers()
                for section in sections:
                    section.dump(flat=True, f=f)
                    f.write('\n')
                f.write('\n')
            if options.dump_section_summary:
                sections = self.get_section_headers()
                elf_file_size = self.data.get_size()
                f.write('Byte size   Size   % file  Name\n')
                f.write('----------- ------ ------- -----------------------\n')
                total_section_size = 0
                ssi = {}
                for (i, section) in enumerate(sections):
                    if i == 0:
                        continue
                    if section.sh_size in ssi:
                        ssi[section.sh_size].append(section)
                    else:
                        ssi[section.sh_size] = [section]
                for size in sorted(ssi.keys(), reverse=True):
                    for section in ssi[size]:
                        total_section_size += size
                        f.write("%11u %6s %6.2f%% %s\n" % (size,
                                sizeof_fmt(size),
                                get_percentage(size, elf_file_size),
                                section.name))
                f.write('=========== ====== ======= =======================\n')
                f.write("%11u %6s %6.2f%%\n" % (total_section_size,
                        sizeof_fmt(total_section_size),
                        get_percentage(total_section_size, elf_file_size)))
            if options.gnu_build_id is not None:
                try:
                    # Locate "objcopy" in the current path if it wasn't
                    # specified
                    if options.objcopy is None:
                        paths = os.environ['PATH'].split(os.pathsep)
                        for basename in ['objcopy', 'llvm-objcopy']:
                            for path in paths:
                                objcopy_path = os.path.join(path, basename)
                                if os.path.exists(objcopy_path):
                                    options.objcopy = objcopy_path
                                    break
                            if options.objcopy is not None:
                                break
                        if options.objcopy is None:
                            raise ValueError('error: no "objcopy" or '
                                             '"llvm-objcopy" binary was found '
                                             'your path:\n%s\nSpecify the '
                                             'path to the objcopy binary with '
                                             '--objcopy' % (paths))
                    # strip all '-' characters from input string
                    uuid_hex_only = options.gnu_build_id.replace('-', '')
                    # Get the hex bytes from this string
                    uuid_bytes = binascii.unhexlify(uuid_hex_only)
                    # Create a note for the GNU build ID
                    note = Note("GNU", NT_LINUX.GNU_BUILD_ID_TAG,
                                self.create_extractor(io.BytesIO(uuid_bytes)))
                    # Make a temp file and encode the above note object into
                    # the file so we can use objcopy to insert the note into
                    # it
                    gnu_build_id_path = None
                    with tempfile.NamedTemporaryFile(delete=False) as f:
                        gnu_build_id_path = f.name
                        encoder = self.create_encoder(f)
                        note.encode(encoder)
                    # If all went well lets add the note to the ELF file.
                    if gnu_build_id_path:
                        sect_name = '.note.gnu.build-id'
                        subprocess.call([options.objcopy,
                                        "--remove-section", sect_name,
                                        self.path])

                        subprocess.call([options.objcopy,
                                            "--add-section",
                                            "%s=%s" % (sect_name,
                                                    gnu_build_id_path),
                                            self.path])
                        print('Updated GNU build ID to "%s"' % (
                              options.gnu_build_id))
                        # Remove the temp file we used that contains the GNU
                        # build ID bytes.
                        os.unlink(gnu_build_id_path)
                except ValueError as e:
                    print(e)

            if options.dump_symtab:
                symbols = self.get_symtab()
                if symbols:
                    f.write("Symbol table:\n")
                    Symbol.dump_header(f=f)
                    for (idx, symbol) in enumerate(symbols):
                        symbol.dump(flat=True, f=f)
                    f.write('\n')
                else:
                    f.write("error: ELF file doesn't contain a SHT_SYMTAB "
                            "section\n")
            if options.dump_dynsym:
                symbols = self.get_dynsym()
                if symbols:
                    f.write("Dynamic symbol table:\n")
                    Symbol.dump_header(f=f)
                    for (idx, symbol) in enumerate(symbols):
                        symbol.dump(flat=True, f=f)
                    f.write('\n')
                else:
                    f.write("error: ELF file doesn't contain a SHT_DYNSYM "
                            "section\n")

            if options.symbol_check:
                sym_tree = SymbolTree()
                self.get_symtab_functions(sym_tree)
                #self.get_dynsym_functions(sym_tree)
                sym_tree.dump(f)
                # def symbol_address_range_compare(s1, s2):
                #     if s1.st_value != s2.st_value:
                #         return -1 if s1.st_value < s2.st_value else 1
                #     if s1.st_size != s2.st_size:
                #         return -1 if s1.st_size < s2.st_size else 1
                #     if s1.name != s2.name:
                #         return -1 if s1.name < s2.name else 1
                #     return 0
                # func_symbols.sort(cmp=symbol_address_range_compare)
                # f.write("Symbol table:\n")
                # Symbol.dump_header(f=f)
                # prev_symbol = None
                # for symbol in func_symbols:
                #     symbol.dump(flat=True, f=f)
                #     if prev_symbol and symbol.st_value == prev_symbol.st_value and symbol.st_size != prev_symbol.st_size:
                #         f.write('warning: this symbol overlaps with a previous symbol\n')
                #     prev_symbol = symbol
                # f.write('\n')

                # func_info.dump(options.verbose)

            if options.section_names:
                f.write('\n')
                for section_name in options.section_names:
                    sections = self.get_sections_by_name(section_name)
                    if sections:
                        for section in sections:
                            contents = section.get_contents(options.section_offset, options.section_size)
                            if contents:
                                if options.section_offset:
                                    if options.section_size:
                                        f.write('Dumping %u bytes from section "%s" starting at offset %#8.8x:\n' % (options.section_size, section_name, options.section_offset))
                                    else:
                                        f.write('Dumping the section contents of "%s" starting at offset %#8.8x:\n' % (section_name, options.section_offset))
                                else:
                                    if options.section_size:
                                        f.write('Dumping the first %u bytes from section "%s":\n' % (options.section_size, section_name))
                                    else:
                                        f.write('Dumping the section contents of "%s":\n' % (section_name))
                                base_addr = section.sh_addr
                                if options.section_offset is not None:
                                    base_addr += options.section_offset
                                file_extract.dump_memory(base_addr,
                                                         contents,
                                                         options.num_per_line,
                                                         f)
                    else:
                        f.write('error: no sections named %s were found\n' %
                                (section_name))
            if options.gnu_debugdata:
                f.write('\n')
                gnu_debugdata_path = self.path + ".gnu_debugdata"
                compressed_path = self.path + ".lzma"
                if os.path.exists(gnu_debugdata_path):
                    f.write('error: .gnu_debugdata file "%s" exists already\n' % (gnu_debugdata_path))
                else:
                    sections = self.get_sections_by_name(".gnu_debugdata")
                    if sections:
                        if len(sections) > 1:
                            f.write('warning: multiple ".gnu_debugdata" setions\n')
                        else:
                            with open(compressed_path, 'w') as lzma_f:
                                lzma_f.write(sections[0].get_contents())
                                lzma_f.close()
                            subprocess.call(["xz", "--decompress", "--stdout", compressed_path],
                                        #    capture_output=True,
                                           stdout=open(gnu_debugdata_path, 'w'))
                            os.unlink(compressed_path)
                            f.write(".gnu_debugdata compressed file saved to '%s'\n" % (gnu_debugdata_path))
            if options.gnu_hash:
                self.get_hash_table().dump(f=f)
            if options.section_types:
                f.write('\n')
                for section_type in options.section_types:
                    self.dump_section_headers_with_type(options, section_type)
            if options.program_header_types:
                f.write('\n')
                for ph_type in options.program_header_types:
                    self.dump_program_headers_with_type(options, ph_type)
            if options.dump_notes:
                f.write('\n')
                if not self.dump_program_headers_with_type(options, PT.NOTE):
                    self.dump_section_headers_with_type(options, SHT.NOTE)
            if options.dump_auxv:
                self.dump_auxv(options)
            if options.dump_nt_file:
                note = self.get_note(['CORE', 'LINUX'], NT_LINUX.FILE)
                if note:
                    note.dump(options, elf=self)
                else:
                    print('error: no NT_FILE found in notes')
            if options.core_info:
                self.dump_core_info(options, f=f)
            if options.dump_dynamic:
                dynamic_entries = self.get_dynamic()
                for dynamic_entry in dynamic_entries:
                    dynamic_entry.dump(elf=self, f=f)
            if options.undefined:
                symbols = self.get_symbols()
                if symbols:
                    undefined_symbols = {}
                    f.write('Undefined symbols:\n')
                    if options.verbose:
                        Symbol.dump_header(f=f)
                    for (idx, symbol) in enumerate(symbols):
                        if (symbol.st_shndx == SHN_UNDEF and
                                symbol.get_binding() == STB_GLOBAL):
                            if options.verbose:
                                symbol.dump(flat=True, f=f)
                            else:
                                symbol_name = symbol.name
                                if symbol_name not in undefined_symbols:
                                    undefined_symbols[symbol_name] = symbol
                    symbol_names = undefined_symbols.keys()
                    if symbol_names:
                        symbol_names.sort()
                        for symbol_name in symbol_names:
                            f.write(symbol_name)
                            symbol = undefined_symbols[symbol_name]
                            if symbol.get_binding() == STB_WEAK:
                                f.write(' (weak)')
                            f.write('\n')
                        f.write('\n')
                    else:
                        f.write('no undefined symbols\n')
            if options.api:
                api_dict = self.get_api_info()
                f.write(json.dumps(api_dict, indent=2, ensure_ascii=False))
                f.write('\n')
            if options.yaml:
                with open(options.yaml, 'w') as f:
                    self.encode_yaml(f)
            if options.func_ranges:
                func_info = FunctionInfo()
                # Get symbols from symbol table
                symbols = self.get_symbols()
                is_arm = self.is_arm()
                for symbol in symbols:
                    if symbol.st_shndx > 0 and symbol.st_shndx < SHN_LORESERVE:
                        stt = symbol.get_type()
                        if stt == STT.SECTION:
                            continue
                        section = self.get_section_by_shndx(symbol.st_shndx)
                        if section.sh_type == SHT.NOTE:
                            if options.verbose:
                                f.write('ignoring %#x ("%s") since symbol is '
                                        'in section with type SHT_NOTE\n' %
                                        (symbol.st_value, symbol.name))
                            continue
                        # Ignore data
                        if (section.sh_flags & SHF.EXECINSTR) == 0:
                            if options.verbose:
                                f.write('ignoring %#x ("%s") since symbol is '
                                        'in section flags don\'t contain '
                                        'SHF_EXECINSTR\n' % (symbol.st_value,
                                                             symbol.name))
                            continue
                        if is_arm:
                            # Symbols have bit zero set to indicate thumb
                            func_info.add_arm_thumb(addr=symbol.st_value,
                                                    size=symbol.st_size,
                                                    name=symbol.name,
                                                    source='symtab')
                        else:
                            func_info.add(addr=symbol.st_value,
                                          size=symbol.st_size,
                                          name=symbol.name,
                                          source='symtab')
                # Get EH frame info
                eh_frame = dwarf.options.get_unwind_info(self, True)
                if eh_frame:
                    eh_frame.get_function_info(func_info)
                # Get .debug_frame info
                # debug_frame = dwarf.options.get_unwind_info(self, False)
                # if debug_frame:
                #     debug_frame.get_function_info(func_info)
                # Get ARM compact unwind info
                ARMUnwind(self).get_function_info(func_info)
                if self.header.e_entry != 0:
                    if is_arm:
                        func_info.add_arm_thumb(addr=self.header.e_entry,
                                                source='ELFHeader.e_entry')
                    else:
                        func_info.add(addr=self.header.e_entry,
                                      source='ELFHeader.e_entry')

                # Get dynamic table and look for addresses in there
                entries = self.get_dynamic()
                dt_init_array = None
                dt_fini_array = None
                dt_init_size = None
                dt_fini_size = None
                for dyn in entries:
                    dyn_enum = dyn.d_tag
                    if dyn_enum == DT.INIT:
                        func_info.add(dyn.d_val, source='DT_INIT')
                    elif dyn_enum == DT.FINI:
                        func_info.add(dyn.d_val, source='DT_FINI')
                    elif dyn_enum == DT.INIT_ARRAY:
                        dt_init_array = dyn.d_val
                    elif dyn_enum == DT.FINI_ARRAY:
                        dt_fini_array = dyn.d_val
                    elif dyn_enum == DT.INIT_ARRAYSZ:
                        dt_init_size = dyn.d_val
                    elif dyn_enum == DT.FINI_ARRAYSZ:
                        dt_fini_size = dyn.d_val
                if dt_init_array is not None and dt_init_size is not None:
                    dt_init_data = self.read_data_from_file_addr(dt_init_array,
                                                                 dt_init_size)
                    if dt_init_data:
                        count = dt_init_size / dt_init_data.get_addr_size()
                        for _i in range(count):
                            addr = dt_init_data.get_address(None)
                            if (addr and addr != 0xffffffff and
                                    addr != 0xffffffffffffffff):
                                if is_arm:
                                    func_info.add_arm_thumb(
                                            addr, source='DT_INIT_ARRAY')
                                else:
                                    func_info.add(addr, source='DT_INIT_ARRAY')
                    else:
                        print("error: couldn't read DT_INIT_ARRAY")
                if dt_fini_array is not None and dt_fini_size is not None:
                    dt_fini_data = self.read_data_from_file_addr(dt_fini_array,
                                                                 dt_fini_size)
                    if dt_fini_data:
                        count = dt_fini_size / dt_fini_data.get_addr_size()
                        for _i in range(count):
                            addr = dt_init_data.get_address(None)
                            if (addr and addr != 0xffffffff and
                                    addr != 0xffffffffffffffff):
                                if is_arm:
                                    func_info.add_arm_thumb(
                                            addr, source='DT_FINI_ARRAY')
                                else:
                                    func_info.add(addr, source='DT_FINI_ARRAY')
                    else:
                        print("error: couldn't read DT_INIT_ARRAY")
                func_info.dump(options.verbose)
            dwarf.options.handle_options(options, self, f)

    def get_gnu_build_id(self):
        gnu_build_id_note = self.get_note(['GNU'], NT_GNU.BUILD_ID)
        if gnu_build_id_note is None:
            return None
        uuid_bytes = gnu_build_id_note.data.get_all_bytes()
        if uuid_bytes:
            return uuid_bytes
        return None

    def get_api_info(self):
        symbols = self.get_symbols()
        api_info = dict()
        api_info['path'] = self.path
        api_info['dependencies'] = list()
        dynamic_entries = self.get_dynamic()
        for dyn in dynamic_entries:
            if dyn.d_tag == DT.NEEDED:
                api_info['dependencies'].append(
                        self.dynstr.get_string(dyn.d_val))

        if symbols:
            undef_map = {}
            export_map = {}
            for (idx, symbol) in enumerate(symbols):
                if symbol.get_binding() != STB_GLOBAL:
                    continue
                if symbol.st_shndx == SHN_UNDEF:
                    if symbol.name not in undef_map:
                        undef_map[symbol.name] = symbol
                if symbol.value_is_address():
                    if symbol.name not in export_map:
                        export_map[symbol.name] = symbol
            undef_names = undef_map.keys()
            if undef_names:
                undef_names.sort()
            api_info['imports'] = undef_names
            export_names = export_map.keys()
            if export_names:
                export_names.sort()
            api_info['exports'] = export_names
        return api_info


def handle_elf(options, path):
    elf = File(path=path)
    if elf.is_valid():
        if options.links_against:
            dynamic_entries = elf.get_dynamic()
            for dyn in dynamic_entries:
                if dyn.d_tag == DT.NEEDED:
                    shlib__name = elf.dynstr.get_string(dyn.d_val)
                    if shlib__name in options.links_against:
                        print('ELF: %s links against %s ' % (path,
                                                             shlib__name))
                        break
        elif options.hash_lookups:
            elf.dump_file_summary()
            for name in options.hash_lookups:
                hash_table = elf.get_hash_table()
                if hash_table:
                    symbol = hash_table.lookup(name)
                    if symbol:
                        print('Found "%s" in hash table of "%s"...' % (name,
                              elf.path))
                        symbol.dump(False)
        else:
            elf.dump(options=options)
    else:
        if elf.error:
            print(elf.error)
        else:
            print('error: %s is not a valid ELF file' % (path))


def user_specified_options(options):
    '''Return true if the user specified any options, false otherwise.'''
    if options.dump_symtab or options.dump_dynsym or options.symbol_check:
        return True
    if options.dump_program_headers:
        return True
    if options.dump_section_headers:
        return True
    if options.dump_section_summary:
        return True
    if options.gnu_build_id:
        return True
    if options.dump_dynamic:
        return True
    if options.dump_program_headers:
        return True
    if options.dump_header:
        return True
    if options.dump_notes:
        return True
    if options.dump_auxv:
        return True
    if options.dump_nt_file:
        return True
    if options.core_info:
        return True
    if options.section_names:
        return True
    if options.section_types:
        return True
    if options.undefined:
        return True
    if options.api:
        return True
    if len(options.links_against) > 0:
        return True
    if dwarf.options.have_dwarf_options(options):
        return True
    if len(options.hash_lookups) > 0:
        return True
    if options.yaml:
        return True
    if options.func_ranges:
        return True
    if options.gnu_debugdata:
        return True
    return False


def create_addr_to_symbols(symtab):
    addr_to_symbols = defaultdict([])
    for symbol in symtab:
        if not symbol.value_is_address():
            continue
        addr_to_symbols[symbol.st_value].append(symbol)
    return addr_to_symbols


def dump_addr_to_symbols(addr_to_symbols):
    Symbol.dump_header(f=sys.stdout)
    for addr in sorted(addr_to_symbols.keys()):
        symbols = addr_to_symbols[addr]
        for symbol in symbols:
            symbol.dump(flat=True, f=sys.stdout)

def unique(list1):
    set1 = set(list1)
    return list(set1)


def dump_addrs(addrs):
    for addr in addrs:
        print("0x%16.16x" % (addr))


def dump_range_section_name(symbol, f=sys.stdout):
    if symbol.section:
        sect_name = symbol.section.name
    else:
        sect_name = ''
    if symbol.st_size > 0:
        f.write("[0x%16.16x - 0x%16.16x) %-32s %s\n" % (symbol.st_value,
                symbol.st_value + symbol.st_size, sect_name, symbol.name))
    else:
        f.write("[0x%16.16x                     ) %-32s %s\n" % (
                symbol.st_value, sect_name, symbol.name))

def compare_symbols(symtab1, symtab2, symtab_name, f=sys.stdout):
    f.write('\nComparing %s symbols:\n' % (symtab_name))
    addr_to_symbols1 = create_addr_to_symbols(symtab1)
    addr_to_symbols2 = create_addr_to_symbols(symtab2)

    addrs1 = addr_to_symbols1.keys()
    addrs2 = addr_to_symbols2.keys()
    # f.write('Addrs1:\n')
    # dump_addrs(addrs1)
    # f.write('Addrs2:\n')
    # dump_addrs(addrs2)

    addrs1.extend(addrs2)
    sorted_addrs = sorted(unique(addrs1))
    # f.write('Combined addrs:')
    # dump_addrs(sorted_addrs)
    f.write("1 2 Range                                     Section                          Name\n")
    f.write("=== ========================================= ================================ ============================\n")
    for addr in sorted_addrs:
        if addr in addr_to_symbols1:
            symbols1 = addr_to_symbols1[addr]
        else:
            symbols1 = []
        if addr in addr_to_symbols2:
            symbols2 = addr_to_symbols2[addr]
        else:
            symbols2 = []
        num_symbols1 = len(symbols1)
        num_symbols2 = len(symbols2)
        if num_symbols1 > 0:
            if num_symbols2 > 0:
                if symbols1 == symbols2:
                    for symbol in symbols1:
                        f.write('X X ')
                        dump_range_section_name(symbol, f=f)
                else:
                    f.write('error: symbols for address differ...\n')
            else:
                for symbol in symbols1:
                    f.write('X   ')
                    dump_range_section_name(symbol, f=f)
        elif num_symbols2 > 0:
            for symbol in symbols2:
                f.write('  X ')
                dump_range_section_name(symbol, f=f)
        else:
            f.write('error: symbol for address %#x not found...\n' % (addr))


def compare_symtab(symtab1, symtab2, symtab_name):
    print("\nComparing %s symbol tables:" % (symtab_name))
    if symtab1:
        if symtab2:
            compare_symbols(symtab1, symtab2, symtab_name)
        else:
            print("Only 1 has a %s symbol table" % (symtab_name))
    elif symtab2:
        print("Only 2 has a %s symbol table" % (symtab_name))
    else:
        print("No %s symbol tables" % (symtab_name))


def compare_elf_files(elf1_path, elf2_path):
    print("Comparing:\n1: %s\n2: %s" % (elf1_path, elf2_path))
    elf1 = File(path=elf1_path)
    if not elf1.is_valid():
        print('error: "%s" is not a valid ELF file' % (elf1_path))
        return

    elf2 = File(path=elf2_path)
    if not elf2.is_valid():
        print('error: "%s" is not a valid ELF file' % (elf2_path))
        return
    print("\nComparing program headers:")
    elf1_phdrs = elf1.get_program_headers()
    elf2_phdrs = elf2.get_program_headers()
    elf1_file_size = elf1.data.get_size()
    elf2_file_size = elf2.data.get_size()
    elf1_phdrs_not_in_elf2 = []
    elf2_phdrs_not_in_elf1 = []
    elf1_total_phdr_filesz = 0
    elf2_total_phdr_filesz = 0
    verified_elf2_phdr_indexes = set()
    for phdr1 in elf1_phdrs:
        if phdr1.p_type == PT.NOTE:
            print("TODO: implement note comparison...")
        elif phdr1.p_type == PT.LOAD:
            if phdr1.p_filesz > 0:
                elf1_total_phdr_filesz += phdr1.p_filesz
                error1 = None  # Elf1 program header error
                error = None  # Mismatch in program header between elf1 and elf2
                if phdr1.p_offset >= elf1_file_size:
                    error1 = f'error: p_offset is larger than the file size ({elf1_file_size}) for "{elf1_path}"'
                if phdr1.p_offset + phdr1.p_filesz > elf1_file_size:
                    error1 = f'error: p_offset + p_filesz ({phdr1.p_offset + phdr1.p_filesz:016x}) is larger than the file size ({elf1_file_size}) for "{elf1_path}"'
                phdr2 = elf2.find_matching_program_header(phdr1)
                if phdr2 is None:
                    if phdr1.p_filesz > 0:
                        elf1_phdrs_not_in_elf2.append(phdr1)
                else:
                    verified_elf2_phdr_indexes.add(phdr2.index)
                    if phdr1.p_paddr != phdr2.p_paddr:
                        error = 'error: p_paddr mismatch'
                    if phdr1.p_filesz != phdr2.p_filesz:
                        error = 'error: p_filesz mismatch'
                    if phdr1.p_memsz != phdr2.p_memsz:
                        error = 'error: p_memsz mismatch'
                    if phdr1.p_align != phdr2.p_align:
                        error = 'error: p_align mismatch'
                    # Only compare contents if there are bytes in the file
                    # if phdr1.p_filesz == 0 and phdr2.p_filesz == 0:
                    #     print('success: there are no file contents in either program header')
                    # else:
                    #     contents1 = phdr1.get_contents()
                    #     contents2 = phdr2.get_contents()
                    #     if contents1 is None:
                    #         print('error: unable to decode contents of first program header')
                    #     if contents2 is None:
                    #         print('error: unable to decode contents of second program header')
                    #     if contents1 and contents2:
                    #         if contents1 == contents2:
                    #             print('success: contents match exactly')
                    #         else:
                    #             diff_offset = find_diff_offset(contents1, contents2)
                    #             print(f'error: contents do not match (starting at offset {diff_offset}, p_vaddr = 0x{diff_offset + phdr1.p_vaddr:x})')
                if error1 or error:
                    if error1:
                        print(error1)
                    if error:
                        print(error)
                    ProgramHeader.dump_header()
                    phdr1.dump(flat=True, suffix=f' from "{elf1_path}"\n')
                    if error:
                        phdr2.dump(flat=True, suffix=f' from "{elf2_path}"\n')

    for phdr2 in elf2_phdrs:
        if phdr2.p_type == PT.LOAD:
            if phdr2.p_filesz > 0:
                elf2_total_phdr_filesz += phdr2.p_filesz
                error2 = None  # Elf1 program header error
                if phdr2.p_offset >= elf2_file_size:
                    error2 = f'error: p_offset is larger than the file size ({elf2_file_size}) for "{elf2_path}"'
                if phdr2.p_offset + phdr2.p_filesz > elf2_file_size:
                    error2 = f'error: p_offset + p_filesz ({phdr2.p_offset + phdr2.p_filesz:016x}) is larger than the file size ({elf2_file_size}) for "{elf2_path}"'
                phdr1 = elf1.find_matching_program_header(phdr2)
                if phdr1 is None:
                    if phdr2.p_filesz > 0:
                        elf2_phdrs_not_in_elf1.append(phdr2)
                if error2:
                    print(error2)
                    ProgramHeader.dump_header()
                    phdr2.dump(flat=True, suffix=f' from "{elf2_path}"\n')

    if elf1_phdrs_not_in_elf2:
        print(f'PT_LOAD program headers with non-zero p_filesz values present in "{elf1_path}" but not on "{elf2_path}":')
        ProgramHeader.dump_header()
        for phdr in elf1_phdrs_not_in_elf2:
            phdr.dump(flat=True, suffix=f' from "{elf1_path}"\n')

    if elf2_phdrs_not_in_elf1:
        print(f'PT_LOAD program headers with non-zero p_filesz values present in "{elf2_path}" but not on "{elf1_path}":')
        ProgramHeader.dump_header()
        for phdr in elf2_phdrs_not_in_elf1:
            phdr.dump(flat=True, suffix=f' from "{elf1_path}"\n')
    print(f'Total PT_LOAD file size for "{elf1_path}" is {sizeof_fmt(elf1_total_phdr_filesz)}')
    print(f'Total PT_LOAD file size for "{elf2_path}" is {sizeof_fmt(elf2_total_phdr_filesz)}')

    print("\nComparing sections:")
    elf1_section_headers = elf1.get_section_headers()
    elf2_section_headers = elf2.get_section_headers()
    for section in elf1_section_headers:
        if section.index == 0:
            continue
        if len(elf2.get_sections_by_name(section.name)) == 0:
            print('Only 1 has section "%s"' % (section.name))
    for section in elf2_section_headers:
        if section.index == 0:
            continue
        if len(elf1.get_sections_by_name(section.name)) == 0:
            print('Only 2 has section "%s"' % (section.name))
    dysymtab1 = elf1.get_dynsym()
    dysymtab2 = elf2.get_dynsym()
    compare_symtab(dysymtab1, dysymtab2, "SHT_DYNSYM")

    symtab1 = elf1.get_symtab()
    symtab2 = elf2.get_symtab()
    compare_symtab(symtab1, symtab2, "SHT_SYMTAB")

    # See if one file only has a dynamic symbol table and the other has a
    # normal symbol table. If so, compare those.
    if not (dysymtab1 and dysymtab2):
        if not (symtab1 and symtab2):
            if (dysymtab1 and symtab2):
                compare_symbols(dysymtab1, symtab2, "1 SHT_DYNSYM and 2 SHT_SYMTAB")
            if (symtab1 and dysymtab2):
                compare_symbols(symtab1, dysymtab2, "1 SHT_SYMTAB and 2 SHT_DYNSYM")

def main():
    parser = optparse.OptionParser(
        description='A script that parses ELF files.')
    parser.add_option(
        '-v', '--verbose',
        action='store_true',
        dest='verbose',
        help='Display verbose debug info',
        default=False)
    parser.add_option(
        '-g', '--debug',
        action='store_true',
        dest='debug',
        help='Dump debug level logging',
        default=False)
    parser.add_option(
        '-s', '--symtab',
        action='store_true',
        dest='dump_symtab',
        help='Dump the normal ELF symbol table',
        default=False)
    parser.add_option(
        '-d', '--dynsym',
        action='store_true',
        dest='dump_dynsym',
        help='Dump the dynamic ELF symbol table',
        default=False)
    parser.add_option(
        '--symbol-check',
        action='store_true',
        dest='symbol_check',
        help='Dump all symbols with addresses sorted by address.',
        default=False)
    parser.add_option(
        '-p', '--ph', '--program-headers',
        action='store_true',
        dest='dump_program_headers',
        help='Dump the ELF program headers',
        default=False)
    parser.add_option(
        '-S', '--sh', '--section-headers', '--sections',
        action='store_true',
        dest='dump_section_headers',
        help='Dump the ELF section headers',
        default=False)
    parser.add_option(
        '--ss', '--section-summary',
        action='store_true',
        dest='dump_section_summary',
        help='Dump the ELF section summary with sizes and file percentages.',
        default=False)
    parser.add_option(
        '--set-gnu-build-id',
        type='string',
        dest='gnu_build_id',
        metavar="UUID",
        help=('Create a ".note.gnu.build-id" section with the specified UUID '
              'value. Requires objcopy or llvm-objcopy in path or specified '
              'with --objcopy <path> option.'),
        default=None)
    parser.add_option(
        '--objcopy',
        type='string',
        dest='objcopy',
        metavar="PATH",
        help='Specify the basename or full path to the objcopy binary to use with the --set-gnu-build-id option.',
        default=None)
    parser.add_option(
        '-D', '--dynamic',
        action='store_true',
        dest='dump_dynamic',
        help='Dump the ELF Dynamic tags',
        default=False)
    parser.add_option(
        '-H', '--header',
        action='store_true',
        dest='dump_header',
        help='Dump the ELF file header',
        default=False)
    parser.add_option(
        '-n', '--notes',
        action='store_true',
        dest='dump_notes',
        help='Dump any notes in the ELF file program and section headers',
        default=False)
    parser.add_option(
        '--auxv',
        action='store_true',
        dest='dump_auxv',
        help='Dump NT_AUXV notes.',
        default=False)
    parser.add_option(
        '--nt-file',
        action='store_true',
        dest='dump_nt_file',
        help='Dump NT_FILE notes.',
        default=False)
    parser.add_option(
        '--core-info',
        action='store_true',
        dest='core_info',
        default=False,
        help='Dump core file information.')
    parser.add_option(
        '-N', '--num-per-line',
        dest='num_per_line',
        metavar='COUNT',
        type='int',
        help='The number of bytes per line when dumping section contents',
        default=32)
    parser.add_option(
        '--undefined',
        action='store_true',
        help=('Display the external API (functions and data) that this ELF '
              'file links against.'),
        default=False)
    parser.add_option(
        '--section',
        type='string',
        metavar='NAME',
        dest='section_names',
        action='append',
        help='Specify one or more section names to dump')
    parser.add_option(
        '--offset',
        type='int',
        metavar='OFFSET',
        dest='section_offset',
        default=None,
        help='Specify an offset within the section data to start dumping when using --section NAME')
    parser.add_option(
        '--size',
        type='int',
        metavar='SIZE',
        dest='section_size',
        default=None,
        help='Specify the number of bytes to dump when using --section NAME')
    parser.add_option(
        '--gnu-debugdata',
        action='store_true',
        dest='gnu_debugdata',
        default=False,
        help=('Extract a the .gnu_debugdata and decompress it into the '
              'specfiied file path.'))
    parser.add_option(
        '--gnu-hash',
        action='store_true',
        dest='gnu_hash',
        default=False,
        help=('Dump the .gnu.hash section contents'))
    parser.add_option(
        '--section-type',
        type='int',
        metavar='SH_TYPE',
        dest='section_types',
        action='append',
        help='Specify one or more section types to dump')
    parser.add_option(
        '--program-header-type',
        type='int',
        metavar='PT_TYPE',
        dest='program_header_types',
        action='append',
        help='Specify one or more program header types to dump')
    parser.add_option(
        '--api',
        action='store_true',
        dest='api',
        help='Dump the API details as JSON',
        default=False)
    parser.add_option(
        '--links-against',
        type='string',
        metavar='LIBNAME',
        action='append',
        dest='links_against',
        help='Print any ELF file that links against the specified library',
        default=list())
    parser.add_option(
        '--hash',
        type='string',
        action='append',
        metavar='STRING',
        dest='hash_lookups',
        help='Lookup names in the ELF hash tables',
        default=list())
    parser.add_option(
        '--func-ranges',
        action='store_true',
        dest='func_ranges',
        help=('Use all data in ELF file to identify function address ranges. '
              'Ranges will be extracted .eh_frame, .debug_frame, dynamic '
              'table (DT_FINI_ARRAY and DT_INIT_ARRAY), symbol table, dynamic '
              'symbol table, and PLT entries.'),
        default=False)
    parser.add_option(
        '--yaml',
        type='string',
        dest='yaml',
        default=None,
        help='Convert the input ELF file to a YAML representation in the specified file.')

    parser.add_option(
        '--compare',
        action='store_true',
        dest='compare_files',
        help=('Compare two elf files that are specified as arguments.'),
        default=False)

    dwarf.options.append_dwarf_options(parser)

    (options, files) = parser.parse_args()
    if options.compare_files:
        if len(files) != 2:
            print("error: two path arguments must be specified when using "
                  "--compare option")
            return
        compare_elf_files(files[0], files[1])
        return
    if not user_specified_options(options):
        options.dump_header = True
        options.dump_program_headers = True
        options.dump_section_headers = True
    for path in files:
        handle_elf(options, path)


if __name__ == '__main__':
    main()
