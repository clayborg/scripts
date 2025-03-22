#!/usr/bin/python

from collections import defaultdict
import copy
import file_extract
import io
import sys

from dwarf.defines import UINT32_MAX, UINT64_MAX
from dwarf.DW.CFA import *
from dwarf.debug.loc import Location
import dwarf.options


class debug_frame(object):
    '''Represents the .debug_frame or .eh_frame section object files.'''
    def __init__(self, objfile, data, is_eh_frame):
        self.objfile = objfile
        self.data = data
        self.entries = []  # Both CIE and FDE entries
        self.cie_map = {}
        self.is_eh_frame = is_eh_frame
        self.regs = None
        while True:
            e = self.decode_cie_or_fde()
            if e is None:
                break
            self.entries.append(e)
            if e.is_cie():
                self.cie_map[e.offset] = e

    def get_function_info(self, func_info):
        '''Get all function ranges that we know about from the FDEs.'''
        if self.is_eh_frame:
            source = '.eh_frame'
        else:
            source = '.debug_frame'
        for e in self.entries:
            if e.is_cie():
                continue
            func_info.add(e.addr, size=e.size, source=source)

    def get_fde_for_addr(self, addr):
        '''The the FDE entry for a given file address.'''
        for e in self.entries:
            if e.is_cie():
                continue
            if e.addr <= addr and addr < e.addr + e.size:
                return e
        return None

    def get_fdes(self):
        '''The all of the FDE entries.'''
        result = []
        for e in self.entries:
            if not e.is_cie():
                result.append(e)
        return result

    def is_eh_frame(self):
        return self.is_eh_frame

    def decode_cie_or_fde(self):
        INVALID_CIE = -2
        data = self.data
        offset = data.tell()
        length = data.get_uint32()
        if length == UINT32_MAX:
            length = data.get_uint64(0)
            cie_id_or_ptr = data.get_uint64(INVALID_CIE)
            length_size = 12
        else:
            cie_id_or_ptr = data.get_uint32(INVALID_CIE)
            length_size = 4
        if length == 0:
            return None
        end_offset = offset + length_size + length
        if cie_id_or_ptr == INVALID_CIE:
            return None

        is_cie = False
        if self.is_eh_frame:
            is_cie = cie_id_or_ptr == 0
        elif data.get_addr_size() == 4:
            is_cie = cie_id_or_ptr == UINT32_MAX
        else:
            is_cie = cie_id_or_ptr == UINT64_MAX

        if is_cie:
            result = CIE(self, offset, length, end_offset, data)
        else:
            cie_id = cie_id_or_ptr
            if self.is_eh_frame:
                # cie_id value for EH frame is an offset to backup to
                # that identifies the CIE instead of just an absolute
                # offset value, so fix it up here
                cie_id = (offset - cie_id) + length_size
            result = FDE(self, offset, length, end_offset, cie_id, data)
        data.seek(end_offset)
        return result

    def get_cie(self, cie_id):
        if cie_id in self.cie_map:
            return self.cie_map[cie_id]
        return None

    def dump(self, verbose=False, f=sys.stdout):
        for entry in self.entries:
            entry.dump(verbose=verbose, f=f)

    @staticmethod
    def get_registers(is_eh_frame, objfile=None):
        if objfile is None:
            return RegisterNames(None, None, is_eh_frame)
        return RegisterNames(objfile.get_arch(), objfile.get_file_type(),
                             is_eh_frame)

    def get_regs(self):
        if self.regs is None:
            self.regs = debug_frame.get_registers(self.is_eh_frame,
                                                  self.objfile)
        return self.regs

    def dump_unwind_stats(self, f=sys.stdout):
        cfa_rule_dict = defaultdict(int)
        reg_rules_dict = defaultdict(int)
        rule_type_counts = defaultdict(int)
        regs = self.get_regs()
        for entry in self.entries:
            if not entry.is_cie():
                for row in entry.get_rows():
                    row.get_unwind_stats(regs, cfa_rule_dict, reg_rules_dict,
                                         rule_type_counts)
        f.write('Unwind Statistics:\n')
        dump_count_dict(reg_rules_dict, f,
                        ('  Register rule counts for rows with the all the '
                         'same register rules'))
        dump_count_dict(cfa_rule_dict, f,
                        ('  CFA rule counts for rows with the the same CFA '
                         'rule'))
        dump_count_dict(rule_type_counts, f, '  Register rule class counts')

    def parse_rows(self, e):
        ip = InstructionParser(self.objfile.get_arch(), log=None)
        ip.parse_entry(e)
        return ip.rows


class eh_frame_hdr(object):
    '''Represents the .eh_frame_hdr section.'''
    class Entry(object):
        def __init__(self, addr, fde_offset):
            self.addr = addr
            self.fde_offset = fde_offset

    def __init__(self, data):
        '''
        The "data" FileExtract argument must have the pcrel and datarel
        GNU base addresses correctly set to the section base address
        for the ".eh_frame_hdr" section or an exception will be raised
        with an appropriate error message during decoding.

        Details about the exact format were found at:

            https://www.airs.com/blog/archives/462

        Both gold and the GNU linker support an option --eh-frame-hdr which
        tell them to construct a header for all the .eh_frame sections.
        This header is placed in a section named .eh_frame_hdr and also in
        a PT_GNU_EH_FRAME segment. At runtime the unwinder can find all the
        PT_GNU_EH_FRAME segments by calling dl_iterate_phdr.

        The format of the .eh_frame_hdr section is as follows:
        1. A 1 byte version number, currently 1.
        2. A 1 byte encoding of the pointer to the exception frames. This
            is a DW_EH_PE_xxx value. It is normally DW_EH_PE_pcrel |
            DW_EH_PE_sdata4, meaning a 4 byte relative offset.
        3. A 1 byte encoding of the count of the number of FDEs in the
            lookup table. This is a DW_EH_PE_xxx value. It is normally
            DW_EH_PE_udata4, meaning a 4 byte unsigned count.
        4. A 1 byte encoding of the entries in the lookup table. This is a
            DW_EH_PE_xxx value. It is normally DW_EH_PE_datarel |
            DW_EH_PE_sdata4, meaning a 4 byte offset from the start of the
            .eh_frame_hdr section. That is the only encoding that gcc's
            current unwind library supports.
        5. A pointer to the contents of the .eh_frame section, encoded as
            indicated by the second byte in the header. This pointer is only
            used if the format of the lookup table is not supported or is
            for some reason omitted..
        6. The number of FDE pointers in the table, encoded as indicated by
            the third byte in the header. If there are no FDEs, the encoding
            can be DW_EH_PE_omit and this number will not be present.
        7. The lookup table itself, starting at a 4-byte aligned address in
            memory. Assuming the fourth byte in the header is
            DW_EH_PE_datarel | DW_EH_PE_sdata4, each entry in the table is 8
            bytes long. The first four bytes are an offset to the initial PC
            value for the FDE. The last four byte are an offset to the FDE
            data itself. The table is sorted by starting PC.

        Since FDEs do not overlap, this table is sufficient for the stack
        unwinder to quickly find the relevant FDE if there is one.
        '''
        self.version = data.get_uint8()
        self.eh_frame_ptr_enc = data.get_uint8()
        self.fde_count_enc = data.get_uint8()
        self.table_enc = data.get_uint8()
        self.eh_frame_ptr = data.get_gnu_pointer(self.eh_frame_ptr_enc)
        self.fde_count = data.get_gnu_pointer(self.fde_count_enc)
        self.lookup_table = []
        for i in range(self.fde_count):
            addr = data.get_gnu_pointer(self.table_enc)
            fde_offset = data.get_gnu_pointer(self.table_enc)
            self.lookup_table.append(HEader.Entry(addr, fde_offset))

    def dump(self, f=sys.stdout):
        f.write('.eh_frame_hdr\n')
        f.write('version          = %#2.2x\n' % (self.version))
        f.write('eh_frame_ptr_enc = %#2.2x\n' % (self.eh_frame_ptr_enc))
        f.write('fde_count_enc    = %#2.2x\n' % (self.fde_count_enc))
        f.write('table_enc        = %#2.2x\n' % (self.table_enc))
        f.write('eh_frame_ptr     = %#x\n' % (self.eh_frame_ptr))
        f.write('fde_count        = %u\n' % (self.fde_count))
        for (i, entry) in enumerate(self.lookup_table):
            f.write("[%5u] %#16.16x @ %#8.8x (.eh_frame + %#8.8x)\n" % (
                    i, entry.addr, entry.fde_offset,
                    entry.fde_offset - self.eh_frame_ptr))
        f.write('\n')


class RegisterNames(object):
    """A class that turns register numbers into register names."""
    def __init__(self, arch, file_type, is_eh_frame):
        self.regs = {}
        if arch is None:
            return
        if arch == "arm64" or arch == "aarch64":
            for i in range(29):
                self.regs[i] = 'x%u' % (i)
            self.regs[29] = 'fp'
            self.regs[30] = 'lr'
            self.regs[31] = 'sp'
            self.regs[32] = 'pc'
            self.regs[33] = 'elr_mode'
            for i in range(32):
                self.regs[i+64] = 'v%u' % (i)
        elif arch.startswith("arm"):
            for i in range(13):
                self.regs[i] = 'r%u' % (i)
            self.regs[13] = 'sp'
            self.regs[14] = 'lr'
            self.regs[15] = 'pc'
            self.regs[16] = 'cpsr'
            for i in range(32):
                self.regs[i+64] = 's%u' % (i)
            for i in range(32):
                self.regs[i+256] = 'd%u' % (i)
            for i in range(16):
                self.regs[i+288] = 'q%u' % (i)
        elif (arch == 'x86' or arch == 'i386' or arch == 'i486' or
              arch == 'i686'):
            is_darwin = file_type and file_type == 'mach-o'
            self.regs[0] = 'eax'
            self.regs[1] = 'ecx'
            self.regs[2] = 'edx'
            self.regs[3] = 'ebx'
            if is_darwin and is_eh_frame:
                self.regs[4] = 'ebp'
                self.regs[5] = 'esp'
            else:
                self.regs[4] = 'esp'
                self.regs[5] = 'ebp'
            self.regs[6] = 'esi'
            self.regs[7] = 'edi'
            self.regs[8] = 'eip'
            self.regs[9] = 'eflags'
            for i in range(8):
                self.regs[i+12] = 'st%u' % (i)
            for i in range(8):
                self.regs[i+21] = 'xmm%u' % (i)
            for i in range(8):
                self.regs[i+29] = 'mm%u' % (i)
        elif arch.startswith("x86_64"):
            self.regs[0] = 'rax'
            self.regs[1] = 'rdx'
            self.regs[2] = 'rcx'
            self.regs[3] = 'rbx'
            self.regs[4] = 'rsi'
            self.regs[5] = 'rdi'
            self.regs[6] = 'rbp'
            self.regs[7] = 'rsp'
            for i in range(8, 16):
                self.regs[i] = 'r%u' % (i)
            self.regs[16] = 'rip'
            for i in range(16):
                self.regs[17+i] = 'xmm%u' % (i)
            for i in range(8):
                self.regs[33+i] = 'st%u' % (i)
            for i in range(8):
                self.regs[41+i] = 'mm%u' % (i)
            self.regs[49] = 'rflags'
            self.regs[50] = 'es'
            self.regs[51] = 'cs'
            self.regs[52] = 'ss'
            self.regs[53] = 'ds'
            self.regs[54] = 'fs'
            self.regs[55] = 'gs'
            self.regs[64] = 'mxcsr'
            self.regs[65] = 'fctrl'
            self.regs[66] = 'fstat'
            for i in range(16):
                self.regs[67+i] = 'ymm%uh' % (i)
            for i in range(4):
                self.regs[126+i] = 'bnd%u' % (i)

    def get_reg_name(self, reg_num, include_number=False):
        if reg_num in self.regs:
            if include_number:
                return '%i (%s)' % (reg_num, self.regs[reg_num])
            else:
                return self.regs[reg_num]
        return 'reg(%u)' % (reg_num)

    def dump_reg_name(self, reg_num, f=sys.stdout):
        f.write(self.get_reg_name(reg_num))


class RuleIsRegPlusOffset(object):
    """A register rule where the value is a register plus an offset."""
    def __init__(self, reg, offset):
        self.reg = reg
        self.offset = offset

    def dump(self, regs, verbose=False, f=sys.stdout):
        f.write('%s%+i' % (regs.get_reg_name(self.reg), self.offset))

    def encode(self, reg, code_align, data_align, strm):
        strm.put_uint8(DW_CFA_def_cfa)
        strm.put_uleb128(self.reg)
        strm.put_uleb128(self.offset)

    def __eq__(self, other):
        if not isinstance(other, RuleIsRegPlusOffset):
            return NotImplemented
        return self.reg == other.reg and self.offset == other.offset


class RuleDWARFExpr(object):
    """A register rule where the value is the result of a DWARF expression."""
    def __init__(self, expr, deref=True):
        self.deref = deref
        self.location = Location(expr)

    def dump(self, regs, verbose=False, f=sys.stdout):
        f.write('dwarf_expr(')
        if self.deref:
            f.write('[')
        self.location.dump(verbose, f=f, regs=regs)
        if self.deref:
            f.write(']')
        f.write(')')

    def encode(self, reg, code_align, data_align, strm):
        # If "reg" is None, then this is a DW_CFA_def_cfa_expression
        if reg is None:
            strm.put_uint8(DW_CFA_def_cfa_expression)
        else:
            if self.deref:
                strm.put_uint8(DW_CFA_expression)
            else:
                strm.put_uint8(DW_CFA_val_expression)
            strm.put_uleb128(reg)
        expr_data = self.location.data
        expr_size = expr_data.get_size()
        strm.put_uleb128(expr_size)
        expr_data.seek(0)
        for _i in range(expr_size):
            strm.put_uint8(expr_data.get_uint8())

    def __eq__(self, other):
        if not isinstance(other, RuleDWARFExpr):
            return NotImplemented
        self_bytes = self.location.data.get_all_bytes()
        other_bytes = other.location.data.get_all_bytes()
        return self_bytes == other_bytes


class RuleAtCFAPlusOffset(object):
    """A register rule where the value is at the CFA plus an offset."""
    def __init__(self, offset):
        self.offset = offset

    def dump(self, regs, verbose=False, f=sys.stdout):
        f.write('[cfa%+i]' % (self.offset))

    def encode(self, reg, code_align, data_align, strm):
        factored_offset = self.offset // data_align
        if factored_offset > 0:
            if reg <= 0x3f:
                strm.put_uint8(DW_CFA_offset | reg)
                strm.put_uleb128(factored_offset)
            else:
                strm.put_uint8(DW_CFA_offset_extended)
                strm.put_uleb128(reg)
                strm.put_uleb128(factored_offset)
        else:
            strm.put_uint8(DW_CFA_offset_extended_sf)
            strm.put_uleb128(reg)
            strm.put_sleb128(factored_offset)

    def __eq__(self, other):
        if not isinstance(other, RuleAtCFAPlusOffset):
            return NotImplemented
        return self.offset == other.offset


class RuleInRegister(object):
    """A register rule where the value in a register."""
    def __init__(self, in_reg):
        self.in_reg = in_reg

    def dump(self, regs, verbose=False, f=sys.stdout):
        f.write(regs.get_reg_name(self.in_reg))

    def encode(self, reg, code_align, data_align, strm):
        if reg == self.in_reg:
            strm.put_uint8(DW_CFA_same_value)
            strm.put_uleb128(reg)
        else:
            strm.put_uint8(DW_CFA_register)
            strm.put_uleb128(reg)
            strm.put_uleb128(self.in_reg)


class RuleIsUndefined(object):
    def dump(self, regs, verbose=False, f=sys.stdout):
        f.write('<undefined>')

    def encode(self, reg, code_align, data_align, strm):
        if reg is None:
            raise ValueError('"reg" value must be valid')
        strm.put_uint8(DW_CFA_undefined)
        strm.put_uleb128(reg)

    def __eq__(self, other):
        if not isinstance(other, RuleIsUndefined):
            return NotImplemented
        return True


class RuleIsConstant(object):
    def __init__(self, value):
        self.value = value

    def dump(self, regs, verbose=False, f=sys.stdout):
        f.write('%i' % (self.value))

    def encode(self, reg, code_align, data_align, strm):
        if reg is None:
            raise ValueError('"reg" value must be valid')
        strm.put_uint8(DW_CFA_undefined)

    def __eq__(self, other):
        if not isinstance(other, RuleIsConstant):
            return NotImplemented
        return self.value == other.value


class Row(object):
    '''A complete unwind row.

    The Row object has a start address, a call frame address (CFA) rule, and
    multiple register rules, and tracks how many arguments were pushed onto
    the stack. The is a full representation of the .debug_frame or EH frame
    unwind rules.
    '''
    def __init__(self, addr=None):
        self.addr = None
        self.cfa = None
        self.reg_rules = []
        self.args_size = None
        pass

    def dump(self, regs=None, verbose=False, f=sys.stdout, prefix=None):
        if prefix is not None:
            f.write(prefix)
        if self.addr is not None:
            f.write('%#16.16x: ' % (self.addr))
        if self.cfa is not None:
            f.write('cfa=')
            self.cfa.dump(regs, verbose=verbose, f=f)
        if self.args_size is not None:
            f.write(' (args_size=%u)' % (self.args_size))
        if len(self.reg_rules) > 0:
            if self.cfa is not None:
                f.write(': ')
            First = True
            for (reg, rule) in self.reg_rules:
                if First:
                    First = False
                else:
                    f.write(', ')
                f.write('%s=' % (regs.get_reg_name(reg)))
                rule.dump(regs, verbose=verbose, f=f)
        f.write('\n')

    def get_unwind_stats(self, regs, cfa_rule_dict, reg_rules_dict,
                         rule_type_counts):
        # Get all register rules as a string so we can get the count of the
        # number of rows that share the exact same register rules.
        reg_rules_strm = io.StringIO()
        First = True
        for (reg, rule) in self.reg_rules:
            if First:
                First = False
            else:
                reg_rules_strm.write(', ')
            reg_rules_strm.write('%s=' % (regs.get_reg_name(reg)))
            rule_type_counts[type(rule).__name__] += 1
            rule.dump(regs, verbose=False, f=reg_rules_strm)
        reg_rules_dict[reg_rules_strm.getvalue()] += 1

        # Get the CFA rule as a string so we can get the count of the number
        # of rows that share the exact same CFA rule.
        cfa_rule_strm = io.StringIO()
        self.cfa.dump(regs, verbose=False, f=cfa_rule_strm)
        cfa_rule_dict[cfa_rule_strm.getvalue()] += 1
        rule_type_counts[type(self.cfa).__name__] += 1

    def get_rule_for_reg(self, match_reg):
        for (reg, rule) in self.reg_rules:
            if reg == match_reg:
                return rule
        return None

    def set_rule_for_reg(self, reg, rule):
        self.clear_rule_for_reg(reg)
        self.reg_rules.append((reg, rule))

    def clear_rule_for_reg(self, match_reg):
        for (i, (reg, rule)) in enumerate(self.reg_rules):
            if self.reg_rules[i][0] == match_reg:
                del self.reg_rules[i]
                return


class FDE(object):
    '''Frame Descriptor Entry (FDE)'''
    def __init__(self, frame, offset, length, end_offset, cie_id, data):
        self.frame = frame
        self.offset = offset
        self.length = length
        self.cie_id = cie_id
        self.rows = None
        self.lsda = None
        cie = frame.get_cie(cie_id)
        if cie is None:
            raise ValueError('''%#8.8x: FDE can't get CIE at %#8.8x''' % (
                                self.offset, cie_id))
        ptr_enc = cie.fde_eh_ptr_enc
        self.addr = data.get_gnu_pointer(ptr_enc)
        size_ptr_enc = ptr_enc & file_extract.DW_EH_PE_MASK_encoding
        self.size = data.get_gnu_pointer(size_ptr_enc)
        # Save the instructions offset so we can do pc relative GNU pointer
        # fethes for augmentation data.
        self.instr_off = data.tell()

        if end_offset > self.instr_off:
            self.instructions = data.read_data(end_offset - self.instr_off)
        else:
            self.instructions = None

    def dump(self, verbose=False, f=sys.stdout):
        regs = self.frame.get_regs()

        f.write('%s: FDE CIE=%s' % (
                dwarf.options.get_color_offset(self.offset),
                dwarf.options.get_color_offset(self.cie_id)))
        # if self.segment is not None:
        #     seg = 'segment[%i]' % (self.segment)
        # else:
        #     seg = ''
        seg = ''
        # Get the rows first so we parse any data from the CIE augmentation
        # into this object before dumping it (like self.lsda below).
        rows = self.get_rows()
        f.write(', range=%s[%#16.16x-%#16.16x)' % (seg, self.addr,
                                                   self.addr+self.size))
        if self.lsda is not None:
            f.write(', lsda=%#x' % (self.lsda))
        f.write('\n')
        if self.instructions and verbose:
            self.instructions.dump(num_per_line=16, f=f)
        for (i, row) in enumerate(rows):
            row.dump(regs, verbose=verbose, f=f, prefix='            ')

    def get_cie(self):
        return self.frame.get_cie(self.cie_id)

    def is_cie(self):
        return False

    def get_rows(self):
        if self.rows is None:
            self.rows = self.frame.parse_rows(self)
        return self.rows


class CIE(object):
    '''Common Information Entry (CIE)'''

    def __init__(self, frame, offset, length, end_offset, data):
        self.frame = frame
        self.offset = offset
        self.length = length

        self.version = data.get_uint8()
        self.augmentation = data.get_c_string()
        is_eh_frame = frame.is_eh_frame
        if not is_eh_frame and self.version >= 4:
            self.address_size = data.get_uint8()
            self.segment_size = data.get_uint8()
        else:
            self.address_size = data.get_addr_size()
            self.segment_size = 0
        self.code_align = data.get_uleb128()
        self.data_align = data.get_sleb128()
        if not is_eh_frame and self.version >= 3:
            self.return_addr_reg = data.get_uleb128()
        else:
            self.return_addr_reg = data.get_uint8()
        self.initial_instructions_offset = data.tell()
        # Augmentation optional values
        self.lsda_eh_ptr_enc = None
        self.personality = None
        self.fde_eh_ptr_enc = file_extract.DW_EH_PE_absptr
        if self.augmentation and self.augmentation[0]:
            aug_len = data.get_uleb128()
            if self.augmentation[0] == 'z':
                for ch in self.augmentation[1:]:
                    if ch == 'L':
                        # Indicates the presence of one argument in the
                        # Augmentation Data of the CIE, and a corresponding
                        # argument in the Augmentation Data of the FDE. The
                        # argument in the Augmentation Data of the CIE is
                        # 1-byte and represents the pointer encoding used for
                        # the argument in the Augmentation Data of the FDE,
                        # which is the address of a language-specific data area
                        # (LSDA). The size of the LSDA pointer is specified by
                        # the pointer encoding used.
                        self.lsda_eh_ptr_enc = data.get_uint8()
                    elif ch == 'P':
                        # Indicates the presence of two arguments in the
                        # Augmentation Data of the CIE. The first argument is
                        # 1-byte and represents the pointer encoding used for
                        # the second argument, which is the address of a
                        # personality routine handler. The size of the
                        # personality routine pointer is specified by the
                        # pointer encoding used.
                        #
                        # The address of the personality function will be
                        # stored at this location.  Pre-execution, it will be
                        # all zero's so don't read it until we're trying to do
                        # an unwind & the reloc has been resolved.
                        eh_ptr_enc = data.get_uint8()
                        self.personality = data.get_gnu_pointer(eh_ptr_enc)
                    elif ch == 'R':
                        # A 'R' may be present at any position after the first
                        # character of the string. The Augmentation Data shall
                        # include a 1 byte argument that represents the pointer
                        # encoding for the address pointers used in the FDE.
                        self.fde_eh_ptr_enc = data.get_uint8()
                    elif ch == 'S':
                        # The character 'S' in the augmentation string means
                        # that this CIE represents a stack frame for the
                        # invocation of a signal handler. When unwinding the
                        # stack, signal stack frames are handled slightly
                        # differently: the instruction pointer is assumed to be
                        # before the next instruction to execute rather than
                        # after it.
                        pass
                    elif ch == 'B':
                        # ARM64 saying addresses are signed with bkey.
                        pass
                    else:
                        error = "unhandled 'z' augmentation '%c'" % (ch)
                        raise ValueError(error)
            else:
                data.read_size(aug_len)
        offset = data.tell()
        if end_offset > offset:
            self.instructions = data.read_data(end_offset - offset)
        else:
            self.instructions = None
        self.initial_instructions = None

    def get_initial_instructions(self):
        if self.initial_instructions is None:
            self.initial_instructions = self.frame.parse_rows(self)[0]
        return self.initial_instructions

    def dump(self, verbose=False, f=sys.stdout):
        regs = self.frame.get_regs()

        f.write('%s: CIE version=%u, augmentation="%s"' % (
                dwarf.options.get_color_offset(self.offset), self.version,
                self.augmentation))
        if not self.frame.is_eh_frame and self.version >= 4:
            f.write(', addr_size=%u, segment_size=%u' % (
                    self.address_size, self.segment_size))
        if self.lsda_eh_ptr_enc is not None:
            pstr = file_extract.DW_EH_PE_to_str(self.lsda_eh_ptr_enc)
            f.write(', lsda_eh_ptr_enc==%#2.2x (%s)' % (
                    self.lsda_eh_ptr_enc, pstr))

        if self.personality is not None:
            f.write(', personality=%#16.16x' % (self.personality))
        if self.fde_eh_ptr_enc is not None:
            pstr = file_extract.DW_EH_PE_to_str(self.fde_eh_ptr_enc)
            f.write(', fde_eh_ptr_encoding=%#2.2x (%s)' % (
                    self.fde_eh_ptr_enc, pstr))
        f.write(', code_align=%i, data_align=%i, ra_reg=%s\n' %
                (self.code_align, self.data_align,
                    regs.get_reg_name(self.return_addr_reg)))
        if verbose:
            self.instructions.dump(num_per_line=16, f=f)
        self.get_initial_instructions().dump(regs, verbose=verbose, f=f,
                                             prefix='            ')

    def is_cie(self):
        return True


def dump_count_dict(d, f, prefix):
    f.write('%s:\n' % (prefix))
    count_dict = {}
    for key in d:
        count = d[key]
        if count in count_dict:
            count_dict[count].append(key)
        else:
            count_dict[count] = [key]
    for count in sorted(count_dict.keys(), reverse=True):
        for value in sorted(count_dict[count]):
            f.write('    %5u: %s\n' % (count, value))


class InstructionParser():
    def __init__(self, arch, log=None):
        self.arch = arch
        self.code_align = None
        self.data_align = None
        self.row = None  # The current row that is being populated.
        self.rows = []  # Completed rows get pushed onto this stack.
        self.states = []  # For DW_CFA_remember_state and DW_CFA_restore_state.
        self.log = log  # If valid, log all opcodes to this file.

    def dump(self, f=sys.stdout, regs=None):
        for row in self.rows:
            row.dump(f=f, regs=regs)

    def push_row(self):
        self.rows.append(copy.deepcopy(self.row))

    def parse_entry(self, cie_or_fde):
        data = cie_or_fde.instructions
        if cie_or_fde.is_cie():
            return self.__parse_cie(cie_or_fde, data)
        else:
            return self.__parse_fde(cie_or_fde, data)

    def parse_instructions(self, data, addr, code_align, data_align):
        self.code_align = code_align
        self.data_align = data_align
        self.row = Row()
        if addr is not None:
            self.row.addr = addr
        self.__parse_insructions(data)

    def __set_cie(self, cie):
        self.code_align = cie.code_align
        self.data_align = cie.data_align

    def __parse_cie(self, cie, data):
        self.__set_cie(cie)
        self.row = Row()
        self.__parse_insructions(data)

    def __parse_fde(self, fde, data):
        cie = fde.get_cie()
        if cie is None:
            raise ValueError("%#8.8x: FDE can't get CIE with ID %#8.8x" % (
                             fde.offset, fde.cie_id))
        self.__set_cie(cie)
        self.row = copy.deepcopy(cie.get_initial_instructions())
        self.row.addr = fde.addr
        if data is None:
            self.push_row()
            return
        if (cie.augmentation and cie.augmentation[0] == 'z'):
            aug_len = data.get_uleb128()
            aug_start = data.tell()
            if cie.lsda_eh_ptr_enc:
                fde.lsda = data.get_gnu_pointer(cie.lsda_eh_ptr_enc)
            aug_end = data.tell()
            if aug_start + aug_len != aug_end:
                data.seek(aug_start + aug_len)
        self.__parse_insructions(data)

    def __parse_insructions(self, data):
        while True:
            op = data.get_uint8(None)
            if op is None:
                break
            primary_op = op & 0xC0
            if primary_op != 0:
                op_arg = op & 0x3F
                if primary_op == DW_CFA.advance_loc:
                    offset = op_arg * self.code_align
                    self.DW_CFA_advance_loc(primary_op, offset)
                elif primary_op == DW_CFA.offset:
                    reg = op_arg
                    offset = data.get_uleb128() * self.data_align
                    self.DW_CFA_offset(primary_op, reg, offset)
                elif primary_op == DW_CFA.restore:
                    reg = op_arg
                    self.DW_CFA_restore(primary_op, reg)
                else:
                    err = "unhandled primary opcode %s" % (DW_CFA(primary_op))
                    raise ValueError(err)
            else:
                if op == DW_CFA.def_cfa:
                    reg = data.get_uleb128()
                    offset = data.get_uleb128()
                    self.DW_CFA_def_cfa(op, reg, offset)
                elif op == DW_CFA.def_cfa_offset:
                    offset = data.get_uleb128()
                    self.DW_CFA_def_cfa_offset(op, offset)
                elif op == DW_CFA.def_cfa_offset_sf:
                    offset = data.get_sleb128() * self.data_align
                    self.DW_CFA_def_cfa_offset(op, offset)
                elif op == DW_CFA.def_cfa_register:
                    reg = data.get_uleb128()
                    self.DW_CFA_def_cfa_register(op, reg)
                elif op == DW_CFA.advance_loc1:
                    offset = data.get_uint8() * self.code_align
                    self.DW_CFA_advance_loc(op, offset)
                elif op == DW_CFA.advance_loc2:
                    offset = data.get_uint16() * self.code_align
                    self.DW_CFA_advance_loc(op, offset)
                elif op == DW_CFA.advance_loc4:
                    offset = data.get_uint32() * self.code_align
                    self.DW_CFA_advance_loc(op, offset)
                elif op == DW_CFA.set_loc:
                    addr = data.get_address()
                    self.DW_CFA_set_loc(op, addr)
                elif op == DW_CFA.offset_extended:
                    reg = data.get_uleb128()
                    offset = data.get_uleb128() * self.data_align
                    self.DW_CFA_offset(op, reg, offset)
                elif op == DW_CFA.offset_extended_sf:
                    reg = data.get_uleb128()
                    offset = data.get_sleb128() * self.data_align
                    self.DW_CFA_offset(op, reg, offset)
                elif op == DW_CFA.register:
                    reg = data.get_uleb128()
                    in_reg = data.get_uleb128()
                    self.DW_CFA_register(op, reg, in_reg)
                elif op == DW_CFA.def_cfa_expression:
                    expr_len = data.get_uleb128()
                    expr_data = data.read_data(expr_len)
                    self.DW_CFA_def_cfa_expression(op, expr_data)
                elif op == DW_CFA.expression or op == DW_CFA.val_expression:
                    reg = data.get_uleb128()
                    expr_len = data.get_uleb128()
                    expr_data = data.read_data(expr_len)
                    if op == DW_CFA.expression:
                        self.DW_CFA_expression(op, reg, expr_data)
                    else:
                        self.DW_CFA_val_expression(op, reg, expr_data)
                elif op == DW_CFA.remember_state:
                    self.DW_CFA_remember_state(op)
                elif op == DW_CFA.restore_state:
                    self.DW_CFA_restore_state(op)
                elif op == DW_CFA.undefined:
                    reg = data.get_uleb128()
                    self.DW_CFA_restore_state(op, reg)
                elif op == DW_CFA.GNU_args_size:
                    args_size = data.get_uleb128()
                    self.DW_CFA_GNU_args_size(op, args_size)
                elif op == DW_CFA.nop:
                    self.DW_CFA_nop(op)
                elif op == DW_CFA.restore_extended:
                    reg = data.get_uleb128()
                    self.DW_CFA_restore(op, reg)
                elif op == DW_CFA.same_value:
                    reg = data.get_uleb128()
                    self.DW_CFA_same_value(op, reg)
                elif op == DW_CFA.GNU_window_save:
                    self.DW_CFA_GNU_window_save(op)
                else:
                    raise ValueError("unhandled opcode %s" % (str(DW_CFA(op))))
        self.push_row()

    def DW_CFA_set_loc(self, op, addr):
        # DW_CFA_set_loc takes a single argument that represents an address.
        # The required action is to create a new table row using the specified
        # address as the location. All other values in the new row are
        # initially identical to the current row. The new location value should
        # always be greater than the current one.
        self.push_row()
        if self.log:
            self.log.write("%s(addr=%#x)" % (DW_CFA(op), addr))
        self.row.addr = addr

    def DW_CFA_advance_loc(self, op, offset):
        # The DW_CFA_advance instruction takes a single operand (encoded with
        # the opcode) that represents a constant delta. The required action is
        # to create a new table row with a location value that is computed by
        # taking the current entry's location value and adding the value of
        # delta * code_alignment_factor. All other values in the new row are
        # initially identical to the current row.
        #
        # "offset" has the code alignment factor already computed into it.
        #
        # "op" will be one of:
        #   DW_CFA_advance_loc
        #   DW_CFA_advance_loc1
        #   DW_CFA_advance_loc2
        #   DW_CFA_advance_loc4
        self.push_row()
        if self.log:
            self.log.write("%s(offset=%#x) " % (DW_CFA(op), offset))
        self.row.addr += offset

    def DW_CFA_offset(self, op, reg, offset):
        # The DW_CFA_offset instruction takes two operands: a register number
        # (encoded with the opcode) and an unsigned LEB128 constant
        # representing a factored offset. The required action is to change the
        # rule for the register indicated by the register number to be an
        # offset(N) rule where the value of N is factored offset *
        # data_alignment_factor.
        #
        # "offset" has the data alignment factor already computed into it.
        #
        # "op" will be one of:
        #   DW_CFA_offset
        #   DW_CFA_offset_extended
        #   DW_CFA_offset_extended_sf
        if self.log:
            self.log.write("%s(reg=%u, offset=%+i) " % (DW_CFA(op), reg,
                                                        offset))
        self.row.set_rule_for_reg(reg, RuleAtCFAPlusOffset(offset))

    def DW_CFA_restore(self, op, reg):
        # The DW_CFA_restore instruction takes a single operand (encoded with
        # the opcode) that represents a register number. The required action is
        # to change the rule for the indicated register to the rule assigned it
        # by the initial_instructions in the CIE.
        #
        # "op" will be one of:
        #   DW_CFA_restore
        #   DW_CFA_restore_extended
        if self.log:
            self.log.write("%s(reg=%u) " % (DW_CFA(op), reg))
        self.row.clear_rule_for_reg(reg)

    def DW_CFA_def_cfa(self, op, reg, offset):
        # The DW_CFA_def_cfa instruction takes two unsigned LEB128 operands
        # representing a register number and a (non-factored) offset. The
        # required action is to define the current CFA rule to use the provided
        # register and offset.
        #
        # "offset" has any data alignment factor already computed into it.
        if self.log:
            self.log.write("%s(reg=%u, offset=%+i) " % (DW_CFA(op), reg, offset))
        self.row.cfa = RuleIsRegPlusOffset(reg, offset)

    def DW_CFA_def_cfa_offset(self, op, offset):
        # The DW_CFA_def_cfa_offset instruction takes a single unsigned LEB128
        # operand representing a (non-factored) offset. The required action is
        # to define the current CFA rule to use the provided offset (but to
        # keep the old register). This operation is valid only if the current
        # CFA rule is defined to use a register and offset.
        #
        # "offset" has any data alignment factor already computed into it.
        #
        # "op" will be one of:
        #   DW_CFA_def_cfa_offset
        #   DW_CFA_def_cfa_offset_sf
        if self.log:
            self.log.write("%s(offset=%+i) " % (DW_CFA(op), offset))
        self.row.cfa.offset = offset

    def DW_CFA_def_cfa_register(self, op, reg):
        # The DW_CFA_def_cfa_register instruction takes a single unsigned
        # LEB128 operand representing a register number. The required action is
        # to define the current CFA rule to use the provided register (but to
        # keep the old offset). This operation is valid only if the current CFA
        # rule is defined to use a register and offset.
        if self.log:
            self.log.write("%s(reg=%u) " % (DW_CFA(op), reg))
        self.row.cfa.reg = reg

    def DW_CFA_register(self, op, reg, in_reg):
        # The DW_CFA_register instruction takes two unsigned LEB128 operands
        # representing register numbers. The required action is to set the rule
        # for the first register to be register(R) where R is the second
        # register.
        if self.log:
            self.log.write("%s(reg=%u, in_reg=%u) " % (DW_CFA(op), reg, in_reg))
        self.row.set_rule_for_reg(reg, RuleInRegister(in_reg))

    def DW_CFA_def_cfa_expression(self, op, expr_data):
        # The DW_CFA_def_cfa_expression instruction takes a single operand
        # encoded as a DW_FORM_exprloc value representing a DWARF expression.
        # The required action is to establish that expression as the means by
        # which the current CFA is computed.
        rule = RuleDWARFExpr(expr_data, deref=False)
        if self.log:
            self.log.write("%s(" % (DW_CFA(op)))
            rule.dump(None, f=self.log)
            self.log.write(') ')
        self.row.cfa = rule

    def DW_CFA_expression(self, op, reg, expr_data):
        # The DW_CFA_expression instruction takes two operands: an unsigned
        # LEB128 value representing a register number, and a DW_FORM_block
        # value representing a DWARF expression. The required action is to
        # change the rule for the register indicated by the register number to
        # be an expression(E) rule where E is the DWARF expression. That is,
        # the DWARF expression computes the address. The value of the CFA is
        # pushed on the DWARF evaluation stack prior to execution of the DWARF
        # expression.
        rule = RuleDWARFExpr(expr_data, deref=True)
        if self.log:
            self.log.write("%s(%u, " % (DW_CFA(op), reg))
            rule.dump(None, f=self.log)
            self.log.write(') ')
        self.row.set_rule_for_reg(reg, rule)

    def DW_CFA_val_expression(self, op, reg, expr_data):
        # The DW_CFA_val_expression instruction takes two operands: an unsigned
        # LEB128 value representing a register number, and a DW_FORM_block
        # value representing a DWARF expression. The required action is to
        # change the rule for the register indicated by the register number to
        # be a val_expression(E) rule where E is the DWARF expression. That is,
        # the DWARF expression computes the value of the given register. The
        # value of the CFA is pushed on the DWARF evaluation stack prior to
        # execution of the DWARF expression.
        rule = RuleDWARFExpr(expr_data, deref=False)
        if self.log:
            self.log.write("%s(%u, " % (DW_CFA(op), reg))
            rule.dump(None, f=self.log)
            self.log.write(') ')
        self.row.set_rule_for_reg(reg, rule)

    def DW_CFA_remember_state(self, op):
        # The DW_CFA_remember_state instruction takes no operands. The required
        # action is to push the set of rules for every register onto an
        # implicit stack.
        if self.log:
            self.log.write("%s() " % (DW_CFA(op)))
        self.states.append(copy.deepcopy(self.row.reg_rules))

    def DW_CFA_restore_state(self, op):
        # The DW_CFA_restore_state instruction takes no operands. The required
        # action is to pop the set of rules off the implicit stack and place
        # them in the current row.
        if self.log:
            self.log.write("%s() " % (DW_CFA(op)))
        self.row.reg_rules = self.states.pop()

    def DW_CFA_undefined(self, op, reg):
        # The DW_CFA_undefined instruction takes a single unsigned LEB128
        # operand that represents a register number. The required action is to
        # set the rule for the specified register to be undefined.
        if self.log:
            self.log.write("%s(%u) " % (DW_CFA(op), reg))
        self.row.set_rule_for_reg(reg, RuleIsUndefined())


    def DW_CFA_GNU_args_size(self, op, args_size):
        # The DW_CFA_GNU_args_size instruction takes an unsigned LEB128 operand
        # representing an argument size. This instruction specifies the total
        # of the size of the arguments which have been pushed onto the stack.
        if self.log:
            self.log.write("%s(%u) " % (DW_CFA(op), args_size))
        self.row.args_size = args_size

    def DW_CFA_nop(self, op):
        if self.log:
            self.log.write("%s() " % (DW_CFA(op)))

    def DW_CFA_same_value(self, op, reg):
        # The DW_CFA_same_value instruction takes a single unsigned LEB128
        # operand that represents a register number. The required action is to
        # set the rule for the specified register to "same value".
        if self.log:
            self.log.write("%s(%u) " % (DW_CFA(op), reg))
        self.row.set_rule_for_reg(reg, RuleInRegister(reg))

    def DW_CFA_GNU_window_save(self, op):
        if self.log:
            self.log.write("%s() " % (DW_CFA(op)))
        if self.arch == "arm64":
            rule = self.row.get_rule_for_reg(34)
            if rule is None:
                self.row.set_rule_for_reg(34, RuleIsConstant(1))
            else:
                rule.value ^= 1
        else:
            raise ValueError('unhandled DW_CFA_GNU_window_save for %s' % (
                             self.arch))


# class ehframe_lldb_command:
#     program = "ehframe"
#     description = "ehframe help..."

#     @classmethod
#     def register_lldb_command(cls, debugger, module_name):
#         parser = cls.create_options()
#         cls.__doc__ = parser.format_help()
#         # Add any commands contained in this module to LLDB
#         command = "command script add -c %s.%s %s" % (
#             module_name,
#             cls.__name__,
#             cls.program,
#         )
#         debugger.HandleCommand(command)
#         print(
#             'The "{0}" command has been installed, type "help {0}" or "{0} '
#             '--help" for detailed help.'.format(cls.program)
#         )

#     @classmethod
#     def create_options(cls):

#         usage = "usage: %prog [options]"

#         # Pass add_help_option = False, since this keeps the command in line
#         #  with lldb commands, and we wire up "help command" to work by
#         # providing the long & short help methods below.
#         parser = optparse.OptionParser(
#             description=cls.description,
#             prog=cls.program,
#             usage=usage,
#             add_help_option=True,
#         )
#         parser.add_option(
#             "--verbose",
#             action="store_true",
#             dest="verbose",
#             default=False,
#             help="Enable verbose output.",
#         )
#         return parser

#     def get_short_help(self):
#         return self.description

#     def get_long_help(self):
#         return self.help_string

#     def __init__(self, debugger, unused):
#         self.parser = self.create_options()
#         self.help_string = self.parser.format_help()

#     def __call__(self, debugger, command, exe_ctx, result):
#         # Use the Shell Lexer to properly parse up command options just like a
#         # shell would
#         command_args = shlex.split(command)

#         try:
#             (options, args) = self.parser.parse_args(command_args)
#         except:
#             # if you don't handle exceptions, passing an incorrect argument to
#             # the OptionParser will cause LLDB to exit (courtesy of OptParse
#             # dealing with argument errors by throwing SystemExit)
#             result.SetError("option parsing failed")
#             return

#         target = exe_ctx.GetTarget()
#         if target is None or not target.IsValid():
#             result.write("error: invalid target\n")
#             return
#         process = target.GetProcess()
#         if process is None or not process.IsValid():
#             result.write("error: invalid process\n")
#             return

#         addr_size = process.GetAddressByteSize()
#         if process.GetByteOrder() == lldb.eByteOrderLittle:
#             byte_order = 'little'
#         else:
#             byte_order = 'big'

#         error = lldb.SBError()
#         for module in target.modules:
#             result.write("%s:\n" % (module.GetFileSpec().fullpath))
#             sect = module.FindSection(".eh_frame_hdr")
#             if not sect.IsValid():
#                 return
#             section_addr = sect.GetLoadAddress(target)
#             bytes = process.ReadMemory(section_addr, sect.GetByteSize(), error)

#             data = file_extract.FileExtract(io.BytesIO(bytes), byte_order,
#                                             addr_size,
#                                             gnu_pcrel=section_addr,
#                                             gnu_datarel=section_addr)


# def __lldb_init_module(debugger, dict):
#     # Register all classes that have a register_lldb_command method
#     for _name, cls in inspect.getmembers(sys.modules[__name__]):
#         if inspect.isclass(cls) and callable(
#             getattr(cls, "register_lldb_command", None)
#         ):
#             cls.register_lldb_command(debugger, __name__)
