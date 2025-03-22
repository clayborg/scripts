#!/usr/bin/python

# Python imports
import binascii
import sys
import io

# Package imports
from dwarf.defines import UINT32_MAX, UINT64_MAX
from dwarf.ranges import AddressRange
from dwarf.DW.OP import *

DW_STACK_TYPE_FILE_ADDR = 1
DW_STACK_TYPE_LOAD_ADDR = 2
DW_STACK_TYPE_SCALAR = 3


class LocationList(object):
    '''A single location list entry that comes from .debug_loc section.'''
    def __init__(self, sec_offset, data, base_address):
        data.push_offset_and_seek(sec_offset)
        self.sec_offset = sec_offset
        addr_size = data.get_addr_size()
        self.locations = []
        while True:
            begin = data.get_address(0)
            end = data.get_address(0)
            if begin == 0 and end == 0:
                break
            if begin < end:
                length = data.get_uint16()
                range = AddressRange(begin + base_address, end + base_address)
                self.locations.append(Location(data.read_data(length), range))
            elif addr_size == 4 and begin == UINT32_MAX:
                base_address = end
            elif addr_size == 8 and begin == UINT64_MAX:
                base_address = end
            else:
                break
        data.pop_offset_and_seek()

    def is_location_list(self):
        return True

    def dump(self, verbose, f=sys.stdout, regs=None):
        f.write(".debug_loc[%#8.8x]: " % (self.sec_offset))
        for (i, location) in enumerate(self.locations):
            if i > 0:
                f.write(', ')
            location.dump(verbose, f=f, regs=regs)

    def has_file_address(self):
        for location in self.locations:
            if location.has_file_address():
                return True
        return False

    def __str__(self):
        output = io.StringIO()
        self.dump(True, output)
        return output.getvalue()


class Location(object):
    def __init__(self, data, range=None):
        self.data = data
        self.operands = None
        self.range = range

    def is_location_list(self):
        return False

    def has_file_address(self):
        operands = self.get_operands()
        for operand in operands:
            if operand.op == DW_OP.addr:
                return True
        return False

    def evaluate(self, parent_value=None, address=-1):
        operands = self.get_operands()
        stack = []
        for operand in operands:
            op = operand.op
            if op == DW_OP.addr:
                stack.append(Value(operand.value1,
                                   DW_STACK_TYPE_FILE_ADDR))
            elif op in [DW_OP.constu,
                        DW_OP.const1u,
                        DW_OP.const2u,
                        DW_OP.const4u,
                        DW_OP.const8u,
                        DW_OP.consts,
                        DW_OP.const1s,
                        DW_OP.const2s,
                        DW_OP.const4s,
                        DW_OP.const8s]:
                stack.append(Value(operand.value1,
                                   DW_STACK_TYPE_SCALAR))
            elif op == DW_OP.plus:
                if len(stack) < 2:
                    print('error: stack size is too small for DW_OP.plus in '
                          '%s' % (self))
                    exit(2)
                else:
                    last = stack.pop()
                    stack[-1].value = stack[-1].value + last.value
            elif op == DW_OP.minus:
                if len(stack) < 2:
                    print('error: stack size is too small for DW_OP.plus in '
                          '%s' % (self))
                    exit(2)
                else:
                    last = stack.pop()
                    stack[-1].value = stack[-1].value - last.value
            elif op == DW_OP.plus_uconst:
                if len(stack) == 0:
                    print('error: stack size is too small for DW_OP.plus_uconst in '
                          '%s' % (self))
                    exit(2)
                stack[-1].value += operand.value1
            else:
                raise ValueError('error: unhandled %s' % (operand.op))
        stack_len = len(stack)
        if stack_len == 1:
            return stack[-1]
        if stack_len == 0:
            print('error: nothing left of the stack for location: %s' % (self))
        if stack_len != 1:
            print('error: multiple things left on the stack for location: '
                  '%s' % (self))
        return None

    def get_operands(self):
        if self.operands is None:
            self.operands = []
            if self.data is None:
                return
            data = self.data
            offset = data.tell()
            while True:
                op = DW_OP(data.get_uint8())
                if op == DW_OP.null:
                    break
                if op in [DW_OP.addr, DW_OP.call_ref, DW_OP.GNU_encoded_addr]:
                    # Opcodes with a single address sized argument
                    value = data.get_address()
                    self.operands.append(Operand(op, 1, value))
                elif op == DW_OP.const1s:
                    self.operands.append(Operand(op, 1, data.get_sint8()))
                elif op == DW_OP.const2s:
                    self.operands.append(Operand(op, 1, data.get_sint16()))
                elif op == DW_OP.const4s:
                    self.operands.append(Operand(op, 1, data.get_sint32()))
                elif op == DW_OP.const8s:
                    self.operands.append(Operand(op, 1, data.get_sint64()))
                elif op in [DW_OP.const1u, DW_OP.const1s, DW_OP.pick,
                            DW_OP.deref_size, DW_OP.xderef_size]:
                    # Opcodes with a single 1 byte argument
                    self.operands.append(Operand(op, 1, data.get_uint8()))
                elif op in [DW_OP.const2u, DW_OP.skip, DW_OP.bra,
                            DW_OP.call2]:
                    # Opcodes with a single 2 byte argument
                    self.operands.append(Operand(op, 1, data.get_uint16()))
                elif op in [DW_OP.const4u, DW_OP.call4]:
                    # Opcodes with a single 4 byte argument
                    self.operands.append(Operand(op, 1, data.get_uint32()))
                elif op == DW_OP.const8u:
                    # Opcodes with a single 8 byte argument
                    self.operands.append(Operand(op, 1, data.get_uint64()))
                elif op in [DW_OP.consts,
                            DW_OP.breg0,
                            DW_OP.breg1,
                            DW_OP.breg2,
                            DW_OP.breg3,
                            DW_OP.breg4,
                            DW_OP.breg5,
                            DW_OP.breg6,
                            DW_OP.breg7,
                            DW_OP.breg8,
                            DW_OP.breg9,
                            DW_OP.breg10,
                            DW_OP.breg11,
                            DW_OP.breg12,
                            DW_OP.breg13,
                            DW_OP.breg14,
                            DW_OP.breg15,
                            DW_OP.breg16,
                            DW_OP.breg17,
                            DW_OP.breg18,
                            DW_OP.breg19,
                            DW_OP.breg20,
                            DW_OP.breg21,
                            DW_OP.breg22,
                            DW_OP.breg23,
                            DW_OP.breg24,
                            DW_OP.breg25,
                            DW_OP.breg26,
                            DW_OP.breg27,
                            DW_OP.breg28,
                            DW_OP.breg29,
                            DW_OP.breg30,
                            DW_OP.breg31,
                            DW_OP.fbreg]:
                    # Opcodes with a 1 sleb128 byte argument
                    value = data.get_sleb128()
                    self.operands.append(Operand(op, 1, value))
                elif op in [DW_OP.constu,
                            DW_OP.plus_uconst,
                            DW_OP.regx,
                            DW_OP.piece]:
                    # Opcodes with a 1 uleb128 byte argument
                    value = data.get_uleb128()
                    self.operands.append(Operand(op, 1, value))
                elif op in [DW_OP.bregx, DW_OP.bit_piece]:
                    # Opcodes with a 2 uleb128 byte argument
                    value1 = data.get_uleb128()
                    value2 = data.get_uleb128()
                    self.operands.append(Operand(op, 2, value1, value2))
                elif op == DW_OP.implicit_value:
                    # Opcodes with a a uleb128 length + block data
                    block_len = data.get_uleb128()
                    block = data.read_size(block_len)
                    self.operands.append(Operand(op, 1, block))
                elif op == DW_OP.GNU_implicit_pointer:
                    # The first operand is a 4-byte unsigned value in the
                    # 32-bit DWARF format, or an 8-byte unsigned value in
                    # the 64-bit DWARF format (see Section 7.4). The second
                    # operand is a signed LEB128 number.
                    offset = data.get_offset()
                    signed = data.get_sleb128()
                    self.operands.append(Operand(op, 2, offset, signed))
                elif op == DW_OP.GNU_entry_value:
                    block_len = data.get_uleb128()
                    location = Location(data.read_data(block_len))
                    self.operands.append(Operand(op, 1, location))
                else:
                    self.operands.append(Operand(op))
        return self.operands

    def dump(self, verbose, f=sys.stdout, regs=None):
        if self.range:
            self.range.dump(f=f, addr_size=1)
            f.write(": ")
        operands = self.get_operands()
        if operands:
            for (idx, operand) in enumerate(operands):
                if idx > 0:
                    f.write(', ')
                operand.dump(verbose=verbose, f=f, regs=regs)

    def __str__(self):
        output = io.StringIO()
        self.dump(True, output)
        return output.getvalue()


class Operand(object):
    def __init__(self, op, num_values=0, value1=0, value2=0):
        self.op = op
        self.num_values = num_values
        self.value1 = value1
        self.value2 = value2

    def dump(self, verbose, f=sys.stdout, regs=None):
        op = self.op
        op_str = str(DW_OP(self.op))
        if self.num_values == 0:
            f.write(op_str)
        elif self.num_values == 1:
            if regs:
                if ((DW_OP.breg0 <= op and op <= DW_OP.breg31) or
                        op == DW_OP.bregx):
                    reg = op - DW_OP.breg0
                    f.write('[%s%+i]' % (regs.get_reg_name(reg),
                                         self.value1))
                    return
                if ((DW_OP.reg0 <= op and op <= DW_OP.reg31) or
                        op == DW_OP.regx):
                    f.write('%s' % (regs.get_reg_name(op - DW_OP.reg0)))
                    return
            if self.op in [DW_OP.addr]:
                f.write('%s(0x%16.16x)' % (op_str, self.value1))
            elif isinstance(self.value1, (bytes, bytearray)):
                data_len = len(self.value1)
                f.write('%s(<%#x> %s)' % (
                    op_str, data_len,
                    binascii.hexlify(self.value1, ' ').decode('utf-8')))
            elif isinstance(self.value1, (Location)):
                f.write('%s(' % (op_str))
                self.value1.dump(False, f=f, regs=regs)
                f.write(')')
            else:
                f.write('%s(%u)' % (op_str, self.value1))
        elif self.num_values == 2:
            f.write('%s(%s, %s)' % (op_str, self.value1, self.value2))
        else:
            raise ValueError('error: unhandled argument count')

    def __str__(self):
        output = io.StringIO()
        self.dump(True, output)
        return output.getvalue()


class Value(object):
    def __init__(self, value, type):
        self.value = value
        self.type = type
