#!/usr/bin/python

# ---------------------------------------------------------------------
# Be sure to add the python path that points to the LLDB shared library.
#
# # To use this in the embedded python interpreter using "lldb" just
# import it with the full path using the "command script import"
# command
#   (lldb) command script import /path/to/step.py
# ---------------------------------------------------------------------

import inspect
import lldb
import optparse
import os
import shlex
import io
import sys
import zipfile


def run_lldb_command(debugger, command):
    '''Returns the command status and the command output as a tuple.'''
    return_obj = lldb.SBCommandReturnObject()
    status = debugger.GetCommandInterpreter().HandleCommand(
        command, return_obj, False)
    output = return_obj.GetOutput()
    error = return_obj.GetError()
    if output:
        if error:
            return (status, output + "\n" + error)
        else:
            return (status, output)
    return (status, error)


def dump_frame_disassembly(frame, options, f):
    function = frame.GetFunction()
    if not function.IsValid():
        f.write('no function for "%s"\n' % (frame.GetFunctionName()))
        return
    target = frame.GetThread().GetProcess().GetTarget()
    dump_disassembly(target, frame, function, options, f)


def dump_disassembly(target, frame, function, options, f):
    func_name = function.GetName()
    insts = function.GetInstructions(target)

    start_idx = 0
    end_idx = insts.GetSize()
    pc_index = -1
    if options.pc:
        pc_addr = frame.GetPCAddress()
        for (i, inst) in enumerate(insts):
            if inst.GetAddress() == pc_addr:
                pc_index = i
                break

        if pc_index == -1:
            f.write("error: couldn't locate the PC in instructions.")
            return
        if pc_index > options.inst_before:
            start_idx = pc_index - options.inst_before
        if pc_index + options.inst_after < end_idx:
            end_idx = pc_index + options.inst_after
    prev_name = ''
    prev_file = ''
    prev_line = 0
    for i in range(start_idx, end_idx):
        inst = insts.GetInstructionAtIndex(i)
        inst_addr = inst.GetAddress()
        line_entry = inst_addr.GetLineEntry()
        file = line_entry.GetFileSpec().fullpath
        line = line_entry.GetLine()
        block = inst_addr.GetBlock()
        inline_depth = 0
        inline_block = block.GetContainingInlinedBlock()
        if inline_block.IsValid():
            name = inline_block.GetInlinedName()
            b = inline_block
            while b.IsValid():
                inline_depth += 1
                inline_parent_block = b.GetParent().GetContainingInlinedBlock()
                if inline_parent_block.IsValid():
                    b = inline_parent_block
                else:
                    break
        else:
            name = func_name
        indent = '  ' * inline_depth
        addr = inst_addr.GetLoadAddress(target)
        if addr == lldb.LLDB_INVALID_ADDRESS:
            addr = inst_addr.GetFileAddress()
        disassembly = '%#x: %s %s' % (addr, inst.GetMnemonic(target),
                                      inst.GetOperands(target))
        comment = inst.GetComment(target)
        if comment:
            if len(disassembly) < 72:
                spaces = ' ' * (72 - len(disassembly))
                disassembly = disassembly + spaces + '# ' + comment

        # Print function name, file and line if anything changed
        if prev_name != name or prev_file != file or prev_line != line:
            if file or line:
                f.write('%s%s @ %s:%i\n' % (indent, name, file, line))
            else:
                f.write('%s%s\n' % (indent, name))
        # Print disassembly
        if pc_index >= 0:
            if pc_index == i:
                f.write('-> ')
            else:
                f.write('   ')
        f.write('%s%s\n' % (indent, disassembly))
        prev_file = file
        prev_line = line
        prev_name = name


class Command:
    program = 'mixed'
    description = ('Simplified output for mixed mode disassembly.')

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

        # Pass add_help_option = False, since this keeps the command in line
        #  with lldb commands, and we wire up "help command" to work by
        # providing the long & short help methods below.
        parser = optparse.OptionParser(
            description=cls.description,
            prog=cls.program,
            usage=usage,
            add_help_option=True)

        parser.add_option(
            '--name',
            type='string',
            action='append',
            dest='names',
            help='Specify one or more function names to disassemble.')

        parser.add_option(
            '--pc',
            action='store_true',
            dest='pc',
            default=False,
            help='Disassembly around the PC.')

        parser.add_option(
            '-B', '--inst-before',
            type='int',
            dest='inst_before',
            default=0,
            help=('The number of context instructions to print before a '
                  'match. Default is 0.'))

        parser.add_option(
            '-A', '--inst-after',
            type='int',
            dest='inst_after',
            default=4,
            help=('The number of context instructions to print after a '
                  'match. Default is 4.'))

        return parser

    def get_short_help(self):
        return self.description

    def get_long_help(self):
        return self.help_string

    def __init__(self, debugger, unused):
        self.parser = self.create_options()
        self.help_string = self.parser.format_help()

    def __call__(self, debugger, command, exe_ctx, result):
        # Use the Shell Lexer to properly parse up command options just like a
        # shell would
        command_args = shlex.split(command)

        try:
            (options, args) = self.parser.parse_args(command_args)
        except:
            # if you don't handle exceptions, passing an incorrect argument to
            # the OptionParser will cause LLDB to exit (courtesy of OptParse
            # dealing with argument errors by throwing SystemExit)
            result.SetError("option parsing failed")
            return

        target = exe_ctx.GetTarget()

        if options.names:
            for name in options.names:
                sym_ctxs = target.FindFunctions(name)
                if sym_ctxs.GetSize() == 0:
                    result.write('error: no functions found named "%s"\n' %
                                 (name))
                    continue
                for sym_ctx in sym_ctxs:
                    function = sym_ctx.GetFunction()
                    if function.IsValid():
                        dump_disassembly(target, function, result)
                        result.write('\n')
                        continue
                    symbol = sym_ctx.GetSymbol()
                    if symbol.IsValid():
                        dump_disassembly(target, symbol, result)
                        result.write('\n')
                        continue
                    result.write('error: no valid function or symbol\n')
        else:
            frame = exe_ctx.GetFrame()
            if not frame.IsValid():
                result.SetError("invalid frame")
                return
            dump_frame_disassembly(frame, options, result)


def __lldb_init_module(debugger, dict):
    # Register all classes that have a register_lldb_command method
    for _name, cls in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(cls) and callable(getattr(cls,
                                                     "register_lldb_command",
                                                     None)):
            cls.register_lldb_command(debugger, __name__)

if __name__ == '__main__':
    command = Command()
