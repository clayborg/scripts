#!/usr/bin/python

# Python imports
import copy

# Package imports
import dwarf.debug.info
from dwarf.DW.TAG import *
from dwarf.DW.AT import DW_AT
from dwarf.DW.FORM import *
import dwarf.generator


class Optimizer():
    def __init__(self, dwarf_ctx):
        debug_info = dwarf_ctx.get_debug_info()
        self.dwarf_ctx = dwarf_ctx
        self.cus = debug_info.get_dwarf_units()
        self.new_cus = []
        self.curr_cu_path = None
        data = dwarf_ctx.debug_info_data
        dwarf_info = dwarf.parse.Info(addr_size=data.get_addr_size(),
                                      version=4, dwarf_size=4,
                                      byte_order=data.get_byte_order())
        self.dwarfgen = dwarf.generator.DWARF(dwarf_info)

    def optimize(self):
        for cu in self.cus:
            die = cu.get_die()
            if die is None:
                continue
            self.handle_die(die)

    def handle_die(self, die):
        tag = die.get_tag()
        if tag == DW_TAG_compile_unit:
            self.curr_cu_path = die.cu.get_path()
            gen_cu = self.dwarfgen.addCompileUnit(tag)
            gen_cu.dwarf_info = copy.copy(die.cu.dwarf_info)
            self.copy_die_attrs(die, gen_cu.die)

        for child_die in die.get_children():
            self.handle_die(child_die)

    def copy_die_attrs(self, orig_die, gen_die):
        orig_die.userdata = gen_die
        for av in orig_die.get_attrs():
            gen_die.addAttribute(av.attr_spec.attr, av.attr_spec.form,
                                 av.value)

    def save(self, path):
        self.dwarfgen.save(path)
