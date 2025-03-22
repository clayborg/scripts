#!/usr/bin/python


import elf
# import mach_o
import os
import file_extract

def get_object_file(path):
    if not os.path.exists(path):
        return None
    f = open(path, 'rb')
    data = file_extract.FileExtract(f, '=')
    if elf.Header.is_elf_file(data):
        return elf.File(path, data)
