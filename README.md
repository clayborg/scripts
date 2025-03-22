# Python Scripts for developers.

A collection of python scripts aimed at software developers. 

## elf.py

A script that dumps, searches and has utilities for dumping elf files and the 
contained sections.

### Examples
Dump the ELF file header, program headers and section headers in an ELF file:
```
$ elf.py a.out
```
Dump the .debug_info DWARF section with colorization in the terminal:
```
$ elf.py --debug-info --color a.out
```
Dump .dynamic section in an ELF file:
```
$ elf.py --dynamic a.out
```
Dump symbol table and dynamic symbol table:
```
$ elf.py --symtab --dynsym a.out
```

## macho.py

A script that dumps, searches and has utilities for dumping mach-o objecxt 
files and the contained sections.

### Examples
Dump the mach-o file header and load commands:
```
$ macho.py a.out
```
Dump the .debug_info DWARF section with colorization in the terminal:
```
$ macho.py --debug-info --color a.out
```
Dump symbol table:
```
$ macho.py --symtab a.out
```

## dwarf

A package that can parse, dump, and search all sections in an object file that
contains DWARF. This package is used by both `elf.py` and `macho.py` and the 
DWARF options are added to both tools dynamically.

### Examples
Dump the DWARF from the .debug_info or .debug_info.dwo section to the screen:
```
$ elf.py --debug-info a.out
```
Dump a specific debug info entry (DIE) at offset 0x0002eab1 in the .debug_info:
```
$ elf.py --die=0x0002eab1 a.out
```
Dump a specific debug info entry (DIE) at offset 0x0002eab1 in the .debug_info 
and show all of its parent DIEs:
```
$ elf.py --die=0x0002eab1 --parent a.out
```
Dump a specific debug info entry (DIE) at offset 0x0002eab1 in the .debug_info 
and show all of the DIE's child DIEs:
```
$ elf.py --die=0x0002eab1 --children a.out
```
Lookup an address in the DWARF:
```
$ elf.py --address 0xb914 a.out
```
