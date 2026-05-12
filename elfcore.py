#!/usr/bin/env python3

import json
import optparse
import elf

def create_option_parser() -> optparse.OptionParser:
    parser = optparse.OptionParser(
        description='A script that reduces the size of ELF core file files.')
    parser.add_option(
        '-o', '--outfile',
        type='string',
        metavar='PATH',
        dest='outfile',
        default=None,
        help='The path to the file to save.')

    parser.add_option(
        '--elf-headers',
        action='store_true',
        dest='elf_headers',
        default=False,
        help='Save all memory regions that contain ELF headers.')

    parser.add_option(
        '-m', '--minimize',
        action='store_true',
        dest='minimize',
        default=False,
        help='Minimize the core file by removing zero PT_LOAD segments and not'
             ' emitting PT_LOAD entries with no file size.')

    parser.add_option(
        '--yaml',
        action='store_true',
        dest='emit_yaml',
        default=False,
        help='Save as yaml instead of a real core file.')

    parser.add_option(
        '-a', '--address',
        type='int',
        metavar='ADDR',
        dest='addresses',
        action='append',
        default=[],
        help='Specify an address whose memory contents will be preserved. '
             'This can be specified multple times')

    parser.add_option(
        '-j', '--elf-json',
        type='str',
        metavar='PATH',
        dest='elf_json',
        default=[],
        help='Specify a JSON file with contents to be added to the output ELF core file.')
    return parser

def main():
    parser = create_option_parser()

    (options, files) = parser.parse_args()
    if len(files) != 1:
        print("error: a single path to a core file must be given")
        return

    core_elf = elf.File(path=files[0])
    if core_elf.error:
        print(core_elf.error)
        return

    min_core_elf = elf.File(header=core_elf.header)
    program_headers = []

    if options.outfile is None:
        print("error: an output file must be specified with --outfile PATH")
        return

    if options.elf_headers:
        nt_files = core_elf.get_nt_files()
        if nt_files:
            path = None
            for nt_file in nt_files:
                ph = core_elf.get_program_headers_by_vaddr_in_file(nt_file.start)
                if ph is not None:
                    if elf.Header.is_elf_file(ph.get_contents_as_extractor()):
                        nt_file.dump()
                        options.addresses.append(ph.p_vaddr)

    if options.minimize:
        elf.ProgramHeader.dump_header()
    for ph in core_elf.get_program_headers():
        if ph.p_type == elf.PT.NOTE:
            # min_core_elf.add_program_header(ph)
            pass
        elif ph.p_type == elf.PT.LOAD:
            if options.addresses:
                for addr in options.addresses:
                    if ph.contains_vaddr_in_file(addr):
                        min_core_elf.add_program_header(ph)
                        break
            if options.minimize:
                # Many core files have a lot of program headers with zero file
                # size and these are not useful as they have no data.
                if ph.p_filesz == 0 and ph.p_memsz == 0:
                    ph.dump(flat=True, suffix=' skipping program header with p_filesz == 0 && p_memsz == 0\n')
                    continue  # Skip
                if ph.is_all_zeros() and ph.p_filesz > 0:
                    ph.dump(flat=True, suffix=' data is all zeros, changing program header to zero fill\n')
                    ph.p_filesz = 0  # Set the p_filesz to zero so the data doesn't get copied
                    ph.data = None  # If the data had been accessed before, clear it so it doesn't get copied into the new file
                    min_core_elf.add_program_header(ph)
                    continue
                else:
                    min_core_elf.add_program_header(ph)
    if options.elf_json:
        with open(options.elf_json, 'r') as f:
            elf_json = json.load(f)
            program_headers_json = elf_json.get('program_headers', [])
            for ph_dict in program_headers_json:
                ph = elf.ProgramHeader.from_dict(min_core_elf, ph_dict)
                if ph is not None:
                    ph.elf = min_core_elf
                    min_core_elf.add_program_header(ph)
    if options.emit_yaml:
        with open(options.outfile, 'w') as f:
                    min_core_elf.encode_yaml(f)
    else:
        min_core_elf.save(options.outfile)




if __name__ == "__main__":
    main()
