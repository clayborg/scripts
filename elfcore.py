#!/usr/bin/env python3

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
        '-a', '--address',
        type='int',
        metavar='ADDR',
        dest='addresses',
        action='append',
        default=[],
        help='Specify an address whose memory contents will be preserved. '
             'This can be specified multple times')
    return parser

def main():
    parser = create_option_parser()

    (options, files) = parser.parse_args()
    if len(files) != 1:
        print("error: a single path to a core file must be given")
        return

    core_elf = elf.File(path=files[0])
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

    for ph in core_elf.get_program_headers():
        if ph.p_type == elf.PT.NOTE:
            min_core_elf.add_program_header(ph)
        elif ph.p_type == elf.PT.LOAD:
            if options.addresses:
                for addr in options.addresses:
                    if ph.contains_vaddr_in_file(addr):
                        min_core_elf.add_program_header(ph)
                        break

    min_core_elf.save(options.outfile)




if __name__ == "__main__":
    main()
