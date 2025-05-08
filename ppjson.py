#!/usr/bin/env python3

import binascii
import json
import optparse
import sys
import subprocess


def remove_gdb_escapes(s):
    escaped = ''
    s_len = len(s)
    idx = 0
    while idx < s_len:
        paren_idx = s.find('}', idx)
        if paren_idx == -1:
            escaped += s[idx:]
            break
        escaped += s[idx:paren_idx]
        escape_char = '%c' % (ord(s[paren_idx + 1]) ^ 0x20)
        escaped += escape_char
        idx = paren_idx + 2
    return escaped

def dump_json_str(options, json_str):
    json_str = json_str.strip()
    l = len(json_str)
    if options.is_hex:
        json_str = binascii.unhexlify(json_str)
    if options.gdbremote:
        json_str = remove_gdb_escapes(json_str)
    json_dict = json.loads(json_str)
    json.dump(json_dict, options.outfile, indent=options.indent, sort_keys=True)
    print()

def main():
    parser = optparse.OptionParser(
        description='Pretty print a input JSON file',
        prog='ppjson',
        usage='ppjson [options] file1 [file2...]',
        add_help_option=True)
    parser.add_option(
        '--arg',
        action='store_true',
        dest='arg',
        default=False,
        help='Read JSON from command arguments where each argument is a string')
    parser.add_option(
        '--split-lines',
        action='store_true',
        dest='split_lines',
        default=False,
        help='Read the input line by line and decode each line as a JSON object.')
    parser.add_option(
        '--outfile',
        type='string',
        dest='outfile',
        default=None,
        help='Specify file to save ppretty printed data to. '
             'Default is to overwrite the input file.')
    parser.add_option(
        '--indent',
        type='int',
        dest='indent',
        default=2,
        help='Specify the indentation level to use in output. Default is 2.')
    parser.add_option(
        '-g', '--gdb-remote',
        action='store_true',
        dest='gdbremote',
        default=False,
        help='Remove GDB remote escape sequences')
    parser.add_option(
        '--hex',
        action='store_true',
        dest='is_hex',
        default=False,
        help='Specifies the JSON is hex ascii, and should be first decoded.')

    (options, args) = parser.parse_args(sys.argv[1:])

    if options.outfile is None:
        options.outfile = sys.stdout

    if len(args) == 0:
        options.arg = True
        args.append(str(subprocess.check_output('pbpaste').decode('utf8')))

    for arg in args:
        if options.arg:
            dump_json_str(options, arg)
            continue

        with open(arg, 'r') as in_json_file:
            if options.split_lines:
                for line in in_json_file.read().splitlines():
                    dump_json_str(options, line)
            else:
                    dump_json_str(options, in_json_file.read())

if __name__ == '__main__':
    main()
