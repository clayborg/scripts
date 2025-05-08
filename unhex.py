#!/usr/bin/env python3

import binascii
import json
import optparse
import pprint
import subprocess
import sys

def main():
    parser = optparse.OptionParser(
        description='',
        prog='unhex.py',
        usage='unhex.py [options]',
        add_help_option=True)

    parser.add_option(
        '-j', '--json',
        action='store_true',
        dest='json',
        default=False,
        help='Parse decoded string as JSON and pretty print.')

    (options, args) = parser.parse_args(sys.argv[1:])

    if len(args) == 0:
        options.arg = True
        args.append(str(subprocess.check_output('pbpaste').decode('utf8')))

    for s in args:
        unhex_s = binascii.unhexlify(s)
        if options.json:
            j = json.loads(unhex_s)
            print(pprint.PrettyPrinter(indent=4).pprint(j))
        else:
            print(unhex_s.decode('utf-8'))

if __name__ == '__main__':
  main()
