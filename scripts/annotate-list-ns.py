#!/usr/bin/env python

from __future__ import print_function
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import re
import sys

# Constants
HELP_DESCRIPTION = '''\
Annotate list-ns output for humans.
The output should be given via stdin like this:

    sudo nvme list-ns -n 1 | annotate-list-ns.py'''
RE_LINE = re.compile(r'^\[\s*(\d+)\]:0x([0-9a-fA-F]+)$')
RELATIVE_PERFORMANCE = {
    0: 'Best', 1: 'Better', 2: 'Good', 3: 'Degraded',
}


# Functions
def parse_input(file):
    data = [0] * 1024
    for line in file:
        m = RE_LINE.match(line)
        if m is None:
            sys.exit('Invalid input: ' + line)
        n = int(m.group(1))
        v = int(m.group(2), base=16)
        data[1023-n] = v
    return ''.join(format(i, '032b') for i in data)


def decode(data, byte_offset, bit_offset, nbits):
    pos = 1024 * 4 * 8 - byte_offset*8 - bit_offset - nbits
    return int(data[pos:(pos+nbits)], base=2)


def annotate(data):
    '''Annotate list-ns output according to NVMe spec 1.2 Figure 92 & 93.'''
    print('# of logical blocks:', decode(data, 0, 0, 8*8))
    print('# of logical blocks after format:', decode(data, 8, 0, 8*8))
    print('# of logical blocks in use:', decode(data, 16, 0, 8*8))
    print('Support for deallocated or unwritten logical block error:',
          decode(data, 24, 2, 1) != 0)
    print('Support for NAWUN/NAWUPF/NACWU:',
          decode(data, 24, 1, 1) != 0)
    print('Support for thin provisioning:',
          decode(data, 24, 0, 1) != 0)
    # the number of LBA formats is 0's based value.
    nlbaf = decode(data, 25, 0, 1*8)+1
    print('# of LBA formats:', nlbaf)
    print('Metadata at the end of LBA:',
          decode(data, 26, 4, 1) != 0)
    print('LBA format ID (LBAF):', decode(data, 26, 0, 4))
    print('Metadata transfer using a separate buffer:',
          decode(data, 27, 1, 1) != 0)
    print('Metadata transfer using extended data LBA:',
          decode(data, 27, 0, 1) != 0)
    print('Support for PI transfer at the tail of metadata:',
          decode(data, 28, 4, 1) != 0)
    print('Support for PI transfer at the head of metadata:',
          decode(data, 28, 3, 1) != 0)
    print('Support for protection information Type 3:',
          decode(data, 28, 2, 1) != 0)
    print('Support for protection information Type 2:',
          decode(data, 28, 1, 1) != 0)
    print('Support for protection information Type 1:',
          decode(data, 28, 0, 1) != 0)
    pi_type = decode(data, 29, 0, 3)
    if pi_type == 0:
        print('Protection information is not enabled.')
    else:
        print('Protection information is enabled: Type', pi_type)
        print('Protection information at the head of metadata:',
              decode(data, 29, 3, 1) != 0)
    print('Shared namespace:',
          'Yes' if decode(data, 30, 0, 1) != 0 else 'No')
    reservation = decode(data, 31, 0, 8)
    if reservation == 0:
        print('Reservation is not supported.')
    else:
        print('Reservation support for Exclusive Access - All Registrants:',
              decode(data, 31, 6, 1) != 0)
        print('Reservation support for Write Exclusive - All Registrants:',
              decode(data, 31, 5, 1) != 0)
        print('Reservation support for Exclusive Access - Registrants Only:',
              decode(data, 31, 4, 1) != 0)
        print('Reservation support for Write Exclusive - Registrants Only:',
              decode(data, 31, 3, 1) != 0)
        print('Reservation support for Exclusive Access:',
              decode(data, 31, 2, 1) != 0)
        print('Reservation support for Write Exclusive:',
              decode(data, 31, 1, 1) != 0)
        print('Support for Persist Through Power Loss:',
              decode(data, 31, 0, 1) != 0)
    print('Support for format progress indicator:',
          decode(data, 32, 7, 1) != 0)
    print('% remains to be formatted:', decode(data, 32, 0, 7))
    print('Namespace Atomic Write Unit Normal (NAWUN):',
          decode(data, 34, 0, 2*8))
    print('Namespace Atomic Write Unit Power Fail (NAWUPF):',
          decode(data, 36, 0, 2*8))
    print('Namespace Atomic Compare & Write Unit (NACWU):',
          decode(data, 38, 0, 2*8))
    print('Namespace Atomic Boundary Size Normal (NABSN):',
          decode(data, 40, 0, 2*8))
    print('Namespace Atomic Boundary Offset (NABO):',
          decode(data, 42, 0, 2*8))
    print('Namespace Atomic Boundary Size Power Fail (NABSPF):',
          decode(data, 44, 0, 2*8))
    print('NVM capacity in bytes:', decode(data, 48, 0, 16*8))
    print('Namespace GUID:', format(decode(data, 104, 0, 16*8), '032X'))
    print('Namespace EUI64:', format(decode(data, 120, 0, 8*8), '016X'))
    for i, pos in enumerate(range(128, 192, 4)):
        print_lbaf_info(i, decode(data, pos, 0, 4*8))


def print_lbaf_info(n, data):
    if data == 0:
        return
    print('LBAF{}'.format(n))
    print('    Relative performance:', RELATIVE_PERFORMANCE[(data>>24)&3])
    print('    LBA data size:', 1<<((data>>16)&255))
    print('    Metadata size:', data&65535)


# Main
def main():
    p = ArgumentParser(description=HELP_DESCRIPTION,
                       formatter_class=RawDescriptionHelpFormatter)
    p.parse_args()
    data = parse_input(sys.stdin)
    annotate(data)


if __name__ == '__main__':
    main()
