#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
# Verify that every symbol exported in a version script has a prototype
# declared in one of the installed header files.
#
# A __public function that appears in a .ld version script but not in any
# installed header is technically callable by external code, but callers have
# no declaration to include — they would need to write their own prototype or
# use dlsym(), which defeats the purpose of a stable public API.
#
# Usage (via meson — preferred, keeps meson.build as single source of truth):
#   python3 tools/check-public-headers.py \
#       --ld src/libnvme.ld --ld src/accessors.ld [--ld ...] \
#       --header src/nvme/lib.h --header src/nvme/tree.h [--header ...]
#
# Usage (standalone, auto-discovers files from the source root):
#   python3 tools/check-public-headers.py [LIBNVME-SOURCE-ROOT]
#
# In auto-discovery mode the script scans src/*.ld for version scripts and
# src/nvme/*.h (excluding files whose name contains "private") for headers.
# The source root defaults to the parent directory of this script.

import argparse
import re
import sys
import pathlib


def parse_args():
    parser = argparse.ArgumentParser(
        description='Check that every exported symbol has a prototype in an '
                    'installed header.')
    parser.add_argument(
        'root', nargs='?',
        help='libnvme source root for auto-discovery (defaults to the parent '
             'of this script); ignored when --ld / --header are given')
    parser.add_argument(
        '--ld', action='append', metavar='FILE', dest='ld_files',
        help='version-script (.ld) file to read exported symbols from '
             '(may be repeated)')
    parser.add_argument(
        '--header', action='append', metavar='FILE', dest='headers',
        help='installed header file to search for prototypes '
             '(may be repeated)')
    return parser.parse_args()


def main():
    args = parse_args()

    if args.ld_files or args.headers:
        if not args.ld_files or not args.headers:
            sys.exit('error: --ld and --header must both be provided together')
        ld_files = [pathlib.Path(f) for f in args.ld_files]
        headers  = [pathlib.Path(f) for f in args.headers]
    else:
        root = pathlib.Path(args.root) if args.root else \
               pathlib.Path(__file__).resolve().parent.parent
        src = root / 'src'
        ld_files = sorted(src.glob('*.ld'))
        headers  = sorted(h for h in (src / 'nvme').glob('*.h')
                          if 'private' not in h.name)

    # -----------------------------------------------------------------------
    # Collect all symbols listed in the version scripts
    # -----------------------------------------------------------------------
    ld_syms = {}   # symbol -> Path of the .ld file that declares it

    for ld_path in ld_files:
        for line in ld_path.read_text().splitlines():
            m = re.match(r'^\s+([a-z]\w+);', line)
            if m:
                ld_syms[m.group(1)] = ld_path

    # -----------------------------------------------------------------------
    # Collect all names that appear as a prototype/declaration in installed
    # headers.  Match any identifier immediately followed by '(' — this
    # catches both single-line and multi-line function declarations, and macro
    # definitions that alias a function name.  The libnvme_*/libnvmf_*
    # namespace is long enough that false positives from comments are not a
    # practical concern.
    # -----------------------------------------------------------------------
    header_syms = set()

    for hdr_path in headers:
        for m in re.finditer(r'\b([a-z_]\w+)\s*\(', hdr_path.read_text()):
            header_syms.add(m.group(1))

    # -----------------------------------------------------------------------
    # Report exported symbols with no prototype in any installed header
    # -----------------------------------------------------------------------
    errors = 0

    for sym, ld_path in sorted(ld_syms.items()):
        if sym not in header_syms:
            print(f'ERROR: {sym}() is exported in {ld_path.name} '
                  f'but has no prototype in any installed header')
            errors += 1

    if errors:
        print(f'\n{errors} error(s) found.')
        sys.exit(1)

    print(f'OK: all {len(ld_syms)} exported symbols have prototypes '
          f'in installed headers.')


if __name__ == '__main__':
    main()
