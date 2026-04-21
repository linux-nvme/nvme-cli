#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
generate-swig-accessors.py — Generate SWIG #define accessor name bridges.

This file is part of libnvme.
Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
Authors: Martin Belanger <Martin.Belanger@dell.com>

Reads accessor header files produced by generate-accessors.py and emits a
SWIG .i file whose %{ %} block contains #define macros that map the
SWIG-generated accessor naming convention to the libnvme C API convention:

  SWIG generated:  libnvme_STRUCT_MEMBER_get(obj)
  libnvme C API:   libnvme_STRUCT_get_MEMBER(obj)

This is a post-processing step run after generate-accessors.py has refreshed
accessors.h and accessors-fabrics.h.  Both files are parsed so that common
and fabrics structs are covered in a single output file.

Usage:
  generate-swig-accessors.py -o nvme-swig-accessors.i accessors.h [accessors-fabrics.h ...]
"""

import argparse
import os
import re
import sys

BANNER = """\
/*
 * This file is part of libnvme.
 *
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 *
 *   ____                           _           _    ____          _
 *  / ___| ___ _ __   ___ _ __ __ _| |_ ___  __| |  / ___|___   __| | ___
 * | |  _ / _ \\ '_ \\ / _ \\ '__/ _` | __/ _ \\/ _` | | |   / _ \\ / _` |/ _ \\
 * | |_| |  __/ | | |  __/ | | (_| | ||  __/ (_| | | |__| (_) | (_| |  __/
 *  \\____|\\___|_| |_|\\___|_|  \\__,_|\\__\\___|\\__,_|  \\____\\___/ \\__,_|\\___|
 *
 * Auto-generated SWIG accessor #define bridges.
 *
 * To update run: meson compile -C [BUILD-DIR] update-accessors
 * Or:            make update-accessors
 */"""

# Non-greedy on the struct-prefix part so that the first occurrence of _get_
# or _set_ in the function name is used as the split point.
_GET_RE = re.compile(r'\b((?:libnvme|libnvmf)_\w+?)_get_(\w+)\s*\(')
_SET_RE = re.compile(r'\b((?:libnvme|libnvmf)_\w+?)_set_(\w+)\s*\(')


def parse_header(text):
    """Return ordered dict: struct_prefix -> {'gets': [member, ...], 'sets': [...]}.

    Only function declarations whose names follow the libnvme accessor
    convention (PREFIX_get_MEMBER / PREFIX_set_MEMBER) are collected.
    Lifecycle functions (new, free, init_defaults) don't match the regex
    and are silently ignored.
    """
    structs = {}
    for line in text.splitlines():
        for m in _GET_RE.finditer(line):
            pre, mem = m.group(1), m.group(2)
            entry = structs.setdefault(pre, {'gets': [], 'sets': []})
            if mem not in entry['gets']:
                entry['gets'].append(mem)
        for m in _SET_RE.finditer(line):
            pre, mem = m.group(1), m.group(2)
            entry = structs.setdefault(pre, {'gets': [], 'sets': []})
            if mem not in entry['sets']:
                entry['sets'].append(mem)
    return structs


def build_content(all_structs):
    """Return the full text of the generated .i file."""
    lines = [
        '/* SPDX-License-Identifier: LGPL-2.1-or-later */',
        '',
        BANNER,
        '',
        '%{',
    ]
    for pre, members in all_structs.items():
        pairs = ([(f'{pre}_{m}_get', f'{pre}_get_{m}') for m in members['gets']] +
                 [(f'{pre}_{m}_set', f'{pre}_set_{m}') for m in members['sets']])
        if not pairs:
            continue
        width = max(len(swig) for swig, _ in pairs)
        lines.append(f'\t/* struct {pre} */')
        for swig, c in pairs:
            lines.append(f'\t#define {swig:{width}} {c}')
        lines.append('')
    lines.append('%}')
    lines.append('')
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Generate SWIG #define accessor bridges from accessor headers.',
    )
    parser.add_argument('-o', '--output', required=True,
                        metavar='FILE',
                        help='Output SWIG *.i file.')
    parser.add_argument('headers', nargs='+',
                        help='Accessor header files to parse (e.g. accessors.h).')
    args = parser.parse_args()

    all_structs = {}
    for hdr in args.headers:
        try:
            with open(hdr) as f:
                text = f.read()
        except OSError as e:
            print(f'error: cannot read {hdr!r}: {e}', file=sys.stderr)
            sys.exit(1)

        for pre, members in parse_header(text).items():
            entry = all_structs.setdefault(pre, {'gets': [], 'sets': []})
            for mem in members['gets']:
                if mem not in entry['gets']:
                    entry['gets'].append(mem)
            for mem in members['sets']:
                if mem not in entry['sets']:
                    entry['sets'].append(mem)

    content = build_content(all_structs)

    # Only rewrite when content changes to avoid spurious mtime updates.
    try:
        with open(args.output) as f:
            if f.read() == content:
                print(f'  unchanged: {os.path.basename(args.output)}')
                return
    except OSError:
        pass

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, 'w') as f:
        f.write(content)
    print(f'  updated:   {os.path.basename(args.output)}')


if __name__ == '__main__':
    main()
