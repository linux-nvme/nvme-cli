#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
# Verify that __libnvme_public annotations and version-script entries are
# kept in sync:
#
#   1. Every function definition annotated with __libnvme_public in a .c
#      file must appear in one of the three version scripts (libnvme.ld,
#      libnvmf.ld, accessors.ld).  A function that is annotated but not
#      listed is visible to the compiler but silently hidden by the linker
#      version script's "local: *;" catch-all — the developer's intent to
#      export it would be silently ignored.
#
#   2. Every symbol listed in a version script must have a __libnvme_public
#      annotation on its definition.  Without the annotation the symbol is
#      hidden at compile time (due to -fvisibility=hidden) and the build
#      will either fail to link or produce a .so that is missing the symbol.
#
# Usage (standalone):
#   python3 tools/check-public-symbols.py [LIBNVME-SOURCE-ROOT]
#
# The source root defaults to the parent directory of this script.

import re
import sys
import pathlib

ROOT = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else \
       pathlib.Path(__file__).resolve().parent.parent

SRC_DIR = ROOT / 'src' / 'nvme'
LD_FILES = [
    ROOT / 'src' / 'libnvme.ld',
    ROOT / 'src' / 'libnvmf.ld',
    ROOT / 'src' / 'accessors.ld',
    ROOT / 'src' / 'accessors-fabrics.ld',
]

# ---------------------------------------------------------------------------
# Collect symbols listed in the version scripts
# ---------------------------------------------------------------------------
ld_syms = {}   # symbol -> Path of the .ld file that declares it

for ld_path in LD_FILES:
    if not ld_path.exists():
        continue
    for line in ld_path.read_text().splitlines():
        m = re.match(r'^\s+([a-z]\w+);', line)
        if m:
            ld_syms[m.group(1)] = ld_path

# ---------------------------------------------------------------------------
# Collect function names annotated with __libnvme_public in .c files
# ---------------------------------------------------------------------------
# Match: __libnvme_public <return-type> [*] function_name(
# The .*\b is greedy so it skips over the return type and any __attribute__
# qualifiers, leaving the last identifier before '(' as the function name.
PUB_RE = re.compile(r'^__libnvme_public\b.*\b([a-z_]\w+)\s*\(', re.MULTILINE)

pub_syms = {}  # symbol -> Path of the .c file that defines it

for c_path in sorted(SRC_DIR.glob('*.c')):
    for m in PUB_RE.finditer(c_path.read_text()):
        sym = m.group(1)
        pub_syms[sym] = c_path

# ---------------------------------------------------------------------------
# Report mismatches
# ---------------------------------------------------------------------------
errors = 0

# Check 1: __libnvme_public in .c but missing from all .ld files
for sym, c_path in sorted(pub_syms.items()):
    if sym not in ld_syms:
        print(f'ERROR: {sym}() is annotated __libnvme_public in '
              f'{c_path.name} but is not listed in any version script')
        errors += 1

# Check 2: listed in a .ld file but no __libnvme_public definition found
for sym, ld_path in sorted(ld_syms.items()):
    if sym not in pub_syms:
        print(f'ERROR: {sym}() is listed in {ld_path.name} but has no '
              f'__libnvme_public definition in {SRC_DIR.name}/*.c')
        errors += 1

if errors:
    print(f'\n{errors} error(s) found.')
    sys.exit(1)

print(f'OK: {len(pub_syms)} __libnvme_public symbols all present in version '
      f'scripts; {len(ld_syms)} version-script entries all annotated.')
