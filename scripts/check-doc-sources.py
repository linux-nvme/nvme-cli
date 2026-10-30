#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Fail if a man page source in DOCDIR is not listed in its meson.build.

A page which is not listed is neither built nor installed.

Usage: check-doc-sources.py DOCDIR SOURCE...

SOURCE is a listed page, with or without the .txt extension.
"""

import pathlib
import sys


def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2

    listed = {s.removesuffix('.txt') for s in sys.argv[2:]}
    missing = sorted(p.stem for p in pathlib.Path(sys.argv[1]).glob('*.txt')
                     if p.stem not in listed)
    for name in missing:
        print(f'{name}.txt is not listed in Documentation/meson.build',
              file=sys.stderr)

    return 1 if missing else 0


if __name__ == '__main__':
    sys.exit(main())
