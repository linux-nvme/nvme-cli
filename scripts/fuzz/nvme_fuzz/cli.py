# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""The command line of nvme-fuzz."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import build, check, coverage, run, triage
from .targets import SOURCE_ROOT

COMMANDS = {
    'build': build,
    'run': run,
    'triage': triage,
    'check': check,
    'coverage': coverage,
}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='nvme-fuzz',
        description='Build, run and evaluate the libFuzzer targets of '
        'nvme-cli, see Documentation/TESTING.md.',
    )
    p.add_argument(
        '-C',
        '--build-dir',
        type=Path,
        default=SOURCE_ROOT / '.build-fuzz',
        help='the build directory (%(default)s)',
    )
    sub = p.add_subparsers(dest='command', required=True)
    for name, mod in COMMANDS.items():
        doc = (mod.__doc__ or '').strip()
        sp = sub.add_parser(
            name,
            help=doc.splitlines()[0].split(': ', 1)[-1],
            description=doc,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        mod.add_arguments(sp)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    args.build_dir = args.build_dir.resolve()
    try:
        status: int = COMMANDS[args.command].main(args)
    except KeyboardInterrupt:
        return 130
    return status


if __name__ == '__main__':
    sys.exit(main())
