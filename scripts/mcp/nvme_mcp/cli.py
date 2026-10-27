# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""The command line of nvme-mcp."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .nvme import System
from .server import Server


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='nvme-mcp',
        description='MCP server on stdin/stdout which lets an agent watch '
        'the I/O of the NVMe subsystems with nvme top, see README.md.',
    )
    p.add_argument(
        '--nvme',
        default='nvme',
        help='the nvme binary, with nvme top -o json (%(default)s)',
    )
    p.add_argument(
        '--allow-iopolicy',
        action='store_true',
        help='offer the tools which change the I/O policy of a subsystem',
    )
    p.add_argument(
        '--sysfs',
        type=Path,
        default=Path('/sys'),
        help=argparse.SUPPRESS,  # for the tests
    )
    p.add_argument(
        '--version', action='version', version=f'%(prog)s {__version__}'
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    server = Server(System(args.nvme, args.sysfs), args.allow_iopolicy)
    try:
        server.serve(sys.stdin, sys.stdout)
    except KeyboardInterrupt:
        return 130
    return 0
