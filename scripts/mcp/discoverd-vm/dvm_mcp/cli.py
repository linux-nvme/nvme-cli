# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
"""The command line of discoverd-vm-mcp."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .server import Server
from .vm import VM


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='discoverd-vm-mcp',
        description='MCP server on stdin/stdout which tests, in a VM, '
        'what a system shutdown does to the nvme-discoverd connection '
        'units and the file systems mounted on them, see README.md.',
    )
    p.add_argument(
        '--vm-dir',
        type=Path,
        default=Path.home() / '.local' / 'share' / 'discoverd-vm',
        help='the VM directory: disk, seed, ssh key (%(default)s)',
    )
    p.add_argument(
        '--source',
        type=Path,
        required=True,
        help='the local nvme-cli source tree to build in the VM',
    )
    p.add_argument(
        '--port',
        type=int,
        default=2222,
        help='the local port forwarded to ssh in the VM (%(default)s)',
    )
    p.add_argument(
        '--allow-changes',
        action='store_true',
        help='offer the tools which create, start, change, reboot or '
        'stop the VM',
    )
    p.add_argument(
        '--version', action='version', version=f'%(prog)s {__version__}'
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    server = Server(
        VM(args.vm_dir.expanduser(), port=args.port),
        args.source.expanduser().resolve(),
        args.allow_changes,
    )
    try:
        server.serve(sys.stdin, sys.stdout)
    except KeyboardInterrupt:
        return 130
    return 0
