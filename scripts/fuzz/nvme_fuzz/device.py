# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""The commands of the device target, as its inputs select them.

An input of tests/fuzz/fuzz-device.c is the index of a command in its
commands[] table, a variant byte, an argument byte, for a command with
pci set the PCI vendor and device ID, and then the answers of the device.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path

from .targets import FUZZ_DIR

SOURCE = FUZZ_DIR / 'fuzz-device.c'

# The bits of the variant byte
VARIANTS = ((1, 'json'), (2, 'verbose'), (4, 'ns'), (8, 'arg'))

# An answer of the device: a control byte (0: success), the result dword
# and then the data of the command
OK_ANSWER = bytes(5)

# The PCI IDs of controllers the plugins check for: a model of each set of
# capabilities in their model tables (wdc_get_drive_capabilities(),
# sndk_get_drive_capabilities() and GetDriveModel() of micron)
_WDC_PCI_IDS = (
    (0x1C58, 0x0003),
    (0x1C58, 0x0023),
    (0x1B96, 0x2200),
    (0x1B96, 0x2400),
    (0x1B96, 0x2500),
    (0x1B96, 0x2600),
    (0x1B96, 0x2700),
    (0x1B96, 0x2750),
    (0x1B96, 0x2761),
    (0x15B7, 0x2001),
    (0x15B7, 0x2765),
    (0x15B7, 0x5002),
    (0x15B7, 0x5003),
    (0x15B7, 0x5006),
    (0x15B7, 0x5007),
    (0x15B7, 0x5010),
    (0x15B7, 0x5011),
    (0x15B7, 0x5015),
    (0x15B7, 0x5037),
)
PCI_IDS: dict[str, tuple[tuple[int, int], ...]] = {
    'wdc': _WDC_PCI_IDS,
    # the models it does not know it leaves to wdc
    'sndk': (
        *_WDC_PCI_IDS,
        (0x1B96, 0x2751),
        (0x15B7, 0x2770),
        (0x15B7, 0x27A0),
        (0x15B7, 0x503B),
        (0x15B7, 0x5081),
    ),
    'micron': (
        (0x1344, 0x5196),
        (0x1344, 0x51A2),
        (0x1344, 0x51B0),
        (0x1344, 0x51B7),
        (0x1344, 0x51BB),
        (0x1344, 0x51C0),
        (0x1344, 0x5405),
        (0x1344, 0x5410),
        (0x1344, 0x5411),
        (0x1344, 0x6001),
        (0x1344, 0x6003),
        (0x1344, 0x6004),
    ),
}


@dataclass(frozen=True)
class Command:
    index: int
    argv: tuple[str, ...]
    # The option which takes the argument byte, if any
    arg: str | None
    pci: bool

    @property
    def name(self) -> str:
        return ' '.join(self.argv)

    @property
    def pci_ids(self) -> tuple[tuple[int, int], ...]:
        """The PCI IDs of the controllers its plugin checks for, those of
        all plugins if it is none of them, none without pci set."""
        if not self.pci:
            return ()
        if self.argv[0] in PCI_IDS:
            return PCI_IDS[self.argv[0]]
        return tuple(dict.fromkeys(i for v in PCI_IDS.values() for i in v))

    def header(
        self, variant: int = 0, arg: int = 0, pci_ids: tuple[int, int] = (0, 0)
    ) -> bytes:
        """The start of an input which selects this command."""
        data = bytes([self.index, variant, arg])
        if self.pci:
            data += struct.pack('<HH', *pci_ids)
        return data


_ENTRY = re.compile(r'^\t\{ \{ (?P<argv>[^}]*)\}(?P<rest>[^\n]*)\},$', re.M)


def commands(source: Path = SOURCE) -> list[Command]:
    """The commands[] table of the device target."""
    src = source.read_text()
    start = src.index('} commands[] = {')
    body = src[start : src.index('\n};', start)]
    cmds: list[Command] = []
    for m in _ENTRY.finditer(body):
        argv = tuple(re.findall(r'"([^"]*)"', m.group('argv')))
        arg = re.search(r'"([^"]+)"', m.group('rest'))
        cmds.append(
            Command(
                len(cmds),
                argv,
                arg.group(1) if arg else None,
                '.pci = true' in m.group('rest'),
            )
        )
    return cmds


def describe(data: bytes, cmds: list[Command]) -> str:
    """What the input @data runs, e.g. "id ctrl (json,verbose)"."""
    if len(data) < 3:
        return 'too short'
    if data[0] >= len(cmds):
        return f'index {data[0]} (no command)'
    cmd = cmds[data[0]]
    flags = [name for bit, name in VARIANTS if data[1] & bit]
    if 'arg' in flags:
        if cmd.arg:
            flags[flags.index('arg')] = f'{cmd.arg}={data[2]}'
        else:
            flags.remove('arg')
    if cmd.pci and len(data) >= 7:
        vid, did = struct.unpack_from('<HH', data, 3)
        flags.append(f'pci={vid:04x}:{did:04x}')
    return cmd.name + (f' ({",".join(flags)})' if flags else '')
