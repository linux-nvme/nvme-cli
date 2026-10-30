# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""The commands of the device target, as its inputs select them.

An input of tests/fuzz/fuzz-device.c is the index of a command in its
commands[] table (0xff and a second byte from index 255 on), a variant
byte, an argument byte, for a command with pci set the PCI vendor and
device ID, and then the answers of the device.
"""

from __future__ import annotations

import argparse
import re
import struct
from dataclasses import dataclass
from pathlib import Path

from .targets import FUZZ_DIR

SOURCE = FUZZ_DIR / 'fuzz-device.c'

# The bits of the variant byte; bits 5:4 select the option set
VARIANTS = ((1, 'json'), (2, 'verbose'), (4, 'ns'), (8, 'arg'))
OPTS_SHIFT = 4

# The first byte of an input of a command from index 255 on
EXTENDED_INDEX = 0xFF

# An answer of the device: a control byte (0: success), the result dword
# and then the data of the command
OK_ANSWER = bytes(5)

# The PCI IDs of controllers the plugins check for: a model of each set of
# capabilities in their model tables (wdc_get_drive_capabilities(),
# sndk_get_drive_capabilities(), GetDriveModel() of micron, GetSSDModel()
# of ymtc), and the vendors sfx status knows
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
    'ymtc': (
        (0x1E49, 0x1058),
        (0x1E49, 0x1078),
        (0x1E49, 0x1A28),
        (0x1E49, 0x1A38),
        (0x1E49, 0x1A48),
    ),
    'sfx': (
        (0xCC53, 0x0020),
        (0xCC53, 0x0021),
        (0x1DFD, 0x0020),
    ),
}


@dataclass(frozen=True)
class Command:
    index: int
    argv: tuple[str, ...]
    # The option which takes the argument byte, if any
    arg: str | None
    pci: bool
    # The option sets bits 5:4 of the variant select
    opts: tuple[tuple[str, ...], ...] = ()

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
        self,
        variant: int = 0,
        arg: int = 0,
        pci_ids: tuple[int, int] = (0, 0),
        opts: int = 0,
    ) -> bytes:
        """The start of an input which selects this command, with the
        option set @opts."""
        if self.index < EXTENDED_INDEX:
            data = bytes([self.index])
        else:
            data = bytes([EXTENDED_INDEX, self.index - EXTENDED_INDEX])
        data += bytes([variant | opts << OPTS_SHIFT, arg])
        if self.pci:
            data += struct.pack('<HH', *pci_ids)
        return data


def split(data: bytes) -> tuple[int, bytes] | None:
    """The command index of the input @data and the rest of it, from the
    variant byte on; None if it is too short to have one."""
    if data[:1] == bytes([EXTENDED_INDEX]):
        if len(data) < 2:
            return None
        return EXTENDED_INDEX + data[1], data[2:]
    if not data:
        return None
    return data[0], data[1:]


def _entries(body: str) -> list[str]:
    """The text of each entry of the table @body, by its braces."""
    res = []
    depth = 0
    start = 0
    for i, c in enumerate(body):
        if c == '{':
            if depth == 0:
                start = i
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                res.append(body[start + 1 : i])
    return res


def commands(source: Path = SOURCE) -> list[Command]:
    """The commands[] table of the device target."""
    src = source.read_text()
    start = src.index('} commands[] = {') + len('} commands[] = {')
    body = src[start : src.index('\n};', start)]
    cmds: list[Command] = []
    for entry in _entries(body):
        argv_end = entry.index('}')
        argv = tuple(re.findall(r'"([^"]*)"', entry[:argv_end]))
        rest, _, opts_text = entry[argv_end + 1 :].partition('.opts')
        arg = re.search(r'"([^"]+)"', rest)
        opts = (
            tuple(
                tuple(re.findall(r'"([^"]*)"', o))
                for o in _entries(opts_text[opts_text.index('{') + 1 :])
            )
            if opts_text
            else ()
        )
        cmds.append(
            Command(
                len(cmds),
                argv,
                arg.group(1) if arg else None,
                '.pci = true' in rest,
                opts,
            )
        )
    return cmds


def parse_entries(spec: str, n: int) -> list[int]:
    """The indices of a list of them and ranges, e.g. 0-9,175, below
    @n."""
    res: list[int] = []
    for part in spec.split(','):
        first, _, last = part.partition('-')
        res += range(int(first), int(last or first) + 1)
    return [i for i in res if 0 <= i < n]


def of_plugins(cmds: list[Command], plugins: tuple[str, ...]) -> list[Command]:
    """The commands of @cmds whose first word is one of @plugins: the
    plugin, or the built-in command."""
    return [c for c in cmds if c.argv[0] in plugins]


def parse_plugins(spec: str) -> tuple[str, ...]:
    """The plugins of a comma-separated list of them, for FUZZ_PLUGINS of
    the device target."""
    known = dict.fromkeys(c.argv[0] for c in commands())
    plugins = tuple(spec.split(','))
    for name in plugins:
        if name not in known:
            raise argparse.ArgumentTypeError(
                f"no command of '{name}' in the device target, one of: "
                f'{", ".join(sorted(known))}'
            )
    return plugins


def describe(data: bytes, cmds: list[Command]) -> str:
    """What the input @data runs, e.g. "id ctrl (json,verbose)"."""
    parts = split(data)
    if parts is None or len(parts[1]) < 2:
        return 'too short'
    index, rest = parts
    if index >= len(cmds):
        return f'index {index} (no command)'
    cmd = cmds[index]
    flags = [name for bit, name in VARIANTS if rest[0] & bit]
    if 'arg' in flags:
        if cmd.arg:
            flags[flags.index('arg')] = f'{cmd.arg}={rest[1]}'
        else:
            flags.remove('arg')
    n = rest[0] >> OPTS_SHIFT & 3
    if n < len(cmd.opts) and cmd.opts[n]:
        flags.append(' '.join(cmd.opts[n]))
    if cmd.pci and len(rest) >= 6:
        vid, did = struct.unpack_from('<HH', rest, 2)
        flags.append(f'pci={vid:04x}:{did:04x}')
    return cmd.name + (f' ({",".join(flags)})' if flags else '')
