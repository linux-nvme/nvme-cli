# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""nvme-fuzz coverage: how far the device target gets into each command.

For each command of the device target, the edges its inputs reach
beyond those of a reference command, which only identifies the
controller. A command which adds few never gets past its option parsing
or a check of the device: a gate the fuzzer has to learn, or one it can
not pass at all. The inputs are random and zeroed device data, or the
inputs of a corpus, e.g. of a long run.
"""

from __future__ import annotations

import argparse
import collections
import random
from pathlib import Path

from . import device
from .libfuzzer import coverage
from .targets import TARGETS


def _pci_id(s: str) -> tuple[int, int]:
    vid, _, did = s.partition(':')
    return int(vid, 16), int(did, 16)


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        '--entries', default='', help='commands by index, e.g. 0-9,175 (all)'
    )
    p.add_argument(
        '--reference',
        default='ns get-id',
        help='the reference command (%(default)s)',
    )
    p.add_argument('--corpus', type=Path, help='use the inputs of this corpus')
    p.add_argument(
        '--pci',
        type=_pci_id,
        action='append',
        metavar='VID:DID',
        help='PCI IDs for commands with pci set, instead of models of '
        'the plugin of the command',
    )
    p.add_argument(
        '--low',
        type=int,
        default=50,
        help='mark commands which add fewer edges (%(default)s)',
    )


def generated(
    cmd: device.Command, pci_ids: tuple[tuple[int, int], ...] = ()
) -> list[bytes]:
    """Inputs for @cmd: random and zeroed data, with each variant, and
    for a command with pci set each of @pci_ids, by default those of its
    plugin."""
    ins = []
    for variant in (0, 1, 2, 9):
        rnd = random.Random(cmd.index * 100 + variant)
        for ids in (pci_ids or cmd.pci_ids) if cmd.pci else ((0, 0),):
            head = cmd.header(variant, rnd.randrange(256), ids)
            ins.append(head + rnd.randbytes(8192))
            ins.append(head + bytes(8192))
    return ins


def main(args: argparse.Namespace) -> int:
    binary = TARGETS['device'].binary(args.build_dir)
    cmds = device.commands()
    names = [c.name for c in cmds]
    if args.reference not in names:
        print(f"no command '{args.reference}'")
        return 1
    ref = cmds[names.index(args.reference)]
    pci_ids = tuple(args.pci or ())

    if args.corpus:
        by_index: dict[int, list[bytes]] = collections.defaultdict(list)
        for f in args.corpus.iterdir():
            data = f.read_bytes()
            if data:
                by_index[data[0]].append(data)

        def inputs(cmd: device.Command) -> list[bytes]:
            return by_index.get(cmd.index, [])
    else:

        def inputs(cmd: device.Command) -> list[bytes]:
            return generated(cmd, pci_ids)

    base_inputs = inputs(ref)
    base = coverage(binary, base_inputs)
    print(f'reference {ref.name}: {base} edges')
    selected = (
        device.parse_entries(args.entries, len(cmds))
        if args.entries
        else range(len(cmds))
    )
    for i in selected:
        cmd = cmds[i]
        ins = inputs(cmd)
        if not ins:
            print(f'{i:4d}       -  {cmd.name} (no inputs)')
            continue
        cov = coverage(binary, base_inputs + ins)
        if cov < 0:
            print(f'{i:4d}  failed  {cmd.name} (a finding, see triage)')
            continue
        low = '  LOW' if cov - base < args.low else ''
        print(f'{i:4d} {cov - base:+7d}  {cmd.name}{low}')
    return 0
