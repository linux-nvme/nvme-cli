# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""nvme-fuzz triage: group findings by the bug they hit.

Each input is replayed once with halting sanitizers, and grouped by the
kind of finding and the first nvme-cli frame. For the device target, the
command an input runs is decoded from the commands[] table.
"""

from __future__ import annotations

import argparse
import collections
import sys
from pathlib import Path

from . import device, sanitizer
from .libfuzzer import inputs_of, replay
from .targets import TARGETS


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        '--target',
        choices=list(TARGETS),
        default='device',
        help='the target of the inputs (%(default)s)',
    )
    p.add_argument(
        '--show',
        action='store_true',
        help='print the report and stack of each input instead',
    )
    p.add_argument(
        'inputs',
        nargs='*',
        type=Path,
        help='inputs or directories of them (the artifacts of '
        'the target in BUILD_DIR/fuzz)',
    )


def show(binary: Path, path: Path, depth: int = 16) -> None:
    _, report = replay(binary, path)
    for line in sanitizer.summary(report):
        print(line)
    for f in sanitizer.stack(report)[:depth]:
        print(f'    {f.function} {f.location}')


def main(args: argparse.Namespace) -> int:
    t = TARGETS[args.target]
    binary = t.binary(args.build_dir)
    paths = args.inputs or [args.build_dir / 'fuzz' / 'artifacts' / t.name]
    files = inputs_of(paths)
    if args.show:
        for f in files:
            print(f'== {f}')
            show(binary, f)
        return 0

    cmds = device.commands() if t.name == 'device' else []
    groups: dict[sanitizer.Finding, list[tuple[Path, str]]] = (
        collections.defaultdict(list)
    )
    progress = sys.stderr.isatty()
    for i, f in enumerate(files, 1):
        if progress:
            print(f'\r{i}/{len(files)}', end='', file=sys.stderr, flush=True)
        _, report = replay(binary, f)
        what = device.describe(f.read_bytes(), cmds) if cmds else ''
        groups[sanitizer.classify(report)].append((f, what))
    if progress:
        print(file=sys.stderr)

    for finding, items in sorted(
        groups.items(), key=lambda g: (g[0].kind == 'none', g[0])
    ):
        print(f'{len(items):4d} {finding.kind:28s} {finding.location}')
        example, what = items[0]
        if cmds:
            names = sorted({w.split(' (')[0] for _, w in items})
            print(f'     [{", ".join(names)}]')
        print(f'     e.g. {example.name}{": " + what if what else ""}')
    return 0
