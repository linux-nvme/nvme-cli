# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""nvme-fuzz check: run inputs once each, as regression tests.

The test suite runs the seeds with the fuzz driver, which sends the
output of the target to /dev/null: a seed which fails there shows no
report. This runs each input alone with halting sanitizers, and prints
what went wrong. To show that a regression input catches its bug, run it
without the fix and with it.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import sanitizer
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
        'inputs',
        nargs='*',
        type=Path,
        help='inputs or directories of them (the regression '
        'inputs of the target, regress-* in its corpus)',
    )


def main(args: argparse.Namespace) -> int:
    t = TARGETS[args.target]
    binary = t.binary(args.build_dir)
    files = (
        inputs_of(args.inputs)
        if args.inputs
        else sorted(t.seeds.glob('regress-*'))
    )
    failed = 0
    for f in files:
        status, report = replay(binary, f)
        if status == 0:
            print(f'ok    {f.name}')
            continue
        failed += 1
        finding = sanitizer.classify(report)
        print(f'FAIL  {f.name}: {finding.kind} {finding.location}')
        for line in sanitizer.summary(report)[:3]:
            print(f'      {line.strip()}')
    print(f'{len(files) - failed} ok, {failed} failed')
    return 1 if failed else 0
