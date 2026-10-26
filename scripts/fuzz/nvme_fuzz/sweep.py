# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""nvme-fuzz sweep: try commands of the device target before fuzzing them.

Runs each selected command of the device target a few times with each
variant and random device data, with halting sanitizers, and reports a
command which crashes, takes long or writes files into its working
directory: a new entry of the commands[] table which does any of this
makes a fuzz run fail on nearly every input, or fills its directory. The
inputs depend only on the command, the same ones each time.
"""

from __future__ import annotations

import argparse
import os
import random
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import device, sanitizer
from .libfuzzer import Result, run_input
from .targets import TARGETS


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        '--entries', default='', help='commands by index, e.g. 0-9,175 (all)'
    )
    p.add_argument(
        '--samples',
        type=int,
        default=3,
        help='inputs per variant (%(default)s)',
    )
    p.add_argument(
        '--slow',
        type=float,
        default=10,
        help='report runs longer than this many seconds (%(default)s)',
    )
    p.add_argument(
        '--jobs',
        type=int,
        default=os.cpu_count() or 1,
        help='parallel runs (%(default)s)',
    )
    p.add_argument(
        '--save',
        type=Path,
        help='write the inputs with a problem to this directory, for '
        'check and triage',
    )


def inputs(cmd: device.Command, samples: int) -> list[bytes]:
    """The inputs for @cmd: @samples with random data for each variant
    and option set, each with the next of the PCI IDs of its plugin."""
    variants = [0, 1, 2, 3, 4]
    if cmd.arg:
        variants += [9, 11]
    variants += [
        v | n << device.OPTS_SHIFT
        for n in range(1, len(cmd.opts))
        for v in (0, 1)
    ]
    pci_ids = cmd.pci_ids or ((0, 0),)
    res = []
    for v in variants:
        for s in range(samples):
            rnd = random.Random(cmd.index * 1000 + v * 10 + s)
            ids = pci_ids[(v * samples + s) % len(pci_ids)]
            res.append(
                cmd.header(v, rnd.randrange(256), ids) + rnd.randbytes(8192)
            )
    return res


def problem(r: Result, slow: float) -> str | None:
    """What is wrong with the run @r, if anything."""
    if r.status:
        f = sanitizer.classify(r.report)
        return f'{f.kind} {f.location}'
    if r.files:
        return f'wrote {", ".join(r.files)}'
    if r.seconds > slow:
        return 'slow'
    return None


def main(args: argparse.Namespace) -> int:
    binary = TARGETS['device'].binary(args.build_dir)
    cmds = device.commands()
    selected = (
        device.parse_entries(args.entries, len(cmds))
        if args.entries
        else range(len(cmds))
    )
    if args.save:
        args.save.mkdir(parents=True, exist_ok=True)

    failed = 0
    with (
        tempfile.TemporaryDirectory(prefix='nvme-fuzz-sweep-') as tmp,
        ThreadPoolExecutor(args.jobs) as pool,
    ):
        for i in selected:
            cmd = cmds[i]
            paths = []
            for n, data in enumerate(inputs(cmd, args.samples)):
                path = Path(tmp) / f'sweep-{i}-{n}'
                path.write_bytes(data)
                paths.append(path)
            results = list(pool.map(lambda p: run_input(binary, p), paths))

            problems: dict[str, list[Path]] = {}
            for path, r in zip(paths, results, strict=True):
                what = problem(r, args.slow)
                if what:
                    problems.setdefault(what, []).append(path)
            longest = max(r.seconds for r in results)
            state = 'PROBLEM' if problems else 'ok'
            print(f'{i:4d} {state:7s} {longest:5.1f}s  {cmd.name}', flush=True)
            for what, found in problems.items():
                example = found[0]
                desc = device.describe(example.read_bytes(), cmds)
                print(f'       {len(found):3d}x {what}')
                print(f'            e.g. {example.name}: {desc}')
                if args.save:
                    for p in found:
                        (args.save / p.name).write_bytes(p.read_bytes())
            failed += bool(problems)
    print(f'{len(selected) - failed} ok, {failed} with problems')
    return 1 if failed else 0
