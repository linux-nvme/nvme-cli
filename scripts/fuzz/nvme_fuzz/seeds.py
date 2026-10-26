# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""nvme-fuzz seeds: seeds for the device target from the CLI mock tests.

The mock tests in tests/cli answer the commands of nvme-cli with valid
device data, which a fuzzed input rarely gets: most inputs end at the
first check of the data. This runs the mock tests with NVME_FUZZ_RECORD,
which records their answers in the input format of the device target,
and turns each run of a command of its commands[] table into a seed. The
seeds go into the corpus of the target, where the next run keeps those
which add coverage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import device

DEVICES = {'/dev/nvme0': 0, '/dev/nvme0n1': 4}


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        '--results', type=Path, help='results directory (BUILD_DIR/fuzz)'
    )
    p.add_argument(
        '--records',
        type=Path,
        help='use the records in this directory instead of running the '
        'mock tests',
    )


@dataclass
class _Args:
    """A command line of a mock test, split up."""

    words: list[str]
    device: str | None
    options: dict[str, str | None]

    @classmethod
    def parse(cls, args: list[str]) -> _Args:
        words: list[str] = []
        dev = None
        options: dict[str, str | None] = {}
        i = 0
        while i < len(args):
            a = args[i]
            if a.startswith('--'):
                name, eq, value = a.partition('=')
                if not eq and i + 1 < len(args) and _is_value(args[i + 1]):
                    i += 1
                    value = args[i]
                options[name] = value if eq or value else None
            elif a in ('-o', '-v'):
                # the short names of the options of the variant byte
                if a == '-o' and i + 1 < len(args):
                    i += 1
                    options['--output-format'] = args[i]
                else:
                    options['--verbose'] = None
            elif a.startswith('-'):
                pass
            elif a.startswith('/dev/'):
                dev = dev or a
            elif dev is None and not options:
                words.append(a)
            i += 1
        return cls(words, dev, options)


def _is_value(a: str) -> bool:
    return not a.startswith('-') and not a.startswith('/dev/nvme')


def _score(cmd: device.Command, args: _Args) -> int | None:
    """How well @cmd matches @args, None for not at all: its words must be
    those of the command line, its options given, best with its value."""
    words = [a for a in cmd.argv if not a.startswith('-')]
    if words != args.words:
        return None
    score = 0
    for opt in (a for a in cmd.argv if a.startswith('-')):
        name, _, value = opt.partition('=')
        if name not in args.options:
            return None
        score += 1 + (args.options[name] == value)
    return score


def seed(record: dict[str, Any], cmds: list[device.Command]) -> bytes | None:
    """The input which runs the command of @record with its answers, None
    if the device target has no such command."""
    args = _Args.parse(record['args'])
    if args.device not in DEVICES:
        return None
    pci = record.get('pci')
    best: tuple[int, device.Command] | None = None
    for cmd in cmds:
        if cmd.pci and not pci:
            continue
        score = _score(cmd, args)
        if score is None:
            continue
        # a command with pci set passes the checks of the PCI IDs
        score = score * 2 + (cmd.pci and bool(pci))
        if best is None or score > best[0]:
            best = (score, cmd)
    if best is None:
        return None
    cmd = best[1]
    variant = DEVICES[args.device]
    if args.options.get('--output-format') == 'json':
        variant |= 1
    if '--verbose' in args.options:
        variant |= 2
    arg = 0
    value = args.options.get(cmd.arg) if cmd.arg else None
    if value is not None:
        try:
            n = int(value, 0)
        except ValueError:
            n = -1
        if n == 0xFFFFFFFF or 0 <= n < 0xFF:
            variant |= 8
            arg = n & 0xFF
    pci_ids = (pci[0], pci[1]) if cmd.pci and pci else (0, 0)
    return cmd.header(variant, arg, pci_ids, _opts(cmd, args)) + bytes.fromhex(
        record['answers']
    )


def _opts(cmd: device.Command, args: _Args) -> int:
    """The option set of @cmd the command line @args uses: the one with
    the most options, all of which it gives with the same value, else
    one without options."""
    best, most = None, -1
    for n in range(4):
        opts = cmd.opts[n] if n < len(cmd.opts) else ()
        given = all(
            name in args.options and (not eq or args.options[name] == value)
            for name, eq, value in (o.partition('=') for o in opts)
        )
        if given and len(opts) > most:
            best, most = n, len(opts)
    return best or 0


def _record(build_dir: Path, records: Path) -> None:
    """Run the mock tests of @build_dir with their answers recorded to
    @records. A failed test still records what it ran."""
    env = dict(os.environ, NVME_FUZZ_RECORD=str(records))
    r = subprocess.run(
        ['meson', 'test', '-C', str(build_dir), '--suite', 'mock'],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if r.returncode:
        print(f'some mock tests failed, see {build_dir}/meson-logs')


def write_seeds(records: Path, corpus: Path) -> tuple[int, int, int]:
    """Write the seeds of the records in @records to @corpus. Returns the
    number of records, of new seeds and of commands they run."""
    cmds = device.commands()
    corpus.mkdir(parents=True, exist_ok=True)
    files = sorted(records.glob('*.json'))
    new = 0
    seen = set()
    for f in files:
        data = seed(json.loads(f.read_text()), cmds)
        if data is None:
            continue
        seen.add(data[0])
        out = corpus / f'mock-{hashlib.sha1(data).hexdigest()}'
        if not out.exists():
            out.write_bytes(data)
            new += 1
    return len(files), new, len(seen)


def add_seeds(
    build_dir: Path, corpus: Path, records: Path | None = None
) -> None:
    """Add the seeds of the mock tests of @build_dir to @corpus, or of the
    records in @records."""
    with tempfile.TemporaryDirectory(prefix='nvme-fuzz-records-') as tmp:
        if not records:
            records = Path(tmp)
            _record(build_dir, records)
        n, new, nr_cmds = write_seeds(records, corpus)
    print(
        f'{n} runs of the mock tests, {new} new seeds of {nr_cmds} '
        f'commands in {corpus}'
    )


def main(args: argparse.Namespace) -> int:
    results: Path = args.results or args.build_dir / 'fuzz'
    add_seeds(args.build_dir, results / 'corpus' / 'device', args.records)
    return 0
