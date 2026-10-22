# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for the seeds of the device target from the CLI mock tests."""

import json
import struct
import tempfile
import unittest
from pathlib import Path

from nvme_fuzz import device, seeds

CMDS = device.commands()
ANSWERS = '00' + '78563412' + 'aa' * 4


def index(name: str, pci: bool = False) -> int:
    return next(c.index for c in CMDS if c.name == name and c.pci == pci)


def maybe_seed(*args: str, pci: list[int] | None = None) -> bytes | None:
    return seeds.seed(
        {'args': list(args), 'pci': pci, 'answers': ANSWERS}, CMDS
    )


def seed(*args: str, pci: list[int] | None = None) -> bytes:
    data = maybe_seed(*args, pci=pci)
    assert data is not None
    return data


class SeedTest(unittest.TestCase):
    def test_option_and_arg(self) -> None:
        # --log-len matches by name, --log-id is the argument byte
        data = seed('get-log', '/dev/nvme0', '--log-id=2', '--log-len=512')
        self.assertEqual(
            data,
            bytes([index('get-log --log-len=4096'), 8, 2])
            + bytes.fromhex(ANSWERS),
        )

    def test_variant(self) -> None:
        data = seed('id', 'ctrl', '/dev/nvme0n1', '-o', 'json', '-v')
        self.assertEqual(data[:3], bytes([index('id ctrl'), 4 | 1 | 2, 0]))
        data = seed('id', 'ctrl', '/dev/nvme0', '--output-format=normal')
        self.assertEqual(data[:3], bytes([index('id ctrl'), 0, 0]))

    def test_all_namespaces(self) -> None:
        data = seed('id', 'ns', '/dev/nvme0', '--namespace-id=0xffffffff')
        self.assertEqual(data[:3], bytes([index('id ns'), 8, 0xFF]))
        # does not fit the argument byte
        data = seed('id', 'ns', '/dev/nvme0', '--namespace-id', '300')
        self.assertEqual(data[:3], bytes([index('id ns'), 0, 0]))

    def test_pci_ids(self) -> None:
        data = seed('wdc', 'vs-nand-stats', '/dev/nvme0', pci=[0x1B96, 0x2500])
        self.assertEqual(
            data[:7],
            bytes([index('wdc vs-nand-stats', pci=True), 0, 0])
            + struct.pack('<HH', 0x1B96, 0x2500),
        )
        data = seed('wdc', 'vs-nand-stats', '/dev/nvme0')
        self.assertEqual(data[0], index('wdc vs-nand-stats'))

    def test_no_command(self) -> None:
        self.assertIsNone(maybe_seed('no-such-command', '/dev/nvme0'))
        self.assertIsNone(maybe_seed('id', 'ctrl', '/dev/nvme1'))
        self.assertIsNone(maybe_seed('id', 'ctrl'))
        # an option of the command is missing
        self.assertIsNone(maybe_seed('dir', 'receive', '/dev/nvme0'))

    def test_write_seeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            records = Path(tmp) / 'records'
            corpus = Path(tmp) / 'corpus'
            records.mkdir()
            rec = {'args': ['id', 'ctrl', '/dev/nvme0'], 'pci': None}
            for i, args in enumerate(
                (rec['args'], rec['args'], ['no-such-command', '/dev/nvme0'])
            ):
                (records / f'{i}.json').write_text(
                    json.dumps({**rec, 'args': args, 'answers': ANSWERS})
                )
            self.assertEqual(seeds.write_seeds(records, corpus), (3, 1, 1))
            (f,) = corpus.iterdir()
            self.assertTrue(f.name.startswith('mock-'))
            # again: nothing new
            self.assertEqual(seeds.write_seeds(records, corpus), (3, 0, 1))


if __name__ == '__main__':
    unittest.main()
