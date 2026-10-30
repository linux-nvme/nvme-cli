# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for reading the commands[] table of the device target."""

import argparse
import tempfile
import unittest
from pathlib import Path

from nvme_fuzz import device

TABLE = """\
static const struct {
\tconst char *argv[4];
\tconst char *arg;
\tbool pci;
\tconst char *opts[4][3];
} commands[] = {
\t{ { "id", "ctrl" } },
\t{ { "id", "ns" }, "--namespace-id" },
\t{ { "get-log", "--log-len=4096" }, "--log-id" },
\t{ { "wdc", "vs-smart-add-log" }, .pci = true },
\t{ { "ocp", "get-latency-monitor", "--no-uuid" }, "--sel" },
\t{ { "format", "--force" }, "--lbaf",
\t  .opts = { { "--ses=1" }, { "--pi=1", "--ms=1" } } },
};
"""


class CommandsTest(unittest.TestCase):
    def setUp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fuzz-device.c'
            path.write_text(TABLE)
            self.cmds = device.commands(path)

    def test_entries(self) -> None:
        self.assertEqual(
            [(c.index, c.name, c.arg, c.pci) for c in self.cmds],
            [
                (0, 'id ctrl', None, False),
                (1, 'id ns', '--namespace-id', False),
                (2, 'get-log --log-len=4096', '--log-id', False),
                (3, 'wdc vs-smart-add-log', None, True),
                (4, 'ocp get-latency-monitor --no-uuid', '--sel', False),
                (5, 'format --force', '--lbaf', False),
            ],
        )
        self.assertEqual(self.cmds[4].opts, ())
        self.assertEqual(
            self.cmds[5].opts, (('--ses=1',), ('--pi=1', '--ms=1'))
        )

    def test_header(self) -> None:
        self.assertEqual(self.cmds[1].header(9, 7), bytes([1, 9, 7]))
        self.assertEqual(
            self.cmds[3].header(0, 0, (0x1B96, 0x2500)),
            bytes([3, 0, 0, 0x96, 0x1B, 0x00, 0x25]),
        )
        self.assertEqual(
            self.cmds[5].header(1, 0, opts=2), bytes([5, 0x21, 0])
        )

    def test_extended_index(self) -> None:
        # from index 255 on, 0xff and the index - 255
        cmd = device.Command(300, ('x',), None, True)
        data = cmd.header(1, 2, (0x1234, 0x5678))
        self.assertEqual(data, bytes([0xFF, 45, 1, 2, 0x34, 0x12, 0x78, 0x56]))
        self.assertEqual(device.split(data), (300, data[2:]))
        self.assertEqual(device.split(bytes([0xFF, 0])), (255, b''))
        self.assertEqual(device.split(bytes([7, 1])), (7, bytes([1])))
        self.assertIsNone(device.split(bytes([0xFF])))
        self.assertIsNone(device.split(b''))

    def test_pci_ids(self) -> None:
        self.assertEqual(self.cmds[0].pci_ids, ())
        self.assertEqual(self.cmds[3].pci_ids, device.PCI_IDS['wdc'])
        other = device.Command(9, ('other', 'cmd'), None, True)
        for ids in device.PCI_IDS.values():
            self.assertTrue(set(ids) <= set(other.pci_ids))

    def test_describe(self) -> None:
        def d(data: bytes) -> str:
            return device.describe(data, self.cmds)

        self.assertEqual(d(bytes([0, 0, 0])), 'id ctrl')
        self.assertEqual(
            d(bytes([1, 11, 5])), 'id ns (json,verbose,--namespace-id=5)'
        )
        # no option takes the argument byte
        self.assertEqual(d(bytes([0, 8, 5])), 'id ctrl')
        self.assertEqual(
            d(bytes([3, 4, 0, 0x96, 0x1B, 0x00, 0x25])),
            'wdc vs-smart-add-log (ns,pci=1b96:2500)',
        )
        self.assertEqual(d(bytes([9, 0, 0])), 'index 9 (no command)')
        self.assertEqual(d(bytes([0xFF, 1, 0, 0])), 'index 256 (no command)')
        self.assertEqual(d(bytes([0])), 'too short')
        self.assertEqual(d(bytes([0xFF, 1, 0])), 'too short')
        self.assertEqual(
            d(bytes([5, 0x18, 4])), 'format --force (--lbaf=4,--pi=1 --ms=1)'
        )
        # a set the command doesn't have adds nothing
        self.assertEqual(d(bytes([5, 0x30, 0])), 'format --force')

    def test_of_plugins(self) -> None:
        def names(*plugins: str) -> list[str]:
            return [c.name for c in device.of_plugins(self.cmds, plugins)]

        self.assertEqual(names('ocp'), ['ocp get-latency-monitor --no-uuid'])
        self.assertEqual(names('id'), ['id ctrl', 'id ns'])
        # a built-in command by its name
        self.assertEqual(
            names('wdc', 'format'),
            ['wdc vs-smart-add-log', 'format --force'],
        )
        self.assertEqual(names('get'), [])


class RealTableTest(unittest.TestCase):
    """The table in the tree parses, and its first entry is id ctrl: the
    inputs in the corpus depend on the indices."""

    def test_real_table(self) -> None:
        cmds = device.commands()
        self.assertGreater(len(cmds), 100)
        # the plugins with commands which check the PCI IDs have models
        plugins = {c.argv[0] for c in cmds if c.pci}
        self.assertLessEqual(plugins, set(device.PCI_IDS))
        self.assertEqual(cmds[0].name, 'id ctrl')
        self.assertTrue(all(c.argv for c in cmds))
        self.assertEqual([c.index for c in cmds], list(range(len(cmds))))

    def test_parse_plugins(self) -> None:
        self.assertEqual(device.parse_plugins('ocp,micron'), ('ocp', 'micron'))
        self.assertEqual(device.parse_plugins('read'), ('read',))
        with self.assertRaisesRegex(
            argparse.ArgumentTypeError, "no command of 'nope'.*ocp"
        ):
            device.parse_plugins('ocp,nope')
        # the commands from index 255 on are selected as well
        cmds = device.of_plugins(device.commands(), ('zns',))
        self.assertTrue(any(c.index >= device.EXTENDED_INDEX for c in cmds))


if __name__ == '__main__':
    unittest.main()
