# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests of how nvme-mcp runs nvme top and sets the I/O policy."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from nvme_mcp.nvme import NvmeError, System

DATA = Path(__file__).resolve().parent / 'data'


class TestSystem(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def fake_nvme(self, body: str) -> str:
        """An nvme which logs its arguments and runs @body"""
        nvme = self.dir / 'nvme'
        nvme.write_text(
            f'#!/bin/sh\necho "$@" > {self.dir / "args"}\n{body}\n'
        )
        nvme.chmod(0o755)
        return str(nvme)

    def test_snapshot(self) -> None:
        nvme = self.fake_nvme(f'cat {DATA / "loop-3-paths.json"}')
        snap = System(nvme).snapshot(5)
        self.assertEqual(snap['Interval'], 3)
        self.assertEqual(
            (self.dir / 'args').read_text().split(),
            ['top', '--delay=5', '-o', 'json'],
        )

    def test_snapshot_fails(self) -> None:
        nvme = self.fake_nvme('echo no top here >&2; exit 1')
        with self.assertRaisesRegex(NvmeError, 'no top here'):
            System(nvme).snapshot(1)

    def test_snapshot_no_json(self) -> None:
        nvme = self.fake_nvme('echo Subsystem Summary')
        with self.assertRaisesRegex(NvmeError, 'no JSON'):
            System(nvme).snapshot(1)

    def test_no_nvme(self) -> None:
        with self.assertRaises(NvmeError):
            System(str(self.dir / 'missing')).snapshot(1)

    def test_interval(self) -> None:
        for bad in (0, 61):
            with self.assertRaises(NvmeError):
                System('nvme').snapshot(bad)

    def make_subsys(self, name: str, policy: str) -> Path:
        d = self.dir / 'class' / 'nvme-subsystem' / name
        d.mkdir(parents=True)
        (d / 'iopolicy').write_text(policy + '\n')
        return d / 'iopolicy'

    def test_iopolicy(self) -> None:
        f = self.make_subsys('nvme-subsys3', 'numa')
        system = System(sysfs=self.dir)
        self.assertEqual(system.iopolicy('nvme-subsys3'), 'numa')
        system.set_iopolicy('nvme-subsys3', 'queue-depth')
        self.assertEqual(f.read_text(), 'queue-depth')

    def test_iopolicy_checks(self) -> None:
        self.make_subsys('nvme-subsys3', 'numa')
        system = System(sysfs=self.dir)
        with self.assertRaisesRegex(NvmeError, 'unknown I/O policy'):
            system.set_iopolicy('nvme-subsys3', 'fastest')
        with self.assertRaisesRegex(NvmeError, 'not a subsystem name'):
            system.iopolicy('../../../etc')
        with self.assertRaisesRegex(NvmeError, 'no subsystem'):
            system.iopolicy('nvme-subsys4')


if __name__ == '__main__':
    unittest.main()
