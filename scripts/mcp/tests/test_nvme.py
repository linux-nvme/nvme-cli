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

from nvme_mcp import nvme
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


class TestKernelLog(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.kmsg = Path(self.tmp.name) / 'kmsg'
        # from before the watch
        self.kmsg.write_text('3,1,1000,-;nvme nvme0: old message\n')
        self.log = System(kmsg=self.kmsg).kernel_log()

    def tearDown(self) -> None:
        self.log.close()
        self.tmp.cleanup()

    def append(self, text: str) -> None:
        with self.kmsg.open('a') as f:
            f.write(text)

    def test_poll(self) -> None:
        """Only the NVMe lines, stamped with the time they were seen"""
        self.log.poll(0.5)
        self.append(
            '4,2,101500000,-;nvme nvme1: resetting controller\n'
            ' SUBSYSTEM=nvme\n'
            ' DEVICE=c238:1\n'
            '6,3,101600000,-;e1000e: eth0 NIC Link is Up\n'
            'garbage\n'
            '6,5,x,-;nvme no time\n'
        )
        self.log.poll(1.04)
        self.append('3,4,99000000,-;NVME: from another CPU\n')
        self.log.poll(2.0)
        self.assertEqual(
            self.log.lines,
            [
                {
                    'T': 1.0,
                    'KernelTime': 101.5,
                    'Message': 'nvme nvme1: resetting controller',
                },
                {
                    'T': 2.0,
                    'KernelTime': 99.0,
                    'Message': 'NVME: from another CPU',
                },
            ],
        )

    def test_repeated(self) -> None:
        """Messages which differ only in numbers are one, counted; the
        number of a device name tells them apart"""
        lpfc = (
            'lpfc 0000:3b:00.0: 0:(0):6034 ENTER.  lpfc_pnvme '
            'xffff9bb8cae0{}, qidx x{} qhandle xffff9bc0{}'
        )
        self.append(
            f'7,1,1,-;{lpfc.format(10, 3, "aa")}\n'
            '3,2,2,-;nvme nvme12: NVME-FC{3}: controller connectivity lost\n'
            f'7,3,3,-;{lpfc.format(28, 12, "b0")}\n'
            '3,4,4,-;nvme nvme26: NVME-FC{7}: controller connectivity lost\n'
            '4,5,5,-;nvme nvme12: long keepalive RTT (2012 ms)\n'
            '3,6,6,-;lpfc 0000:04:00.0: NVME FCP_ERR ERSP: xri 7ba placed\n'
            '3,7,7,-;lpfc 0000:04:00.0: NVME FCP_ERR ERSP: xri 44a placed\n'
        )
        self.log.poll(1.0)
        self.append(f'7,6,6,-;{lpfc.format(30, 7, "c4")}\n')
        self.log.poll(2.0)
        lines = self.log.lines
        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[4]['Count'], 2)
        self.assertEqual(lines[0]['Message'], lpfc.format(10, 3, 'aa'))
        self.assertEqual((lines[0]['Count'], lines[0]['LastT']), (3, 2.0))
        self.assertEqual(
            [line['Message'][:12] for line in lines[1:4]],
            ['nvme nvme12:', 'nvme nvme26:', 'nvme nvme12:'],
        )
        for line in lines[1:4]:
            self.assertNotIn('Count', line)

    def test_cap(self) -> None:
        n = nvme.MAX_KERNEL_LINES + 5
        self.append(''.join(f'6,{i},1,-;nvme{i}\n' for i in range(n)))
        self.log.poll(1.0)
        self.assertEqual(len(self.log.lines), nvme.MAX_KERNEL_LINES)
        self.assertEqual(self.log.lines[0]['Message'], 'nvme0')
        self.assertEqual(self.log.dropped, 5)

    def test_unreadable(self) -> None:
        with self.assertRaisesRegex(NvmeError, 'cannot read the kernel log'):
            System(kmsg=self.kmsg.with_name('missing')).kernel_log()


if __name__ == '__main__':
    unittest.main()
