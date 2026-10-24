#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests fw download and fw commit: the Firmware Image Download and
Firmware Commit commands they send (NVM Express Base Specification 2.4,
sections 5.2.8 and 5.2.9), how fw download splits an image into
transfers, and how both handle the errors of the controller.

Usage: python3 nvme_fw_test.py <path-to-nvme-binary> <mock-lib>
"""
import os

from tests.cli.nvme_mock import (CNS_CTRL, OPC_FW_COMMIT, OPC_FW_DOWNLOAD,
                                 MockTestCase, Reply, id_ctrl, main)

SC_INTERNAL = 0x006
DNR = 1 << 14
SC_OVERLAPPING_RANGE = 0x114
# FRMW: Multiple Update Detection Support
FRMW_MUDS = 1 << 5


class FwDownloadTest(MockTestCase):

    def image(self, size):
        """A firmware image file of @size bytes, each dword its index"""
        data = b''.join(i.to_bytes(4, 'little') for i in range(size // 4))
        path = os.path.join(self.tmp, 'fw.bin')
        with open(path, 'wb') as f:
            f.write(data)
        return path, data

    def downloads(self):
        return self.server.admin_cmds(OPC_FW_DOWNLOAD)

    def assertTransfers(self, data, transfers, offset=0):
        """The downloads are of the (offset, length) @transfers, offset
        and length in bytes, with the data of the image @data"""
        self.assertEqual(
            [(c.cdw11, c.cdw10, c.data_len) for c in self.downloads()],
            [((offset + o) // 4, n // 4 - 1, n) for o, n in transfers])
        for c, (o, n) in zip(self.downloads(), transfers):
            self.assertEqual(c.data, data[o:o + n])

    def test_transfers_of_4k_by_default(self):
        path, data = self.image(12288)
        self.assertOk(self.nvme('fw', 'download', self.ctrl, f'--fw={path}'))
        self.assertTransfers(data, [(0, 4096), (4096, 4096), (8192, 4096)])

    def test_transfers_of_the_update_granularity(self):
        """FWUG is in units of 4 KiB; the last transfer is shorter"""
        self.server.identify[CNS_CTRL] = id_ctrl(fwug=2)
        path, data = self.image(12288)
        self.assertOk(self.nvme('fw', 'download', self.ctrl, f'--fw={path}'))
        self.assertTransfers(data, [(0, 8192), (8192, 4096)])

    def test_xfer(self):
        path, data = self.image(16384)
        self.assertOk(self.nvme('fw', 'download', self.ctrl, f'--fw={path}',
                                '--xfer=8192'))
        self.assertTransfers(data, [(0, 8192), (8192, 8192)])
        # no need for the update granularity
        self.assertEqual(self.server.identifies(), [])

    def test_xfer_not_4k_aligned(self):
        path, data = self.image(8192)
        self.assertOk(self.nvme('fw', 'download', self.ctrl, f'--fw={path}',
                                '--xfer=1000'))
        self.assertTransfers(data, [(0, 4096), (4096, 4096)])

    def test_offset(self):
        """--offset is in dwords"""
        path, data = self.image(8192)
        self.assertOk(self.nvme('fw', 'download', self.ctrl, f'--fw={path}',
                                '--offset=0x100'))
        self.assertTransfers(data, [(0, 4096), (4096, 4096)], offset=0x400)

    def test_stream(self):
        path, data = self.image(10240)
        self.assertOk(self.nvme('fw', 'download', self.ctrl, f'--fw={path}',
                                '--stream'))
        self.assertTransfers(data, [(0, 4096), (4096, 4096), (8192, 2048)])

    def test_invalid_image_size(self):
        for size in (0, 4094):
            with self.subTest(size=size):
                path = os.path.join(self.tmp, 'fw.bin')
                with open(path, 'wb') as f:
                    f.write(bytes(size))
                result = self.nvme('fw', 'download', self.ctrl,
                                   f'--fw={path}')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'Invalid size:{size}', result.stderr)
        self.assertEqual(self.downloads(), [])

    def test_retry(self):
        """A transfer which fails is tried three times, unless the
        controller says Do Not Retry"""
        path, _ = self.image(8192)
        for status, tries in ((SC_INTERNAL, 3), (SC_INTERNAL | DNR, 1)):
            with self.subTest(status=status):
                self.server.commands.clear()
                self.server.admin[OPC_FW_DOWNLOAD] = status
                result = self.nvme('fw', 'download', self.ctrl,
                                   f'--fw={path}')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('error on offset 0x00000000', result.stderr)
                self.assertEqual(len(self.downloads()), tries)

    def test_overlapping_range(self):
        path, data = self.image(8192)
        self.server.admin[OPC_FW_DOWNLOAD] = SC_OVERLAPPING_RANGE | DNR
        result = self.nvme('fw', 'download', self.ctrl, f'--fw={path}')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--ignore-ovr', result.stderr)
        self.assertEqual(len(self.downloads()), 1)

        self.server.commands.clear()
        self.assertOk(self.nvme('fw', 'download', self.ctrl, f'--fw={path}',
                                '--ignore-ovr'))
        self.assertTransfers(data, [(0, 4096), (4096, 4096)])


class FwCommitTest(MockTestCase):

    def commit(self, *args):
        self.assertOk(self.nvme('fw', 'commit', self.ctrl, *args))
        cmd, = self.server.admin_cmds(OPC_FW_COMMIT)
        return cmd

    def test_fields(self):
        cases = [
            (['--slot=2', '--action=replace-and-activate'], 2 | 1 << 3),
            (['--slot=7', '--action=3'], 7 | 3 << 3),
            (['--action=replace-boot-partition', '--bpid=1'],
             6 << 3 | 1 << 31),
            (['--action=activate-boot-partition'], 7 << 3),
        ]
        for args, cdw10 in cases:
            with self.subTest(args=args):
                self.server.commands.clear()
                self.assertEqual(self.commit(*args).cdw10, cdw10)

    def test_activate_alias(self):
        self.assertOk(self.nvme('fw', 'activate', self.ctrl, '--slot=1',
                                '--action=2'))
        cmd, = self.server.admin_cmds(OPC_FW_COMMIT)
        self.assertEqual(cmd.cdw10, 1 | 2 << 3)

    def test_invalid_options(self):
        cases = [
            (['--slot=8'], 'invalid slot:8'),
            (['--action=4'], 'invalid action:4'),
            (['--action=8'], 'invalid action:8'),
            (['--bpid=2'], 'invalid boot partition id:2'),
        ]
        for args, message in cases:
            with self.subTest(args=args):
                result = self.nvme('fw', 'commit', self.ctrl, *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
        self.assertEqual(self.server.admin_cmds(OPC_FW_COMMIT), [])

    def test_multiple_update_detected(self):
        self.server.admin[OPC_FW_COMMIT] = Reply(result=0x3)
        for frmw, shown in ((FRMW_MUDS, True), (0, False)):
            with self.subTest(frmw=frmw):
                self.server.identify[CNS_CTRL] = id_ctrl(frmw=frmw)
                result = self.assertOk(self.nvme('fw', 'commit', self.ctrl))
                self.assertEqual('Multiple Update Detected (MUD) Value: 0x3'
                                 in result.stdout, shown)
                self.assertEqual('Management Endpoint' in result.stdout,
                                 shown)


if __name__ == '__main__':
    main()
