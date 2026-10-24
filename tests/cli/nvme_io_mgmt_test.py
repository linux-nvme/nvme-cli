#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the I/O Management Send and Receive commands of the io-mgmt
plugin against the NVM Express NVM Command Set Specification 1.3.

Usage: python3 nvme_io_mgmt_test.py <path-to-nvme-binary> <mock-lib>
"""
import os
import struct

from tests.cli.nvme_mock import NVME_IOCTL_ID, MockTestCase, Reply, main

OPC_IO_MGMT_RECV = 0x12
OPC_IO_MGMT_SEND = 0x1d

MO_RUH_STATUS = 1
MO_RUH_UPDATE = 1


class IoMgmtTest(MockTestCase):

    def setUp(self):
        super().setUp()
        self.server.ioctls[NVME_IOCTL_ID] = Reply(status=1)

    def io_mgmt(self, opcode, *args):
        result = self.nvme('io-mgmt', *args)
        if 'invalid sub-command' in result.stderr:
            self.skipTest('io-mgmt plugin not built')
        self.assertOk(result)
        cmd, = self.server.io_cmds(opcode)
        return result, cmd

    def test_send(self):
        """Reclaim Unit Handle Update of two Placement Identifiers"""
        data = struct.pack('<HH', 3, 0x101)
        path = os.path.join(self.tmp, 'pids')
        with open(path, 'wb') as f:
            f.write(data)
        _, cmd = self.io_mgmt(OPC_IO_MGMT_SEND, 'send', self.ns,
                              f'--mo={MO_RUH_UPDATE}', '--mos=1',
                              f'--data={path}', f'--data-len={len(data)}')
        # MO 7:0; MOS 31:16, the 0's based number of Placement Identifiers
        self.assertEqual((cmd.nsid, cmd.cdw10), (1, 1 << 16 | MO_RUH_UPDATE))
        self.assertEqual(cmd.data, data)

    def test_send_namespace_id(self):
        _, cmd = self.io_mgmt(OPC_IO_MGMT_SEND, 'send', self.ctrl,
                              '--namespace-id=3', '--mo=0')
        self.assertEqual((cmd.nsid, cmd.cdw10, cmd.data_len), (3, 0, 0))

    def test_recv(self):
        """Reclaim Unit Handle Status, dumped to stdout"""
        self.server.io[OPC_IO_MGMT_RECV] = bytes(range(0x41, 0x51))
        result, cmd = self.io_mgmt(OPC_IO_MGMT_RECV, 'recv', self.ns,
                                   f'--mo={MO_RUH_STATUS}', '--mos=2',
                                   '--data-len=16')
        # MO 7:0, MOS 31:16; NUMD, 0's based
        self.assertEqual((cmd.nsid, cmd.cdw10, cmd.cdw11, cmd.data_len),
                         (1, 2 << 16 | MO_RUH_STATUS, 3, 16))
        self.assertIn('ABCDEFGHIJKLMNOP', result.stdout)

    def test_recv_data_len_required(self):
        result = self.nvme('io-mgmt', 'recv', self.ns, f'--mo={MO_RUH_STATUS}')
        if 'invalid sub-command' in result.stderr:
            self.skipTest('io-mgmt plugin not built')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('data length (--data-len) has to be given',
                      result.stderr)
        self.assertEqual(self.server.io_cmds(OPC_IO_MGMT_RECV), [])

    def test_recv_file(self):
        """The data received, written to a file"""
        data = bytes(range(16))
        self.server.io[OPC_IO_MGMT_RECV] = data
        path = os.path.join(self.tmp, 'status')
        self.io_mgmt(OPC_IO_MGMT_RECV, 'recv', self.ns,
                     f'--mo={MO_RUH_STATUS}', '--data-len=16',
                     f'--data={path}')
        with open(path, 'rb') as f:
            self.assertEqual(f.read(), data)

    def test_recv_file_short_write(self):
        """A write of the data cut short fails the command"""
        self.server.io[OPC_IO_MGMT_RECV] = bytes(range(256)) * 16
        path = os.path.join(self.tmp, 'status')
        result = self.nvme('io-mgmt', 'recv', self.ns,
                           f'--mo={MO_RUH_STATUS}', '--data-len=4096',
                           f'--data={path}', file_size_limit=1)
        if 'invalid sub-command' in result.stderr:
            self.skipTest('io-mgmt plugin not built')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('write', result.stderr)
        self.assertLess(os.path.getsize(path), 4096)


if __name__ == '__main__':
    main()
