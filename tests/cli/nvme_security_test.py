#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests security send and security recv: the Security Send and Security
Receive commands they send (NVM Express Base Specification 2.4, sections
5.2.28 and 5.2.29), and the data they transfer.

Usage: python3 nvme_security_test.py <path-to-nvme-binary> <mock-lib>
"""
import os

from tests.cli.nvme_mock import OPC_SECURITY_RECV, MockTestCase, main

OPC_SECURITY_SEND = 0x81
# SECP 31:24, SPSP1 23:16, SPSP0 15:8, NSSF 7:0
CDW10 = 0xea << 24 | 0x12 << 16 | 0x34 << 8 | 0x56
FIELDS = ['--namespace-id=1', '--secp=0xea', '--spsp=0x1234', '--nssf=0x56']


class SecuritySendTest(MockTestCase):

    def test_fields(self):
        data = bytes(range(64))
        path = os.path.join(self.tmp, 'payload')
        with open(path, 'wb') as f:
            f.write(data + b'more than the transfer length')
        self.assertOk(self.nvme('security', 'send', self.ctrl, *FIELDS,
                                '--tl=64', f'--file={path}'))
        cmd, = self.server.admin_cmds(OPC_SECURITY_SEND)
        self.assertEqual((cmd.nsid, cmd.cdw10, cmd.cdw11), (1, CDW10, 64))
        self.assertEqual(cmd.data, data)

    def test_stdin(self):
        self.assertOk(self.nvme('security', 'send', self.ctrl, '--tl=16',
                                stdin_data=b'S' * 16, encoding=None))
        cmd, = self.server.admin_cmds(OPC_SECURITY_SEND)
        self.assertEqual(cmd.data, b'S' * 16)

    def test_invalid(self):
        path = os.path.join(self.tmp, 'payload')
        with open(path, 'wb') as f:
            f.write(bytes(8))
        for args, message in ((['--tl=0'], '--tl unspecified or zero'),
                              (['--tl=16', f'--file={path}'],
                               'is smaller than --tl')):
            with self.subTest(args=args):
                result = self.nvme('security', 'send', self.ctrl, *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
        self.assertEqual(self.server.admin_cmds(OPC_SECURITY_SEND), [])


class SecurityRecvTest(MockTestCase):

    def test_fields(self):
        self.server.admin[OPC_SECURITY_RECV] = b'R' * 32
        result = self.assertOk(self.nvme('security', 'recv', self.ctrl,
                                         *FIELDS, '--al=32', '--size=32',
                                         '--raw-binary', encoding=None))
        cmd, = self.server.admin_cmds(OPC_SECURITY_RECV)
        self.assertEqual((cmd.nsid, cmd.cdw10, cmd.cdw11, cmd.data_len),
                         (1, CDW10, 32, 32))
        self.assertEqual(result.stdout, b'R' * 32)


if __name__ == '__main__':
    main()
