#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the fields of the Directive Send command dir send sends, against
the NVM Express Base Specification 2.3.

Usage: python3 nvme_dir_send_test.py <path-to-nvme-binary> <mock-lib>
"""
from tests.cli.nvme_mock import NVME_IOCTL_ID, MockTestCase, Reply, main

OPC_DIRECTIVE_SEND = 0x19

DTYPE_IDENTIFY = 0
DTYPE_STREAMS = 1
DOPER_IDENTIFY_ENDIR = 1
DOPER_STREAMS_RELEASE_ID = 1
DOPER_STREAMS_RELEASE_RES = 2


class DirSendTest(MockTestCase):

    def send(self, *args, device=None):
        result = self.nvme('dir', 'send', device or self.ctrl, *args)
        if 'invalid sub-command' in result.stderr:
            self.skipTest('dir plugin not built')
        self.assertOk(result)
        cmd, = self.server.admin_cmds(OPC_DIRECTIVE_SEND)
        return cmd

    def test_enable_directive(self):
        """Enable Directive: the target directive type and Enable
        Directive bit in CDW12"""
        for endir in (0, 1):
            with self.subTest(endir=endir):
                self.server.commands.clear()
                cmd = self.send('--namespace-id=2',
                                f'--dir-type={DTYPE_IDENTIFY}',
                                f'--dir-oper={DOPER_IDENTIFY_ENDIR}',
                                f'--target-dir={DTYPE_STREAMS}',
                                f'--endir={endir}')
                # DOPER 7:0, DTYPE 15:8, DSPEC 31:16; TDTYPE 15:8, ENDIR 0
                self.assertEqual((cmd.nsid, cmd.cdw11, cmd.cdw12),
                                 (2, DOPER_IDENTIFY_ENDIR,
                                  DTYPE_STREAMS << 8 | endir))
                self.assertEqual((cmd.cdw10, cmd.data_len), (0, 0))

    def test_streams_release(self):
        for doper, dspec in ((DOPER_STREAMS_RELEASE_ID, 7),
                             (DOPER_STREAMS_RELEASE_RES, 0)):
            with self.subTest(doper=doper):
                self.server.commands.clear()
                cmd = self.send('--namespace-id=1',
                                f'--dir-type={DTYPE_STREAMS}',
                                f'--dir-oper={doper}', f'--dir-spec={dspec}')
                self.assertEqual((cmd.cdw11, cmd.cdw12),
                                 (dspec << 16 | DTYPE_STREAMS << 8 | doper,
                                  0))

    def test_namespace_id(self):
        """The namespace of a namespace device, namespace 1 of a
        controller device, unless --namespace-id is given"""
        self.server.ioctls[NVME_IOCTL_ID] = Reply(status=2)
        for device, args, nsid in ((self.ns, [], 2), (self.ctrl, [], 1),
                                   (self.ns, ['--namespace-id=3'], 3)):
            with self.subTest(device=device, args=args):
                self.server.commands.clear()
                cmd = self.send(f'--dir-type={DTYPE_STREAMS}',
                                f'--dir-oper={DOPER_STREAMS_RELEASE_RES}',
                                *args, device=device)
                self.assertEqual(cmd.nsid, nsid)

    def test_invalid(self):
        cases = [
            ([f'--dir-type={DTYPE_IDENTIFY}',
              f'--dir-oper={DOPER_IDENTIFY_ENDIR}'],
             'target-dir required param'),
            ([f'--dir-type={DTYPE_IDENTIFY}', '--dir-oper=2'],
             'invalid directive operations for Identify Directives'),
            ([f'--dir-type={DTYPE_STREAMS}', '--dir-oper=3'],
             'invalid directive operations for Streams Directives'),
            (['--dir-type=2'], 'invalid directive type'),
        ]
        for args, message in cases:
            with self.subTest(args=args):
                self.server.commands.clear()
                result = self.nvme('dir', 'send', self.ctrl, *args)
                if 'invalid sub-command' in result.stderr:
                    self.skipTest('dir plugin not built')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertEqual(
                    self.server.admin_cmds(OPC_DIRECTIVE_SEND), [])


if __name__ == '__main__':
    main()
