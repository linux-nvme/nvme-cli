#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the lm plugin: the Controller Data Queue commands it sends
(NVM Express Base Specification 2.4, section 5.2.3).

Usage: python3 nvme_lm_test.py <path-to-nvme-binary> <mock-lib>
"""
from tests.cli.nvme_mock import MockTestCase, main

OPC_CTRL_DATA_QUEUE = 0x45
SEL_CREATE_CDQ = 0


class LmCreateCdqTest(MockTestCase):

    def cdq_cmds(self):
        return self.server.admin_cmds(OPC_CTRL_DATA_QUEUE)

    def test_needs_consent(self):
        # the device would write the queue to memory nvme-cli can't map
        result = self.nvme('lm', 'create-cdq', self.ctrl, '--size=1024')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('consent required', result.stderr)
        self.assertEqual(self.cdq_cmds(), [])

    def test_create(self):
        self.assertOk(self.nvme('lm', 'create-cdq', self.ctrl,
                                '--size=1024', '--cntlid=3', '--consent'))
        cmd, = self.cdq_cmds()
        self.assertEqual(cmd.cdw10 & 0xff, SEL_CREATE_CDQ)
        # CDQSIZE in dwords
        self.assertEqual(cmd.cdw12, 1024)
        self.assertEqual(cmd.data_len, 4096)


if __name__ == '__main__':
    main()
