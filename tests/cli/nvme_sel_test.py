#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the Select option of get-feature: the numbers 0 to 3 and their
names current, default, saved and supported end up in the SEL field of
the Get Features command, other numbers are rejected before a command is
sent.

Usage: python3 nvme_sel_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
from tests.cli.nvme_mock import OPC_GET_FEATURES, MockTestCase, main


class SelCLITest(MockTestCase):

    def _get_feature(self, *args):
        return self.nvme('get-feature', self.ctrl, '--feature-id=2', *args)

    def _sel(self):
        return [c.sel for c in self.server.admin_cmds(OPC_GET_FEATURES)]

    def test_sel_values(self):
        for arg, sel in (('--sel=0', 0), ('--sel=3', 3),
                         ('--sel=current', 0), ('--sel=default', 1),
                         ('--sel=saved', 2), ('--sel=supported', 3),
                         ('-ssaved', 2)):
            with self.subTest(arg=arg):
                self.server.commands.clear()
                self.assertOk(self._get_feature(arg))
                self.assertEqual(self._sel(), [sel])

    def test_sel_rejected(self):
        for arg in ('--sel=4', '--sel=7', '--sel=bogus'):
            with self.subTest(arg=arg):
                self.server.commands.clear()
                result = self._get_feature(arg)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('--sel', result.stderr)
                self.assertEqual(self._sel(), [])


if __name__ == '__main__':
    main()
