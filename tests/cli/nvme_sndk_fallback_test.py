#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for the sandisk commands which run the wdc ones for older drives:
they hand over the device they opened, instead of parsing the command
line again.

Usage: python3 nvme_sndk_fallback_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
import os

from tests.cli.nvme_mock import MockTestCase, main

# libnvme reports it with --verbose for each global context it creates
_HOSTID_NOTICE = 'no stable host identifier'
_WDC_UNSUPPORTED = 'ERROR: WDC: unsupported device for this command'


class SndkFallbackTest(MockTestCase):

    def setUp(self):
        super().setUp()
        # A WDC controller the sandisk plugin knows no capabilities of,
        # so that each command falls back to the wdc one
        self.write_sysfs_pci_ctrl(vid=0x1b96, did=0x0001)

    def _fallback(self, command, *options):
        result = self.nvme('sndk', command, self.ctrl, *options, '--verbose')
        self.assertIn(_WDC_UNSUPPORTED, result.stderr)
        # one global context: the command line was parsed once
        self.assertEqual(result.stderr.count(_HOSTID_NOTICE), 1,
                         result.stderr)

    def test_vs_internal_log(self):
        self._fallback('vs-internal-log', '--output-file',
                       os.path.join(self.base_dir, 'log.bin'))

    def test_drive_resize(self):
        self._fallback('drive-resize', '--size=1')

    def test_vs_fw_activate_history(self):
        self._fallback('vs-fw-activate-history')

    def test_clear_fw_activate_history(self):
        self._fallback('clear-fw-activate-history')


if __name__ == '__main__':
    main()
