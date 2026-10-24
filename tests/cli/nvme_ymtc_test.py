#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the model the ymtc plugin decodes smart-log-add for: the one of
the PCI IDs of the controller the command opens.

Usage: python3 nvme_ymtc_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
import struct

from tests.cli.nvme_mock import MockTestCase, main

YMTC_VENDOR_ID = 0x1e49
PE511 = 0x1a28

NOT_SUPPORTED = 'Not support for parsing current product log!'

_YMTC_SMART_LOG_ID = 0xca


def smart_item(item_id, raw):
    """An item of the SMART log: ID, normalized value, raw value."""
    return bytes([item_id, 0, 0, 90, 0]) + raw.ljust(7, b'\0')


class YmtcCLITest(MockTestCase):
    """Answers the SMART log with items whose raw values hold 16 and 32
    bit fields, at the odd offsets of the log, and the other commands
    with zeroed data."""

    def setUp(self):
        super().setUp()
        self.server.logs[_YMTC_SMART_LOG_ID] = (
            smart_item(0xad, struct.pack('<HHH', 1, 2, 3)) +
            smart_item(0xc7, struct.pack('<I', 0x01020304)) +
            smart_item(0xeb, struct.pack('<BI', 5, 7)))

    def _smart_log_add(self, device):
        return self.nvme('ymtc', 'smart-log-add', device)

    def test_model(self):
        self.write_sysfs_pci_ctrl(vid=YMTC_VENDOR_ID, did=PE511)
        for device in (self.ctrl, self.ns):
            with self.subTest(device=device):
                result = self._smart_log_add(device)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn(NOT_SUPPORTED, result.stdout)
                self.assertIn('Additional Smart Log', result.stdout)

    def test_fields(self):
        self.write_sysfs_pci_ctrl(vid=YMTC_VENDOR_ID, did=PE511)
        result = self._smart_log_add(self.ctrl)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('runtime error', result.stderr)
        self.assertIn('min: 1, max: 2, avg: 3', result.stdout)
        self.assertIn(str(0x01020304), result.stdout)
        self.assertIn('5, time: 7', result.stdout)

    def test_other_vendor(self):
        self.write_sysfs_pci_ctrl(vid=0x1b96, did=PE511)
        result = self._smart_log_add(self.ctrl)
        self.assertIn(NOT_SUPPORTED, result.stdout)


if __name__ == '__main__':
    main()
