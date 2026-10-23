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
import os
import shutil
import struct
import sys
import tempfile
import unittest

from nvme_mock_ipc import (MockIPCServer, make_mock_env,
                           resolve_mock_lib_path, run_nvme)

_NVME_BIN = (sys.argv[1]
             if len(sys.argv) > 1 and not sys.argv[1].startswith('-')
             else 'nvme')
_MOCK_LIB = resolve_mock_lib_path("./libmock_nvme.so")

YMTC_VENDOR_ID = 0x1e49
PE511 = 0x1a28

NOT_SUPPORTED = 'Not support for parsing current product log!'

_NVME_ADMIN_GET_LOG_PAGE = 0x02
_YMTC_SMART_LOG_ID = 0xca


def smart_item(item_id, raw):
    """An item of the SMART log: ID, normalized value, raw value."""
    return bytes([item_id, 0, 0, 90, 0]) + raw.ljust(7, b'\0')


class YmtcMockIPCServer(MockIPCServer):
    """Answers the SMART log with items whose raw values hold 16 and 32
    bit fields, at the odd offsets of the log, and the other commands
    with zeroed data."""

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                     cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        payload = bytearray(req_len)
        if (opcode == _NVME_ADMIN_GET_LOG_PAGE and
                cdw10 & 0xff == _YMTC_SMART_LOG_ID):
            log = (smart_item(0xad, struct.pack('<HHH', 1, 2, 3)) +
                   smart_item(0xc7, struct.pack('<I', 0x01020304)) +
                   smart_item(0xeb, struct.pack('<BI', 5, 7)))
            payload[:len(log)] = log
        self.send_response(conn, 0, payload=bytes(payload))


class YmtcCLITest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nvme-ymtc-', dir='/tmp')
        self.sysfs_dir = os.path.join(self.tmp, 'sysfs')
        self.base_dir = os.path.join(self.tmp, 'base')
        os.makedirs(os.path.join(self.sysfs_dir, 'sys/class/nvme-subsystem'))
        os.mkdir(self.base_dir)
        sock = os.path.join(self.tmp, 'ipc.sock')
        self.server = YmtcMockIPCServer(sock)
        self.server.start()
        self.env = make_mock_env(_MOCK_LIB, sock)

    def tearDown(self):
        self.server.shutdown()
        self.server.join()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _pci_ids(self, vid, did):
        dev = os.path.join(self.sysfs_dir, 'sys/class/nvme/nvme0/device')
        os.makedirs(dev)
        for attr, value in (('vendor', vid), ('device', did)):
            with open(os.path.join(dev, attr), 'w') as f:
                f.write(f'0x{value:04x}\n')

    def _smart_log_add(self, device):
        return run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                        'ymtc', 'smart-log-add', device)

    def test_model(self):
        self._pci_ids(YMTC_VENDOR_ID, PE511)
        for device in ('/dev/nvme0', '/dev/nvme0n1'):
            with self.subTest(device=device):
                result = self._smart_log_add(device)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn(NOT_SUPPORTED, result.stdout)
                self.assertIn('Additional Smart Log', result.stdout)

    def test_fields(self):
        self._pci_ids(YMTC_VENDOR_ID, PE511)
        result = self._smart_log_add('/dev/nvme0')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('runtime error', result.stderr)
        self.assertIn('min: 1, max: 2, avg: 3', result.stdout)
        self.assertIn(str(0x01020304), result.stdout)
        self.assertIn('5, time: 7', result.stdout)

    def test_other_vendor(self):
        self._pci_ids(0x1b96, PE511)
        result = self._smart_log_add('/dev/nvme0')
        self.assertIn(NOT_SUPPORTED, result.stdout)


if __name__ == '__main__':
    unittest.main(argv=sys.argv[:1])
