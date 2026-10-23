#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the LBA data size zns zone-append takes from Identify Namespace:
a shift count from the device, which must not shift past the type it
shifts.

Usage: python3 nvme_zns_append_test.py <path-to-nvme-binary> <mock-lib>
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

_NVME_ADMIN_IDENTIFY = 0x06
_NVME_IDENTIFY_CNS_NS = 0x00
# The LBA data size of LBA format 0 of Identify Namespace
_ID_NS_LBAF0_DS = 128 + 2


class ZnsMockIPCServer(MockIPCServer):
    """A namespace whose LBA format 0 has the data size @lbads."""

    lbads = 9

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                     cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        payload = bytearray(req_len)
        if (opcode == _NVME_ADMIN_IDENTIFY and req_len >= 4096 and
                cdw10 & 0xff == _NVME_IDENTIFY_CNS_NS):
            struct.pack_into('B', payload, _ID_NS_LBAF0_DS, self.lbads)
        self.send_response(conn, 0, payload=bytes(payload))


class ZnsAppendCLITest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nvme-zns-', dir='/tmp')
        self.sysfs_dir = os.path.join(self.tmp, 'sysfs')
        self.base_dir = os.path.join(self.tmp, 'base')
        os.mkdir(self.sysfs_dir)
        os.mkdir(self.base_dir)
        sock = os.path.join(self.tmp, 'ipc.sock')
        self.server = ZnsMockIPCServer(sock)
        self.server.start()
        self.env = make_mock_env(_MOCK_LIB, sock)

    def tearDown(self):
        self.server.shutdown()
        self.server.join()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _append(self, lbads):
        self.server.lbads = lbads
        return run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                        'zns', 'zone-append', '/dev/nvme0n1',
                        '--namespace-id=1', '--data-size=4096')

    def test_lbads_too_large(self):
        result = self._append(40)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('invalid LBA data size 40', result.stderr)
        self.assertNotIn('runtime error', result.stderr)

    def test_unaligned(self):
        # 4096 bytes are no multiple of an 8 KiB LBA
        result = self._append(13)
        self.assertIn('not aligned to lba size:0x2000', result.stderr)


if __name__ == '__main__':
    unittest.main(argv=sys.argv[:1])
