#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the LBA formats format takes from Identify Namespace: an LBA data
size (LBADS) the device reports is a shift count, which must not shift
past the type it shifts.

Usage: python3 nvme_format_test.py <path-to-nvme-binary> <path-to-mock-lib>
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
# NLBAF and the LBA format table of Identify Namespace
_ID_NS_NLBAF = 25
_ID_NS_LBAF = 128


class FormatMockIPCServer(MockIPCServer):
    """A namespace with the LBA data sizes @lbads, which answers the other
    commands with success and zeroed data."""

    def __init__(self, sock_path, lbads):
        super().__init__(sock_path)
        self.lbads = lbads

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                     cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        payload = bytearray(req_len)
        if (opcode == _NVME_ADMIN_IDENTIFY and req_len >= 4096 and
                cdw10 & 0xff == _NVME_IDENTIFY_CNS_NS):
            payload[_ID_NS_NLBAF] = len(self.lbads) - 1
            for i, ds in enumerate(self.lbads):
                struct.pack_into('<HBB', payload, _ID_NS_LBAF + i * 4,
                                 0, ds, 0)
        self.send_response(conn, 0, payload=bytes(payload))


class FormatCLITest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nvme-format-', dir='/tmp')
        self.sysfs_dir = os.path.join(self.tmp, 'sysfs')
        self.base_dir = os.path.join(self.tmp, 'base')
        os.mkdir(self.sysfs_dir)
        os.mkdir(self.base_dir)
        self.ipc_sock_path = os.path.join(self.tmp, "ipc.sock")
        self.server = None

    def tearDown(self):
        if self.server:
            self.server.shutdown()
            self.server.join()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _format(self, lbads, *args):
        self.server = FormatMockIPCServer(self.ipc_sock_path, lbads)
        self.server.start()
        env = make_mock_env(_MOCK_LIB, self.ipc_sock_path)
        return run_nvme(_NVME_BIN, env, self.sysfs_dir, self.base_dir,
                        'format', *args, '--force')

    def test_block_size_lbads_too_large(self):
        # 1ULL << 64 is no block size, and no shift
        result = self._format([9, 64], '/dev/nvme0', '--namespace-id=1',
                              '--block-size=4096')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('LBAF corresponding to given block size 4096 not '
                      'found', result.stderr)
        self.assertNotIn('runtime error', result.stderr)

    def test_block_size_found(self):
        result = self._format([9, 12], '/dev/nvme0', '--namespace-id=1',
                              '--block-size=4096')
        self.assertNotIn('not found', result.stderr)

    def test_new_block_size_lbads_too_large(self):
        # The block size of the namespace block device after the format
        result = self._format([9, 40], '/dev/nvme0n1', '--namespace-id=1',
                              '--lbaf=1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('invalid LBA data size 40', result.stderr)
        self.assertNotIn('runtime error', result.stderr)


if __name__ == '__main__':
    unittest.main(argv=sys.argv[:1])
