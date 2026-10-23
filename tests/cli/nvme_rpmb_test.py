#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the files of the rpmb plugin: an absolute --msgfile names the
file to write as it is, not one below the current directory.

Usage: python3 nvme_rpmb_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
import os
import shutil
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
# RPMBS of the Identify Controller data structure
_ID_CTRL_RPMBS = 312

# struct rpmb_config_block_t
_CONFIG_BLOCK_SIZE = 512


class RpmbMockIPCServer(MockIPCServer):
    """A controller with one RPMB target, which answers each command with
    success and zeroed data."""

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                     cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        payload = bytearray(req_len)
        if opcode == _NVME_ADMIN_IDENTIFY and req_len > _ID_CTRL_RPMBS:
            payload[_ID_CTRL_RPMBS] = 1
        self.send_response(conn, 0, payload=bytes(payload))


class RpmbCLITest(unittest.TestCase):

    DEVICE = '/dev/nvme0'

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nvme-rpmb-', dir='/tmp')
        self.sysfs_dir = os.path.join(self.tmp, 'sysfs')
        self.base_dir = os.path.join(self.tmp, 'base')
        self.out = os.path.join(self.tmp, 'out')
        for d in (self.sysfs_dir, self.base_dir, self.out):
            os.mkdir(d)
        self.ipc_sock_path = os.path.join(self.tmp, "ipc.sock")

        self.server = RpmbMockIPCServer(self.ipc_sock_path)
        self.server.start()

        self.env = make_mock_env(_MOCK_LIB, self.ipc_sock_path)

    def tearDown(self):
        self.server.shutdown()
        self.server.join()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _read_config(self, msgfile):
        return run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                        'rpmb', 'read-config', self.DEVICE,
                        f'--msgfile={msgfile}')

    def test_absolute_msgfile(self):
        path = os.path.join(self.out, 'config.bin')
        result = self._read_config(path)
        self.assertIn(f'Saving received config data to {path}',
                      result.stdout + result.stderr)
        self.assertEqual(os.path.getsize(path), _CONFIG_BLOCK_SIZE)


if __name__ == '__main__':
    unittest.main(argv=sys.argv[:1])
