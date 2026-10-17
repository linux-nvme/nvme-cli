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

_NVME_ADMIN_GET_FEATURES = 0x0a


class SelMockIPCServer(MockIPCServer):

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.sel = []

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                     cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        if opcode == _NVME_ADMIN_GET_FEATURES:
            self.sel.append((cdw10 >> 8) & 0x7)
        self.send_response(conn, 0, payload=b"\x00" * req_len)


class SelCLITest(unittest.TestCase):

    DEVICE = '/dev/nvme0'

    def setUp(self):
        self.sysfs_dir = tempfile.mkdtemp(prefix='nvme-sel-sysfs-',
                                          dir='/tmp')
        self.base_dir = tempfile.mkdtemp(prefix='nvme-sel-base-', dir='/tmp')
        self.ipc_dir = tempfile.mkdtemp(prefix='nvme-sel-ipc-', dir='/tmp')
        self.ipc_sock_path = os.path.join(self.ipc_dir, "ipc.sock")

        self.server = SelMockIPCServer(self.ipc_sock_path)
        self.server.start()

        self.env = make_mock_env(_MOCK_LIB, self.ipc_sock_path)

    def tearDown(self):
        self.server.shutdown()
        self.server.join()

        shutil.rmtree(self.sysfs_dir, ignore_errors=True)
        shutil.rmtree(self.base_dir, ignore_errors=True)
        shutil.rmtree(self.ipc_dir, ignore_errors=True)

    def _get_feature(self, *args):
        return run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                        'get-feature', self.DEVICE, '--feature-id=2', *args)

    def test_sel_values(self):
        for arg, sel in (('--sel=0', 0), ('--sel=3', 3),
                         ('--sel=current', 0), ('--sel=default', 1),
                         ('--sel=saved', 2), ('--sel=supported', 3),
                         ('-ssaved', 2)):
            with self.subTest(arg=arg):
                self.server.sel.clear()
                result = self._get_feature(arg)
                self.assertEqual(result.returncode, 0,
                                 f'{arg} failed:\nstdout:\n{result.stdout}'
                                 f'\nstderr:\n{result.stderr}')
                self.assertEqual(self.server.sel, [sel])

    def test_sel_rejected(self):
        for arg in ('--sel=4', '--sel=7', '--sel=bogus'):
            with self.subTest(arg=arg):
                self.server.sel.clear()
                result = self._get_feature(arg)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('--sel', result.stderr)
                self.assertEqual(self.server.sel, [])


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]] + sys.argv[3:])
