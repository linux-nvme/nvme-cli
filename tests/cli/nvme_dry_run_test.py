#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests that --dry-run keeps the commands which do not send an NVMe
command from changing the device: reset, subsystem-reset and ns-rescan
issue a controller ioctl, which libmock_nvme.c forwards raw.

Usage: python3 nvme_dry_run_test.py <path-to-nvme-binary> <path-to-mock-lib>
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

# linux/nvme_ioctl.h: _IO('N', nr)
_NVME_IOC_TYPE = ord('N')
_NVME_IOCTLS = {
    0x44: 'RESET',
    0x45: 'SUBSYS_RESET',
    0x46: 'RESCAN',
}


class DryRunMockIPCServer(MockIPCServer):

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.ioctls = []

    def handle_raw_ioctl(self, conn, fd, ioc, payload):
        if ioc.type == _NVME_IOC_TYPE and ioc.nr in _NVME_IOCTLS:
            self.ioctls.append(_NVME_IOCTLS[ioc.nr])
            self.send_response(conn, 0)
        else:
            super().handle_raw_ioctl(conn, fd, ioc, payload)


class DryRunCLITest(unittest.TestCase):

    DEVICE = '/dev/nvme0'

    def setUp(self):
        self.sysfs_dir = tempfile.mkdtemp(prefix='nvme-dry-sysfs-',
                                          dir='/tmp')
        self.base_dir = tempfile.mkdtemp(prefix='nvme-dry-base-', dir='/tmp')
        self.ipc_dir = tempfile.mkdtemp(prefix='nvme-dry-ipc-', dir='/tmp')
        self.ipc_sock_path = os.path.join(self.ipc_dir, "ipc.sock")

        self.server = DryRunMockIPCServer(self.ipc_sock_path)
        self.server.start()

        self.env = make_mock_env(_MOCK_LIB, self.ipc_sock_path)

    def tearDown(self):
        self.server.shutdown()
        self.server.join()

        shutil.rmtree(self.sysfs_dir, ignore_errors=True)
        shutil.rmtree(self.base_dir, ignore_errors=True)
        shutil.rmtree(self.ipc_dir, ignore_errors=True)

    def _run(self, *args):
        result = run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                          *args)
        self.assertEqual(result.returncode, 0,
                         f'{args} failed:\nstdout:\n{result.stdout}\n'
                         f'stderr:\n{result.stderr}')
        return result

    def _check(self, command, ioctl):
        # Without --dry-run the ioctl reaches the device, so the test
        # would notice it with --dry-run as well.
        self._run(command, self.DEVICE)
        self.assertEqual(self.server.ioctls, [ioctl])

        self.server.ioctls.clear()
        self._run(command, self.DEVICE, '--dry-run')
        self.assertEqual(self.server.ioctls, [])

    def test_reset(self):
        self._check('reset', 'RESET')

    def test_subsystem_reset(self):
        self._check('subsystem-reset', 'SUBSYS_RESET')

    def test_ns_rescan(self):
        self._check('ns-rescan', 'RESCAN')


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]] + sys.argv[3:])
