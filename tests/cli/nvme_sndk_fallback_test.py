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
import shutil
import sys
import tempfile
import unittest

from nvme_mock_ipc import MockIPCServer, make_mock_env, resolve_mock_lib_path, run_nvme

_NVME_BIN = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else 'nvme'
_MOCK_LIB = resolve_mock_lib_path("./libmock_nvme.so")

# libnvme reports it with --verbose for each global context it creates
_HOSTID_NOTICE = 'no stable host identifier'
_WDC_UNSUPPORTED = 'ERROR: WDC: unsupported device for this command'


class SndkFallbackTest(unittest.TestCase):

    def setUp(self):
        self.sysfs_dir = tempfile.mkdtemp(prefix='nvme-sndk-sysfs-', dir='/tmp')
        self.base_dir = tempfile.mkdtemp(prefix='nvme-sndk-base-', dir='/tmp')
        self.ipc_dir = tempfile.mkdtemp(prefix='nvme-sndk-ipc-', dir='/tmp')
        # A WDC controller the sandisk plugin knows no capabilities of,
        # so that each command falls back to the wdc one
        dev = os.path.join(self.sysfs_dir, 'sys/class/nvme/nvme0/device')
        os.makedirs(dev)
        os.makedirs(os.path.join(self.sysfs_dir, 'sys/class/nvme-subsystem'))
        for attr, value in (('vendor', '0x1b96'), ('device', '0x0001'),
                            ('subsystem_vendor', '0x1b96'),
                            ('subsystem_device', '0x0001'),
                            ('class', '0x010802')):
            with open(os.path.join(dev, attr), 'w') as f:
                f.write(value + '\n')
        self.ipc_sock_path = os.path.join(self.ipc_dir, "ipc.sock")
        self.server = MockIPCServer(self.ipc_sock_path)
        self.server.start()
        self.env = make_mock_env(_MOCK_LIB, self.ipc_sock_path)

    def tearDown(self):
        self.server.shutdown()
        self.server.join()
        for d in (self.sysfs_dir, self.base_dir, self.ipc_dir):
            shutil.rmtree(d, ignore_errors=True)

    def _fallback(self, command, *options):
        result = run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                          'sndk', command, '/dev/nvme0', *options, '--verbose')
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
    unittest.main(argv=sys.argv[:1])
