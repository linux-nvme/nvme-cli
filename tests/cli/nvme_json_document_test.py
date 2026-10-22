#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for the JSON document of a command line: nvme_main() prints it
once at the end, also for a command which parses its options twice.

Usage: python3 nvme_json_document_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

from nvme_mock_ipc import MockIPCServer, make_mock_env, resolve_mock_lib_path, run_nvme

_NVME_BIN = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else 'nvme'
_MOCK_LIB = resolve_mock_lib_path("./libmock_nvme.so")


class JSONDocumentTest(unittest.TestCase):

    def setUp(self):
        self.sysfs_dir = tempfile.mkdtemp(prefix='nvme-json-sysfs-', dir='/tmp')
        self.base_dir = tempfile.mkdtemp(prefix='nvme-json-base-', dir='/tmp')
        self.ipc_dir = tempfile.mkdtemp(prefix='nvme-json-ipc-', dir='/tmp')
        # without them, a topology scan fails
        for d in ('sys/class/nvme-subsystem', 'sys/class/nvme'):
            os.makedirs(os.path.join(self.sysfs_dir, d))
        self.ipc_sock_path = os.path.join(self.ipc_dir, "ipc.sock")
        # every command succeeds with zeroed data: an unknown drive
        self.server = MockIPCServer(self.ipc_sock_path)
        self.server.start()
        self.env = make_mock_env(_MOCK_LIB, self.ipc_sock_path)

    def tearDown(self):
        self.server.shutdown()
        self.server.join()
        for d in (self.sysfs_dir, self.base_dir, self.ipc_dir):
            shutil.rmtree(d, ignore_errors=True)

    def test_parsed_twice(self):
        # sndk vs-fw-activate-history falls back to the wdc command for a
        # drive without the C2 log, which parses the options again
        result = run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                          'sndk', 'vs-fw-activate-history', '/dev/nvme0',
                          '-o', 'json')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout),
                         {'error': 'ERROR: WDC: unsupported device for this command'},
                         result.stderr)


if __name__ == '__main__':
    unittest.main(argv=sys.argv[:1])
