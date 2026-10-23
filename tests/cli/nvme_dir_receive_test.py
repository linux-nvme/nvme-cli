#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the verbose output of dir receive with a --data-len smaller than
the data structure it decodes: it decodes only what the buffer holds,
e.g. no more Stream Identifiers than fit, whatever Open Stream Count the
device reports.

Usage: python3 nvme_dir_receive_test.py <path-to-nvme-binary> <mock-lib>
"""
import json
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

_NVME_ADMIN_DIRECTIVE_RECV = 0x1a

DTYPE_IDENTIFY = 0
DTYPE_STREAMS = 1
DOPER_STREAMS_PARAM = 1
DOPER_STREAMS_STATUS = 2

TOO_SHORT = 'directive data too short'


class DirMockIPCServer(MockIPCServer):
    """Answers Directive Receive with a Streams status of @osc open
    streams, as much of it as the command reads."""

    osc = 0xffff

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                     cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        data = bytearray(req_len)
        if opcode == _NVME_ADMIN_DIRECTIVE_RECV and req_len >= 2:
            struct.pack_into('<H', data, 0, self.osc)
            for i in range(min(self.osc, (req_len - 2) // 2)):
                struct.pack_into('<H', data, 2 + 2 * i, i + 1)
        self.send_response(conn, 0, payload=bytes(data))


class DirReceiveCLITest(unittest.TestCase):

    DEVICE = '/dev/nvme0'

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nvme-dir-', dir='/tmp')
        self.sysfs_dir = os.path.join(self.tmp, 'sysfs')
        self.base_dir = os.path.join(self.tmp, 'base')
        os.mkdir(self.sysfs_dir)
        os.mkdir(self.base_dir)
        self.server = DirMockIPCServer(os.path.join(self.tmp, 'ipc.sock'))
        self.server.start()
        self.env = make_mock_env(_MOCK_LIB, os.path.join(self.tmp,
                                                         'ipc.sock'))

    def tearDown(self):
        self.server.shutdown()
        self.server.join()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _receive(self, dtype, doper, *args):
        result = run_nvme(_NVME_BIN, self.env, self.sysfs_dir,
                          self.base_dir, 'dir', 'receive', self.DEVICE,
                          f'--dir-type={dtype}', f'--dir-oper={doper}',
                          '--verbose', *args)
        self.assertNotIn('ERROR: AddressSanitizer', result.stderr)
        return result

    def test_status_short_buffer(self):
        result = self._receive(DTYPE_STREAMS, DOPER_STREAMS_STATUS,
                               '--data-len=8')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('65535', result.stdout)
        # 8 bytes: the count and three identifiers
        self.assertEqual(result.stdout.count('Stream Identifier'), 3)

    def test_status_short_buffer_json(self):
        result = self._receive(DTYPE_STREAMS, DOPER_STREAMS_STATUS,
                               '--data-len=8', '--output-format=json')
        self.assertEqual(result.returncode, 0, result.stderr)
        doc = json.loads(result.stdout)
        self.assertEqual(doc['Open Stream Count'], 0xffff)
        sids = [k for k in doc if k.startswith('Stream Identifier')]
        self.assertEqual(len(sids), 3)

    def test_status_default_buffer(self):
        self.server.osc = 2
        result = self._receive(DTYPE_STREAMS, DOPER_STREAMS_STATUS)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('Stream Identifier'), 2)

    def test_status_too_short(self):
        result = self._receive(DTYPE_STREAMS, DOPER_STREAMS_STATUS,
                               '--data-len=1')
        self.assertIn(TOO_SHORT, result.stderr)

    def test_params_too_short(self):
        result = self._receive(DTYPE_STREAMS, DOPER_STREAMS_PARAM,
                               '--data-len=8')
        self.assertIn(TOO_SHORT, result.stderr)

    def test_identify_too_short(self):
        result = self._receive(DTYPE_IDENTIFY, 1, '--data-len=16')
        self.assertIn(TOO_SHORT, result.stderr)


if __name__ == '__main__':
    unittest.main(argv=sys.argv[:1])
