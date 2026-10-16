#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for "nvme seagate vs-smart-add-log" against a mocked controller.

The command reads the extended SMART log 0xC4 and the DRAM SMART log 0xCF
of a legacy (Jaguar or Panther) drive, and the log 0xC0 of any other.
Each must be printed once, in text and in JSON.

Usage: python3 seagate_vs_smart_add_log_mock_test.py <nvme-binary> <mock-lib>
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

from tests.cli.nvme_mock_ipc import (MockIPCServer, make_mock_env,
                                     resolve_mock_lib_path, run_nvme)

_NVME_BIN = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else 'nvme'
_MOCK_LIB = resolve_mock_lib_path("./libmock_nvme.so")

_OPC_GET_LOG_PAGE = 0x02
_OPC_IDENTIFY = 0x06
_MN_OFFSET = 24
_JAGUAR_MN = b'ST1000KN0002'


class SeagateMockServer(MockIPCServer):
    """A controller whose model number is @mn, with zeroed log pages.
    Records the log page IDs read."""

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.mn = b'ST800FM0173'
        self.lids = []

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                     cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        data = bytearray(req_len)
        if opcode == _OPC_IDENTIFY and (cdw10 & 0xff) == 1:
            data[_MN_OFFSET:_MN_OFFSET + 40] = self.mn.ljust(40, b' ')
        elif opcode == _OPC_GET_LOG_PAGE:
            self.lids.append(cdw10 & 0xff)
        self.send_response(conn, 0, payload=bytes(data))


class SeagateVsSmartAddLogTest(unittest.TestCase):

    DEVICE = '/dev/nvme0'

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nvme-seagate-', dir='/tmp')
        self.sysfs_dir = os.path.join(self.tmp, 'sysfs')
        self.base_dir = os.path.join(self.tmp, 'base')
        os.mkdir(self.sysfs_dir)
        os.mkdir(self.base_dir)
        self.server = SeagateMockServer(os.path.join(self.tmp, 'ipc.sock'))
        self.server.start()
        self.env = make_mock_env(_MOCK_LIB, self.server.sock_path)

    def tearDown(self):
        self.server.shutdown()
        self.server.join()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, *args):
        result = run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                          'seagate', 'vs-smart-add-log', self.DEVICE, *args)
        self.assertEqual(result.returncode, 0,
                         f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}')
        self.assertEqual(self.server.errors, [])
        return result.stdout

    @staticmethod
    def _json(out):
        # the JSON follows a heading line
        return json.loads(out.split('\n', 1)[1])

    def test_jaguar_logs_read_and_printed_once(self):
        self.server.mn = _JAGUAR_MN
        out = self._run()
        self.assertEqual(self.server.lids, [0xc4, 0xcf])
        self.assertEqual(out.count('Ext-Smart-Id'), 1)

    def test_jaguar_json_printed_once(self):
        self.server.mn = _JAGUAR_MN
        out = self._json(self._run('-o', 'json'))
        self.assertEqual(self.server.lids, [0xc4, 0xcf])
        self.assertEqual(len(out['SMART-Attributes']), 2)

    def test_log_c0_read_and_printed_once(self):
        self._run()
        self.assertEqual(self.server.lids, [0xc0])

    def test_log_c0_json(self):
        out = self._json(self._run('-o', 'json'))
        self.assertEqual(self.server.lids, [0xc0])
        self.assertEqual(len(out['SMART-Attributes']), 1)


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]])
