#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the commands which act on a CTRATT bit of Identify Controller.

CTRATT is a little endian field: a command which tests the bits without
converting it sees other bits on a big endian host. The mocked
controller reports a single CTRATT bit; the tests check that the
command follows it.

Usage: python3 nvme_ctratt_test.py <nvme-binary> <mock-lib>
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

_OPC_NS_MGMT = 0x0d
_OPC_IDENTIFY = 0x06
_OPC_RESV_REPORT = 0x0e
_CNS_ID_CTRL = 0x01
_CNS_NS_GRANULARITY = 0x16

# CTRATT bits
_CTRATT_HIDS = 1 << 0
_CTRATT_NG = 1 << 7


class CtrattMockServer(MockIPCServer):
    """A controller which reports @ctratt and records the commands."""

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.ctratt = 0
        self.cmds = []

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                     cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        self.cmds.append((opcode, cdw10, cdw11))
        data = bytearray(req_len)
        if opcode == _OPC_IDENTIFY and cdw10 & 0xff == _CNS_ID_CTRL:
            struct.pack_into('<I', data, 96, self.ctratt)
        self.send_response(conn, 0, payload=bytes(data))


class CtrattTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nvme-ctratt-', dir='/tmp')
        self.sysfs_dir = os.path.join(self.tmp, 'sysfs')
        self.base_dir = os.path.join(self.tmp, 'base')
        os.mkdir(self.sysfs_dir)
        os.mkdir(self.base_dir)
        self.server = CtrattMockServer(os.path.join(self.tmp, 'ipc.sock'))
        self.server.start()
        self.env = make_mock_env(_MOCK_LIB, self.server.sock_path)

    def tearDown(self):
        self.server.shutdown()
        self.server.join()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, *args):
        result = run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                          *args)
        if 'invalid sub-command' in result.stderr:
            self.skipTest(f'{args[0]} plugin not built')
        self.assertEqual(result.returncode, 0,
                         f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}')
        self.assertEqual(self.server.errors, [])

    def _resv_report_eds(self, ctratt):
        self.server.ctratt = ctratt
        self._run('resv', 'report', '/dev/nvme0', '-n', '1')
        reports = [cdw11 for opcode, _, cdw11 in self.server.cmds
                   if opcode == _OPC_RESV_REPORT]
        self.assertTrue(reports)
        return all(cdw11 & 1 for cdw11 in reports)

    def test_resv_report_eds_with_hids(self):
        """With 128 bit Host Identifiers, the report uses the extended
        data structure."""
        self.assertTrue(self._resv_report_eds(_CTRATT_HIDS))

    def test_resv_report_no_eds(self):
        self.assertFalse(self._resv_report_eds(_CTRATT_NG))

    def _ns_create_reads_granularity(self, ctratt):
        self.server.ctratt = ctratt
        self._run('ns', 'create', '/dev/nvme0', '--nsze=0x1000',
                  '--ncap=0x1000', '--flbas=0')
        self.assertIn(_OPC_NS_MGMT, [c[0] for c in self.server.cmds])
        return any(opcode == _OPC_IDENTIFY and
                   cdw10 & 0xff == _CNS_NS_GRANULARITY
                   for opcode, cdw10, _ in self.server.cmds)

    def test_ns_create_granularity(self):
        """With Namespace Granularity, create reads the granularity
        list."""
        self.assertTrue(self._ns_create_reads_granularity(_CTRATT_NG))

    def test_ns_create_no_granularity(self):
        self.assertFalse(self._ns_create_reads_granularity(_CTRATT_HIDS))


if __name__ == '__main__':
    unittest.main(argv=sys.argv[:1])
