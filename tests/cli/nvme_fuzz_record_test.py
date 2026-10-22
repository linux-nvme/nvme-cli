#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for recording the answers of the mock device as seeds of the
device fuzz target (NVME_FUZZ_RECORD, see nvme_mock_ipc.py).

Usage: python3 nvme_fuzz_record_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path

import nvme_mock_ipc
from nvme_mock_ipc import MockIPCServer, make_mock_env, resolve_mock_lib_path, run_nvme

_NVME_BIN = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else 'nvme'
_MOCK_LIB = resolve_mock_lib_path("./libmock_nvme.so")

_NVME_OPCODE_GET_LOG_PAGE = 0x02
_LOG_LEN = 512
_RESULT = 0x12345678
_PAYLOAD = bytes(range(256)) * 2
NVME_SC_INVALID_FIELD = 0x2


class RecordMockIPCServer(MockIPCServer):

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.sc_status = 0

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                      cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        if opcode != _NVME_OPCODE_GET_LOG_PAGE:
            self.send_response(conn, 0)
        elif self.sc_status:
            self.send_response(conn, 0, sc_status=self.sc_status,
                               result=_RESULT)
        else:
            # shorter than asked for: the record pads it
            self.send_response(conn, 0, result=_RESULT,
                               payload=_PAYLOAD[:req_len - 12])


class FuzzRecordTest(unittest.TestCase):

    def setUp(self):
        self.sysfs_dir = tempfile.mkdtemp(prefix='nvme-rec-sysfs-', dir='/tmp')
        self.base_dir = tempfile.mkdtemp(prefix='nvme-rec-base-', dir='/tmp')
        self.ipc_dir = tempfile.mkdtemp(prefix='nvme-rec-ipc-', dir='/tmp')
        self.record_dir = tempfile.mkdtemp(prefix='nvme-rec-', dir='/tmp')
        self.ipc_sock_path = os.path.join(self.ipc_dir, "ipc.sock")
        self.server = RecordMockIPCServer(self.ipc_sock_path)
        self.server.start()
        self.env = make_mock_env(_MOCK_LIB, self.ipc_sock_path)
        self.old_dir = nvme_mock_ipc._fuzz_recorder.dir
        nvme_mock_ipc._fuzz_recorder.dir = self.record_dir

    def tearDown(self):
        nvme_mock_ipc._fuzz_recorder.dir = self.old_dir
        self.server.shutdown()
        self.server.join()
        for d in (self.sysfs_dir, self.base_dir, self.ipc_dir,
                  self.record_dir):
            shutil.rmtree(d, ignore_errors=True)

    def _record(self):
        result = run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                          'get-log', '/dev/nvme0', '--log-id=2',
                          f'--log-len={_LOG_LEN}')
        records = list(Path(self.record_dir).glob('*.json'))
        self.assertEqual(len(records), 1, result.stderr)
        rec = json.loads(records[0].read_text())
        self.assertEqual(rec['args'], ['get-log', '/dev/nvme0', '--log-id=2',
                                       f'--log-len={_LOG_LEN}'])
        return rec

    def test_data(self):
        rec = self._record()
        self.assertIsNone(rec['pci'])
        data = _PAYLOAD[:_LOG_LEN - 12] + bytes(12)
        self.assertEqual(bytes.fromhex(rec['answers']),
                         b'\x00' + struct.pack('<I', _RESULT) + data)

    def test_status(self):
        self.server.sc_status = NVME_SC_INVALID_FIELD
        rec = self._record()
        self.assertEqual(bytes.fromhex(rec['answers']),
                         b'\xe0' + struct.pack('<I', _RESULT) +
                         struct.pack('<H', NVME_SC_INVALID_FIELD))

    def test_pci_ids(self):
        dev = Path(self.sysfs_dir) / 'sys/class/nvme/nvme0/device'
        dev.mkdir(parents=True)
        (dev / 'vendor').write_text('0x1344\n')
        (dev / 'device').write_text('0x51c0\n')
        self.assertEqual(self._record()['pci'], [0x1344, 0x51c0])

    def test_off(self):
        nvme_mock_ipc._fuzz_recorder.dir = None
        run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                 'get-log', '/dev/nvme0', '--log-id=2', '--log-len=512')
        self.assertEqual(list(Path(self.record_dir).iterdir()), [])


if __name__ == '__main__':
    unittest.main(argv=sys.argv[:1])
