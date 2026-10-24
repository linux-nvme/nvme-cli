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
import struct
import tempfile
from pathlib import Path

from tests.cli import nvme_mock_ipc
from tests.cli.nvme_mock import (OPC_GET_LOG_PAGE, SC_INVALID_FIELD,
                                 MockTestCase, main)
from tests.cli.nvme_mock_ipc import MockIPCServer

_LOG_LEN = 512
_RESULT = 0x12345678
_PAYLOAD = bytes(range(256)) * 2


class RecordController(MockIPCServer):
    """Answers Get Log Page with fewer bytes than it reads, which the
    record pads, or with the NVMe status @sc_status."""

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.sc_status = 0

    def handle_command(self, conn, cmd):
        if cmd.opcode != OPC_GET_LOG_PAGE:
            self.send_response(conn, 0)
        elif self.sc_status:
            self.send_response(conn, 0, sc_status=self.sc_status,
                               result=_RESULT)
        else:
            self.send_response(conn, 0, result=_RESULT,
                               payload=_PAYLOAD[:cmd.data_len - 12])


class FuzzRecordTest(MockTestCase):

    controller_class = RecordController

    def setUp(self):
        super().setUp()
        record_dir = tempfile.TemporaryDirectory(prefix='nvme-rec-',
                                                 dir='/tmp')
        self.addCleanup(record_dir.cleanup)
        self.record_dir = record_dir.name
        self.addCleanup(setattr, nvme_mock_ipc._fuzz_recorder, 'dir',
                        nvme_mock_ipc._fuzz_recorder.dir)
        nvme_mock_ipc._fuzz_recorder.dir = self.record_dir

    def _record(self):
        result = self.nvme('get-log', self.ctrl, '--log-id=2',
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
        self.server.sc_status = SC_INVALID_FIELD
        rec = self._record()
        self.assertEqual(bytes.fromhex(rec['answers']),
                         b'\xe0' + struct.pack('<I', _RESULT) +
                         struct.pack('<H', SC_INVALID_FIELD))

    def test_pci_ids(self):
        self.write_sysfs_pci_ctrl(vid=0x1344, did=0x51c0)
        self.assertEqual(self._record()['pci'], [0x1344, 0x51c0])

    def test_off(self):
        nvme_mock_ipc._fuzz_recorder.dir = None
        self.nvme('get-log', self.ctrl, '--log-id=2', '--log-len=512')
        self.assertEqual(list(Path(self.record_dir).iterdir()), [])


if __name__ == '__main__':
    main()
