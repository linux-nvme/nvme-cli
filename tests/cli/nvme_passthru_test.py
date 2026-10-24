#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests that libmock_nvme.c hands the whole passthru command to the mock
controller: every field of the command, and the data and metadata a
command which transfers data to the controller sends. Like the kernel, a
write gets no data back.

Usage: python3 nvme_passthru_test.py <path-to-nvme-binary> <mock-lib>
"""
import os

from tests.cli.nvme_mock import OPC_NVM_WRITE, MockTestCase, main

_OPC_ADMIN_VENDOR_WRITE = 0xc1
_OPC_ADMIN_VENDOR_READ = 0xc2


class PassthruTest(MockTestCase):

    def _file(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, 'wb') as f:
            f.write(data)
        return path

    def test_write_command(self):
        data = bytes(range(256)) * 2
        self.assertOk(self.nvme(
            'admin-passthru', self.ctrl,
            f'--opcode={_OPC_ADMIN_VENDOR_WRITE}', '--flags=0x40',
            '--namespace-id=5', '--cdw2=2', '--cdw3=3', '--cdw10=10',
            '--cdw11=11', '--cdw12=12', '--cdw13=13', '--cdw14=14',
            '--cdw15=15', '--timeout=1234', '--data-len=512',
            f'--input-file={self._file("data", data)}'))

        cmd, = self.server.admin_cmds(_OPC_ADMIN_VENDOR_WRITE)
        self.assertEqual(
            (cmd.flags, cmd.nsid, cmd.cdw2, cmd.cdw3, cmd.cdw10, cmd.cdw11,
             cmd.cdw12, cmd.cdw13, cmd.cdw14, cmd.cdw15, cmd.timeout_ms),
            (0x40, 5, 2, 3, 10, 11, 12, 13, 14, 15, 1234))
        self.assertEqual((cmd.data_len, cmd.data), (512, data))
        self.assertIsNone(cmd.metadata)

    def test_io_write_metadata(self):
        data = b'D' * 512
        metadata = b'M' * 8
        self.assertOk(self.nvme(
            'io-passthru', self.ns, f'--opcode={OPC_NVM_WRITE}',
            '--namespace-id=1', '--data-len=512', '--metadata-len=8',
            f'--input-file={self._file("data", data)}',
            f'--metadata={self._file("metadata", metadata)}'))

        cmd, = self.server.io_cmds(OPC_NVM_WRITE)
        self.assertFalse(cmd.admin)
        self.assertEqual((cmd.data, cmd.metadata_len, cmd.metadata),
                         (data, 8, metadata))

    def test_read_command(self):
        self.server.admin[_OPC_ADMIN_VENDOR_READ] = b'R' * 64
        result = self.assertOk(self.nvme(
            'admin-passthru', self.ctrl,
            f'--opcode={_OPC_ADMIN_VENDOR_READ}', '--data-len=64',
            '--raw-binary', encoding=None))

        self.assertEqual(result.stdout, b'R' * 64)
        cmd, = self.server.admin_cmds(_OPC_ADMIN_VENDOR_READ)
        self.assertIsNone(cmd.data)

    def test_write_gets_no_data_back(self):
        """--read prints the buffer of the write after the command."""
        self.server.admin[_OPC_ADMIN_VENDOR_WRITE] = b'R' * 64
        result = self.assertOk(self.nvme(
            'admin-passthru', self.ctrl,
            f'--opcode={_OPC_ADMIN_VENDOR_WRITE}', '--data-len=64', '--read',
            '--raw-binary', encoding=None, stdin_data=b'W' * 64))

        self.assertEqual(result.stdout, b'W' * 64)


if __name__ == '__main__':
    main()
