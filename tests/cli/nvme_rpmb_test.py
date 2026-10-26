#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the files of the rpmb plugin: an absolute --msgfile names the
file to write as it is, not one below the current directory, and
read-data writes the sectors it read.

Usage: python3 nvme_rpmb_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
import os
import struct

from tests.cli.nvme_mock import (CNS_CTRL, OPC_SECURITY_RECV, MockTestCase,
                                 id_ctrl, main)

_CONFIG_BLOCK_SIZE = 512
_SECTOR = 512
_OPC_SECURITY_SEND = 0x81
# struct rpmb_data_frame_t: the address and sector count of a request or
# response, little endian, and where its data starts
_FRAME_ADDRESS = 244
_FRAME_DATA = 256


class RpmbCLITest(MockTestCase):
    """A controller with one RPMB target, which answers the other
    commands with success and zeroed data."""

    def setUp(self):
        super().setUp()
        self.server.identify[CNS_CTRL] = id_ctrl(rpmbs=1)
        self.out = os.path.join(self.tmp, 'out')
        os.mkdir(self.out)

    def _read_config(self, msgfile):
        return self.nvme('rpmb', 'read-config', self.ctrl,
                         f'--msgfile={msgfile}')

    def test_absolute_msgfile(self):
        path = os.path.join(self.out, 'config.bin')
        result = self._read_config(path)
        self.assertIn(f'Saving received config data to {path}',
                      result.stdout + result.stderr)
        self.assertEqual(os.path.getsize(path), _CONFIG_BLOCK_SIZE)


class RpmbReadDataTest(MockTestCase):
    """A controller with one RPMB target which transfers a sector at a
    time, and answers each authenticated data read with the sectors it
    was asked for, each filled with the low byte of its address."""

    def setUp(self):
        super().setUp()
        # one target of 128 KiB, an access size of one sector
        self.server.identify[CNS_CTRL] = id_ctrl(rpmbs=1 | 1 << 16)
        self.server.admin[_OPC_SECURITY_SEND] = self._request
        self.server.admin[OPC_SECURITY_RECV] = self._response
        self.requests = []

    def _request(self, cmd):
        self.requests.append(struct.unpack_from('<II', cmd.data,
                                                _FRAME_ADDRESS))
        return b''

    def _response(self, cmd):
        address, sectors = self.requests[-1]
        frame = bytearray(_FRAME_DATA)
        struct.pack_into('<II', frame, _FRAME_ADDRESS, address, sectors)
        for i in range(sectors):
            frame += bytes([(address + i) & 0xff]) * _SECTOR
        return bytes(frame)

    def test_address(self):
        # the sectors read, not the address of the last one plus one
        path = os.path.join(self.tmp, 'data.bin')
        self.assertOk(self.nvme('rpmb', 'read-data', self.ctrl,
                                f'--msgfile={path}', '--address=8',
                                '--blocks=2'))
        self.assertEqual([a for a, _ in self.requests], [8, 9])
        with open(path, 'rb') as f:
            self.assertEqual(f.read(), b'\x08' * _SECTOR + b'\x09' * _SECTOR)


if __name__ == '__main__':
    main()
