#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the files of the rpmb plugin: an absolute --msgfile names the
file to write as it is, not one below the current directory,
read-data writes the sectors it read, read-counter reads the write
counter, and write-data / write-config write authenticated frames.

Usage: python3 nvme_rpmb_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
import hashlib
import hmac
import os
import struct

from tests.cli.nvme_mock import (CNS_CTRL, OPC_SECURITY_RECV, MockTestCase,
                                 id_ctrl, main)

_CONFIG_BLOCK_SIZE = 512
_SECTOR = 512
_OPC_SECURITY_SEND = 0x81

# struct rpmb_data_frame_t field offsets
_FRAME_MAC = 191
_FRAME_HMAC_START = 223
_FRAME_TARGET = 223
_FRAME_NONCE = 224
_FRAME_WRITE_COUNTER = 240
_FRAME_ADDRESS = 244
_FRAME_SECTORS = 248
_FRAME_RESULT = 252
_FRAME_TYPE = 254
_FRAME_DATA = 256

# RPMB request types
_RPMB_REQ_READ_WRITE_CNTR = 0x0002
_RPMB_REQ_AUTH_DATA_WRITE = 0x0003
_RPMB_REQ_READ_RESULT = 0x0005
_RPMB_REQ_AUTH_DCB_WRITE = 0x0006
_RPMB_REQ_AUTH_DCB_READ = 0x0007

# RPMB response types
_RPMB_RSP_READ_WRITE_CNTR = 0x0200
_RPMB_RSP_AUTH_DATA_WRITE = 0x0300
_RPMB_RSP_AUTH_DCB_WRITE = 0x0600
_RPMB_RSP_AUTH_DCB_READ = 0x0700


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


class RpmbReadCounterTest(MockTestCase):
    """A controller with one RPMB target which answers read-counter
    with its write counter."""

    def setUp(self):
        super().setUp()
        self.server.identify[CNS_CTRL] = id_ctrl(rpmbs=1)
        self.server.admin[_OPC_SECURITY_SEND] = self._request
        self.server.admin[OPC_SECURITY_RECV] = self._response
        self.last_nonce = b'\x00' * 16
        self.write_counter = 42

    def _request(self, cmd):
        self.last_nonce = cmd.data[_FRAME_NONCE:_FRAME_NONCE + 16]
        return b''

    def _response(self, cmd):
        frame = bytearray(_FRAME_DATA)
        frame[_FRAME_NONCE:_FRAME_NONCE + 16] = self.last_nonce
        struct.pack_into('<IH', frame, _FRAME_WRITE_COUNTER,
                         self.write_counter, 0)
        struct.pack_into('<H', frame, _FRAME_TYPE,
                         _RPMB_RSP_READ_WRITE_CNTR)
        return bytes(frame)

    def test_read_counter(self):
        result = self.nvme('rpmb', 'read-counter', self.ctrl)
        self.assertOk(result)
        self.assertIn('Write Counter is: 42', result.stdout)


class RpmbWriteDataTest(MockTestCase):
    """A controller with one RPMB target which validates HMAC-SHA256,
    tracks the write counter, and stores written sectors."""

    def setUp(self):
        super().setUp()
        # one target of 128 KiB, access size of one sector
        self.server.identify[CNS_CTRL] = id_ctrl(rpmbs=1 | 1 << 16)
        self.server.admin[_OPC_SECURITY_SEND] = self._request
        self.server.admin[OPC_SECURITY_RECV] = self._response
        self.key = b'01234567890123456789012345678901'
        self.write_counter = 10
        self.storage = {}
        self.last_nonce = b'\x00' * 16
        self.last_req_type = 0
        self.last_result = 0

    def _request(self, cmd):
        req_type, = struct.unpack_from('<H', cmd.data, _FRAME_TYPE)
        self.last_req_type = req_type
        if req_type == _RPMB_REQ_READ_WRITE_CNTR:
            self.last_nonce = cmd.data[_FRAME_NONCE:_FRAME_NONCE + 16]
        elif req_type == _RPMB_REQ_AUTH_DATA_WRITE:
            mac = cmd.data[_FRAME_MAC:_FRAME_MAC + 32]
            computed_mac = hmac.new(
                self.key, cmd.data[_FRAME_HMAC_START:],
                hashlib.sha256).digest()
            if mac != computed_mac:
                self.last_result = 0x0002  # Authentication failure
                return b''
            cntr, addr, sectors = struct.unpack_from(
                '<III', cmd.data, _FRAME_WRITE_COUNTER)
            if cntr != self.write_counter:
                self.last_result = 0x0003  # Counter failure
                return b''
            self.write_counter += 1
            payload = cmd.data[_FRAME_DATA:_FRAME_DATA + sectors * _SECTOR]
            self.storage[addr] = payload
            self.last_result = 0
        return b''

    def _response(self, cmd):
        frame = bytearray(_FRAME_DATA)
        if self.last_req_type == _RPMB_REQ_READ_WRITE_CNTR:
            frame[_FRAME_NONCE:_FRAME_NONCE + 16] = self.last_nonce
            struct.pack_into('<IH', frame, _FRAME_WRITE_COUNTER,
                             self.write_counter, 0)
            struct.pack_into('<H', frame, _FRAME_TYPE,
                             _RPMB_RSP_READ_WRITE_CNTR)
        else:
            struct.pack_into('<IH', frame, _FRAME_WRITE_COUNTER,
                             self.write_counter, self.last_result)
            struct.pack_into('<H', frame, _FRAME_TYPE,
                             _RPMB_RSP_AUTH_DATA_WRITE)
        return bytes(frame)

    def test_write_data(self):
        key_path = os.path.join(self.tmp, 'key.bin')
        data_path = os.path.join(self.tmp, 'data.bin')
        with open(key_path, 'wb') as f:
            f.write(self.key)
        write_bytes = b'\x5a' * _SECTOR + b'\xa5' * _SECTOR
        with open(data_path, 'wb') as f:
            f.write(write_bytes)

        result = self.nvme('rpmb', 'write-data', self.ctrl,
                           f'--keyfile={key_path}', f'--msgfile={data_path}',
                           '--address=4', '--blocks=2')
        if 'without OpenSSL support' in result.stderr:
            self.skipTest('nvme built without OpenSSL')
        self.assertOk(result)
        self.assertIn('Written 2 sectors out of 2', result.stdout)
        self.assertEqual(self.write_counter, 12)
        self.assertEqual(self.storage.get(4), b'\x5a' * _SECTOR)
        self.assertEqual(self.storage.get(5), b'\xa5' * _SECTOR)


class RpmbWriteConfigTest(MockTestCase):
    """A controller with one RPMB target which validates HMAC-SHA256,
    tracks the write counter, and stores device configuration block."""

    def setUp(self):
        super().setUp()
        self.server.identify[CNS_CTRL] = id_ctrl(rpmbs=1)
        self.server.admin[_OPC_SECURITY_SEND] = self._request
        self.server.admin[OPC_SECURITY_RECV] = self._response
        self.key = b'01234567890123456789012345678901'
        self.write_counter = 20
        self.config_block = bytearray(_CONFIG_BLOCK_SIZE)
        self.last_nonce = b'\x00' * 16
        self.last_req_type = 0
        self.last_result = 0

    def _request(self, cmd):
        req_type, = struct.unpack_from('<H', cmd.data, _FRAME_TYPE)
        self.last_req_type = req_type
        if req_type == _RPMB_REQ_AUTH_DCB_READ:
            self.last_nonce = cmd.data[_FRAME_NONCE:_FRAME_NONCE + 16]
        elif req_type == _RPMB_REQ_AUTH_DCB_WRITE:
            mac = cmd.data[_FRAME_MAC:_FRAME_MAC + 32]
            computed_mac = hmac.new(
                self.key, cmd.data[_FRAME_HMAC_START:],
                hashlib.sha256).digest()
            if mac != computed_mac:
                self.last_result = 0x0002  # Authentication failure
                return b''
            cntr, = struct.unpack_from('<I', cmd.data, _FRAME_WRITE_COUNTER)
            if cntr != self.write_counter:
                self.last_result = 0x0003  # Counter failure
                return b''
            self.write_counter += 1
            self.config_block = bytearray(
                cmd.data[_FRAME_DATA:_FRAME_DATA + _CONFIG_BLOCK_SIZE])
            self.last_result = 0
        return b''

    def _response(self, cmd):
        if self.last_req_type == _RPMB_REQ_AUTH_DCB_READ:
            frame = bytearray(_FRAME_DATA)
            frame[_FRAME_NONCE:_FRAME_NONCE + 16] = self.last_nonce
            struct.pack_into('<IH', frame, _FRAME_WRITE_COUNTER,
                             self.write_counter, 0)
            struct.pack_into('<H', frame, _FRAME_TYPE,
                             _RPMB_RSP_AUTH_DCB_READ)
            return bytes(frame) + bytes(self.config_block)

        frame = bytearray(_FRAME_DATA)
        struct.pack_into('<IH', frame, _FRAME_WRITE_COUNTER,
                         self.write_counter, self.last_result)
        struct.pack_into('<H', frame, _FRAME_TYPE,
                         _RPMB_RSP_AUTH_DCB_WRITE)
        return bytes(frame)

    def test_write_config(self):
        key_path = os.path.join(self.tmp, 'key.bin')
        cfg_path = os.path.join(self.tmp, 'cfg.bin')
        with open(key_path, 'wb') as f:
            f.write(self.key)
        new_cfg = b'\x01\x02' + b'\xcc' * (_CONFIG_BLOCK_SIZE - 2)
        with open(cfg_path, 'wb') as f:
            f.write(new_cfg)

        result = self.nvme('rpmb', 'write-config', self.ctrl,
                           f'--keyfile={key_path}', f'--msgfile={cfg_path}')
        if 'without OpenSSL support' in result.stderr:
            self.skipTest('nvme built without OpenSSL')
        self.assertOk(result)
        self.assertEqual(self.write_counter, 21)
        self.assertEqual(bytes(self.config_block), new_cfg)


if __name__ == '__main__':
    main()
