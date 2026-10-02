#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Samsung Electronics Co., Ltd.
#
# Authors: Hyuntae Kim <h1219.kim@samsung.com>
"""Samsung telemetry tests through the real NVMe-MI/MCTP command path.

Run from the repository root with PYTHONPATH=.
Usage: python3 <test-script> <nvme> <mock-lib>
The preload library redirects AF_MCTP sockets to this Unix socket peer,
so the tests need no MCTP kernel support, root or NVMe hardware.
"""
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest

from tests.cli.nvme_mock_ipc import make_mock_env, run_nvme
from nvme_samsung_test import SERIAL, pack_id_ctrl, pack_telemetry_header

NVME_BIN = os.path.abspath(sys.argv[1])
MOCK_LIB = os.path.abspath(sys.argv[2])
BLOCK_SIZE = 512
LAST_BLOCKS = (260, 264, 264, 264)
DUMP_SIZE = LAST_BLOCKS[0] * BLOCK_SIZE


def crc32c(data):
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def telemetry_data(offset, size):
    # Absolute offsets make missing/reordered chunks change the file.
    return bytes((offset + i) % 251 for i in range(size))


def telemetry_header(lid):
    header = bytearray(pack_telemetry_header(LAST_BLOCKS))
    header[0] = lid
    return bytes(header)


class MCTPPeer(threading.Thread):
    def __init__(self, path):
        super().__init__()
        self.stopped = threading.Event()
        self.errors = []
        self.logs = []
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.sock.bind(path)
        self.sock.listen(1)
        self.sock.settimeout(0.1)

    def run(self):
        while not self.stopped.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(0.1)
                while not self.stopped.is_set():
                    try:
                        data = conn.recv(8192)
                        if not data:
                            break
                        # MCTP omits the type byte from socket payloads.
                        request = b'\x84' + data
                        response = self.handle_request(request)
                        mic = struct.pack('<I', crc32c(response))
                        conn.sendall(response[1:] + mic)
                    except socket.timeout:
                        continue
                    except Exception as exc:
                        self.errors.append(str(exc))
                        break

    def handle_request(self, request):
        if len(request) != 72:
            raise ValueError(f'admin request length: {len(request)}')
        if crc32c(request[:-4]) != struct.unpack_from('<I', request, 68)[0]:
            raise ValueError('invalid request MIC')
        if (request[1] >> 3) & 0x0f != 2:
            raise ValueError('expected an NVMe-MI admin command')

        opcode = request[4]
        ctrl_id = struct.unpack_from('<H', request, 6)[0]
        data_len = struct.unpack_from('<I', request, 32)[0]
        cdw10, cdw11, cdw12, cdw13 = struct.unpack_from('<IIII', request, 44)
        payload = b''
        sc = 0
        if opcode == 0x06:
            payload = pack_id_ctrl()[:data_len]
        elif opcode == 0x02:
            lid = cdw10 & 0xff
            lpo = (cdw13 << 32) | cdw12
            numd = (cdw11 >> 16) << 16 | (cdw10 >> 16)
            if data_len != (numd + 1) * 4:
                raise ValueError('DLEN does not match Get Log Page NUMD')
            self.logs.append((ctrl_id, lid, lpo, data_len))
            if lid not in (0x07, 0x08) or data_len > 4096:
                sc = 0x02  # INVALID_FIELD
            elif lpo == 0:
                payload = telemetry_header(lid)[:data_len]
            else:
                payload = telemetry_data(lpo, data_len)
        else:
            sc = 0x01  # INVALID_OPCODE

        response = bytearray(20)
        response[0] = 0x84
        response[1] = request[1] | 0x80
        struct.pack_into('<I', response, 16, sc << 17)
        return bytes(response) + payload

    def shutdown(self):
        self.stopped.set()
        self.sock.close()
        self.join()


class SamsungMCTPTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(
            prefix='nvme-samsung-mctp-', dir='/tmp')
        self.addCleanup(self.tmp.cleanup)
        path = os.path.join(self.tmp.name, 'mctp.sock')
        self.peer = MCTPPeer(path)
        self.peer.start()
        self.addCleanup(self.peer.shutdown)
        self.env = make_mock_env(MOCK_LIB, path)
        self.env['MOCK_MCTP_SOCK'] = path

    def check_dump(self, dump_type, lid, label, device='mctp:1,8:3', area=1):
        prefix = os.path.join(self.tmp.name, dump_type) + '/'
        result = run_nvme(NVME_BIN, self.env, self.tmp.name, self.tmp.name,
                          'samsung', 'vs-internal-log', device,
                          '-t', dump_type, '-a', str(area), '-O', prefix, '-H')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.peer.errors, [])
        self.assertIn('(Xfer 4K)', result.stdout)
        ctrl_id = 3 if device.endswith(':3') else 0
        expected = [(ctrl_id, lid, 0, BLOCK_SIZE)] * 2
        expected += [(ctrl_id, lid, BLOCK_SIZE + offset,
                      min(4096, DUMP_SIZE - offset))
                     for offset in range(0, DUMP_SIZE, 4096)]
        if area == 0:
            expected += [
                (ctrl_id, lid, 0, BLOCK_SIZE),
                (ctrl_id, lid, BLOCK_SIZE + DUMP_SIZE, 4 * BLOCK_SIZE),
            ]
        self.assertEqual(self.peer.logs, expected)
        dump = telemetry_data(BLOCK_SIZE, DUMP_SIZE)
        name = f'{SERIAL}_Telemetry_{label}_Area_1'
        with open(prefix + name + '.bin', 'rb') as f:
            self.assertEqual(f.read(), dump)
        with open(prefix + name + '_header.bin', 'rb') as f:
            self.assertEqual(f.read(), telemetry_header(lid) + dump)
        if area == 0:
            area2 = telemetry_data(BLOCK_SIZE + DUMP_SIZE, 4 * BLOCK_SIZE)
            merged = prefix + f'{SERIAL}_Telemetry_{label}_Area_1+2.bin'
            with open(merged, 'rb') as f:
                self.assertEqual(f.read(),
                                 telemetry_header(lid) + dump + area2)

    def test_host0_uses_4k_transfers(self):
        self.check_dump('host0', 0x07, 'Host(0)')

    def test_host1_uses_4k_transfers(self):
        self.check_dump('host1', 0x07, 'Host(1)')

    def test_controller_uses_4k_transfers(self):
        self.check_dump('ctlr', 0x08, 'Controller')

    def test_implicit_controller_id(self):
        self.check_dump('ctlr', 0x08, 'Controller', device='mctp:1,8')

    def test_all_areas_use_4k_transfers_and_merge(self):
        self.check_dump('ctlr', 0x08, 'Controller', area=0)


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]], verbosity=2)
