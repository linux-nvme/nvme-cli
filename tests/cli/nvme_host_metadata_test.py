#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the printing of the Controller Metadata feature: the element
descriptors are walked within the 4096 byte structure, whatever lengths
the device reports, and each value is printed with its length.

Usage: python3 nvme_host_metadata_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from nvme_mock_ipc import (MockIPCServer, make_mock_env,
                           resolve_mock_lib_path, run_nvme)

_NVME_BIN = (sys.argv[1]
             if len(sys.argv) > 1 and not sys.argv[1].startswith('-')
             else 'nvme')
_MOCK_LIB = resolve_mock_lib_path("./libmock_nvme.so")

_NVME_ADMIN_GET_FEATURES = 0x0a


def json_c_available():
    """True if nvme was built with json-c: the help of --output-format
    lists json only then."""
    proc = subprocess.run([_NVME_BIN, 'get-feature', '--help'],
                          capture_output=True, text=True)
    return 'json' in proc.stdout + proc.stderr
_HOST_METADATA_SIZE = 4096


def element(etype, value, length=None):
    """An element descriptor: type, revision, length and value."""
    return struct.pack('<BBH', etype, 1,
                       len(value) if length is None else length) + value


class MetadataMockIPCServer(MockIPCServer):

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.metadata = b''

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                     cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        if opcode == _NVME_ADMIN_GET_FEATURES:
            data = self.metadata.ljust(_HOST_METADATA_SIZE, b'\xaa')
            self.send_response(conn, 0, payload=data[:req_len])
        else:
            self.send_response(conn, 0, payload=b"\x00" * req_len)


class HostMetadataCLITest(unittest.TestCase):

    DEVICE = '/dev/nvme0'

    def setUp(self):
        self.sysfs_dir = tempfile.mkdtemp(prefix='nvme-md-sysfs-', dir='/tmp')
        self.base_dir = tempfile.mkdtemp(prefix='nvme-md-base-', dir='/tmp')
        self.ipc_dir = tempfile.mkdtemp(prefix='nvme-md-ipc-', dir='/tmp')
        self.ipc_sock_path = os.path.join(self.ipc_dir, "ipc.sock")

        self.server = MetadataMockIPCServer(self.ipc_sock_path)
        self.server.start()

        self.env = make_mock_env(_MOCK_LIB, self.ipc_sock_path)

    def tearDown(self):
        self.server.shutdown()
        self.server.join()

        shutil.rmtree(self.sysfs_dir, ignore_errors=True)
        shutil.rmtree(self.base_dir, ignore_errors=True)
        shutil.rmtree(self.ipc_dir, ignore_errors=True)

    def _get_feature(self, *args):
        result = run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                          'get-feature', self.DEVICE, '--feature-id=0x7e',
                          '--verbose', *args)
        self.assertEqual(result.returncode, 0,
                         f'stdout:\n{result.stdout}\nstderr:\n'
                         f'{result.stderr}')
        return result.stdout

    def _metadata(self, *elements):
        self.server.metadata = bytes([len(elements), 0]) + b''.join(elements)

    def test_values(self):
        """Each value is printed with its length, not up to a NUL."""
        self._metadata(element(1, b'host'), element(2, b'abc'))
        out = self._get_feature()
        self.assertIn('host\n', out)
        self.assertIn('abc\n', out)
        self.assertNotIn('hostabc', out)

    def test_length_past_the_end(self):
        """A length beyond the structure stops the walk at its end."""
        self._metadata(element(1, b'first'),
                       element(2, b'second', length=0xffff),
                       element(3, b'never'))
        formats = [[]]
        if json_c_available():
            formats.append(['--output-format=json'])
        for fmt in formats:
            with self.subTest(fmt=fmt):
                out = self._get_feature(*fmt)
                self.assertIn('first', out)
                self.assertIn('second', out)
                self.assertNotIn('never', out)
                if fmt:
                    descs = json.loads(out)['Feature: 0x7e'][0][
                        'Metadata Element Descriptors']
                    self.assertEqual(len(descs), 2)
                    self.assertEqual(descs[1]['Length'], 0xffff)


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]] + sys.argv[3:])
