#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for the privilege separation of nvme-cli (src/privsep.c).

nvme-cli runs unprivileged here, so NVME_PRIVSEP_TEST_HELPER makes it use
the helper anyway. libmock_nvme.so is preloaded into nvme-cli and, through
the inherited environment, into the helper.

Usage: python3 nvme_privsep_test.py <nvme-binary> <mock-lib> <helper>
"""
import os
import shutil
import stat
import struct
import sys
import tempfile
import unittest

from nvme_mock_ipc import MockIPCServer, make_mock_env, resolve_mock_lib_path, run_nvme

_NVME_BIN = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else 'nvme'
_MOCK_LIB = resolve_mock_lib_path("./libmock_nvme.so")
_HELPER = sys.argv[3] if len(sys.argv) > 3 else None

_NVME_OPCODE_IDENTIFY = 0x06
_NVME_IDENTIFY_CNS_CTRL = 0x01
_ID_CTRL_SIZE = 4096
_SERIAL = b'PRIVSEP-SN-0001'

_HELPER_ERROR = 'failed to start the privilege separation helper'


def _pack_id_ctrl():
    buf = bytearray(_ID_CTRL_SIZE)
    struct.pack_into('<HH', buf, 0, 0x1b36, 0x1af4)
    buf[4:24] = _SERIAL.ljust(20, b' ')
    return bytes(buf)


class PrivsepMockIPCServer(MockIPCServer):

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.ioctls = 0

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                     cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        self.ioctls += 1
        if opcode == _NVME_OPCODE_IDENTIFY and \
                (cdw10 & 0xff) == _NVME_IDENTIFY_CNS_CTRL:
            self.send_response(conn, 0, payload=_pack_id_ctrl())
            return
        self.send_response(conn, 0)


@unittest.skipUnless(_HELPER, 'no privsep helper given')
@unittest.skipIf(os.geteuid() == 0,
                 'NVME_PRIVSEP_TEST_HELPER is ignored when run as root')
class TestPrivsep(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix='nvme-privsep-', dir='/tmp')
        self.sysfs_dir = os.path.join(self.tmp_dir, 'sysfs')
        self.base_dir = os.path.join(self.tmp_dir, 'base')
        os.mkdir(self.sysfs_dir)
        os.mkdir(self.base_dir)
        sock_path = os.path.join(self.tmp_dir, 'ipc.sock')
        self.server = PrivsepMockIPCServer(sock_path)
        self.server.start()
        self.env = make_mock_env(_MOCK_LIB, sock_path)
        self.env.pop('NVME_PRIVSEP_TEST_HELPER', None)

    def tearDown(self):
        self.server.shutdown()
        self.server.join()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def nvme(self, helper, *args):
        env = dict(self.env)
        if helper:
            env['NVME_PRIVSEP_TEST_HELPER'] = helper
        return run_nvme(_NVME_BIN, env, self.sysfs_dir, self.base_dir, *args)

    def test_device_command_starts_helper(self):
        """A device command starts the helper and fails without one."""
        result = self.nvme('/nonexistent/nvme-privsep-helper',
                           'id-ctrl', '/dev/nvme0')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(_HELPER_ERROR, result.stderr)
        self.assertEqual(self.server.ioctls, 0)

    def test_needs_root_command_skips_helper(self):
        """A command which keeps root does not start the helper."""
        result = self.nvme('/nonexistent/nvme-privsep-helper', 'list')
        self.assertNotIn(_HELPER_ERROR, result.stderr)

    def test_mi_device_skips_helper(self):
        """An MI device keeps root, a file named like one does not."""
        result = self.nvme('/nonexistent/nvme-privsep-helper',
                           'id-ctrl', 'mctp:1,8')
        self.assertNotIn(_HELPER_ERROR, result.stderr)
        result = self.nvme('/nonexistent/nvme-privsep-helper',
                           'fw-download', '/dev/nvme0',
                           '--fw', 'mctp:image.bin')
        self.assertIn(_HELPER_ERROR, result.stderr)

    def test_help_skips_helper(self):
        """Help and version select no command."""
        for args in (['version'], ['--version'], ['help']):
            result = self.nvme('/nonexistent/nvme-privsep-helper', *args)
            self.assertNotIn(_HELPER_ERROR, result.stderr, args)

    def test_id_ctrl_through_helper(self):
        """The helper issues the commands and nvme-cli prints the same."""
        direct = self.nvme(None, 'id-ctrl', '/dev/nvme0')
        self.assertEqual(direct.returncode, 0)
        direct_ioctls = self.server.ioctls

        result = self.nvme(_HELPER, 'id-ctrl', '/dev/nvme0')
        self.assertEqual(result.returncode, 0)
        self.assertIn(_SERIAL.decode(), result.stdout)
        self.assertEqual(result.stdout, direct.stdout)
        self.assertEqual(self.server.ioctls - direct_ioctls, direct_ioctls)

    def test_device_opened_by_helper(self):
        """nvme-cli itself does not open the device: without the mock in
        the helper, the open fails although nvme-cli has the mock."""
        wrapper = os.path.join(self.tmp_dir, 'helper-without-mock')
        with open(wrapper, 'w', encoding='utf-8') as f:
            f.write('#!/bin/sh\nunset LD_PRELOAD\nexec "$REAL_HELPER" "$@"\n')
        os.chmod(wrapper, stat.S_IRWXU)
        self.env['REAL_HELPER'] = _HELPER

        result = self.nvme(wrapper, 'id-ctrl', '/dev/nvme0')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(_HELPER_ERROR, result.stderr)
        self.assertEqual(self.server.ioctls, 0)


if __name__ == '__main__':
    unittest.main(argv=sys.argv[:1])
