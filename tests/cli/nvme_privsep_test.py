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
import stat
import sys
import unittest

from tests.cli.nvme_mock import CNS_CTRL, MockTestCase, id_ctrl
from tests.cli.nvme_mock_ipc import run_nvme

_HELPER = sys.argv[3] if len(sys.argv) > 3 else None

_SERIAL = 'PRIVSEP-SN-0001'

_HELPER_ERROR = 'failed to start the privilege separation helper'


@unittest.skipUnless(_HELPER, 'no privsep helper given')
@unittest.skipIf(os.geteuid() == 0,
                 'NVME_PRIVSEP_TEST_HELPER is ignored when run as root')
class TestPrivsep(MockTestCase):

    def setUp(self):
        super().setUp()
        self.server.identify[CNS_CTRL] = id_ctrl(vid=0x1b36, ssvid=0x1af4,
                                                 sn=_SERIAL)
        self.env.pop('NVME_PRIVSEP_TEST_HELPER', None)

    def nvme(self, helper, *args, close_fd=None):
        env = dict(self.env)
        if helper:
            env['NVME_PRIVSEP_TEST_HELPER'] = helper
        return run_nvme(self.nvme_bin, env, self.sysfs_dir, self.base_dir,
                        *args, close_fd=close_fd)

    def test_device_command_starts_helper(self):
        """A device command starts the helper and fails without one."""
        result = self.nvme('/nonexistent/nvme-privsep-helper',
                           'id-ctrl', '/dev/nvme0')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(_HELPER_ERROR, result.stderr)
        self.assertEqual(len(self.server.commands), 0)

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
        direct_ioctls = len(self.server.commands)

        result = self.nvme(_HELPER, 'id-ctrl', '/dev/nvme0')
        self.assertEqual(result.returncode, 0)
        self.assertIn(_SERIAL, result.stdout)
        self.assertEqual(result.stdout, direct.stdout)
        self.assertEqual(len(self.server.commands) - direct_ioctls,
                         direct_ioctls)

    def test_closed_stdio(self):
        """A closed standard descriptor does not become the socket to the
        helper: nvme-cli's output would go to the helper, and a sandboxed
        decoder, which keeps stdio, could send it requests. The helper
        lists the descriptors of nvme-cli, which waits for it."""
        fds = os.path.join(self.tmp, 'fds')
        wrapper = os.path.join(self.tmp, 'helper-list-fds')
        with open(wrapper, 'w', encoding='utf-8') as f:
            f.write('#!/bin/sh\n'
                    f'ls -l /proc/$PPID/fd > "{fds}"\n'
                    'exec "$REAL_HELPER" "$@"\n')
        os.chmod(wrapper, stat.S_IRWXU)
        self.env['REAL_HELPER'] = _HELPER

        for fd in (0, 1, 2):
            result = self.nvme(wrapper, 'id-ctrl', '/dev/nvme0',
                               close_fd=fd)
            self.assertEqual(result.returncode, 0, fd)
            with open(fds, encoding='utf-8') as f:
                links = dict(line.split()[-3::2] for line in f
                             if ' -> ' in line)
            self.assertEqual(links.get(str(fd)), '/dev/null', fd)

    def test_device_opened_by_helper(self):
        """nvme-cli itself does not open the device: without the mock in
        the helper, the open fails although nvme-cli has the mock."""
        wrapper = os.path.join(self.tmp, 'helper-without-mock')
        with open(wrapper, 'w', encoding='utf-8') as f:
            f.write('#!/bin/sh\nunset LD_PRELOAD\nexec "$REAL_HELPER" "$@"\n')
        os.chmod(wrapper, stat.S_IRWXU)
        self.env['REAL_HELPER'] = _HELPER

        result = self.nvme(wrapper, 'id-ctrl', '/dev/nvme0')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(_HELPER_ERROR, result.stderr)
        self.assertEqual(len(self.server.commands), 0)


if __name__ == '__main__':
    unittest.main(argv=sys.argv[:1])
