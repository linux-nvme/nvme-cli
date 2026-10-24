#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the files of the rpmb plugin: an absolute --msgfile names the
file to write as it is, not one below the current directory.

Usage: python3 nvme_rpmb_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
import os

from tests.cli.nvme_mock import CNS_CTRL, MockTestCase, id_ctrl, main

_CONFIG_BLOCK_SIZE = 512


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


if __name__ == '__main__':
    main()
