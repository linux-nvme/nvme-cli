#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests that --dry-run keeps the commands which do not send an NVMe
command from changing the device: reset, subsystem-reset and ns-rescan
issue a controller ioctl, which libmock_nvme.c forwards raw.

Usage: python3 nvme_dry_run_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
from tests.cli.nvme_mock import (NVME_IOCTL_RESCAN, NVME_IOCTL_RESET,
                                 NVME_IOCTL_SUBSYS_RESET, MockTestCase, main)


class DryRunCLITest(MockTestCase):

    def setUp(self):
        super().setUp()
        for nr in (NVME_IOCTL_RESET, NVME_IOCTL_SUBSYS_RESET,
                   NVME_IOCTL_RESCAN):
            self.server.ioctls[nr] = 0

    def _run(self, *args):
        return self.assertOk(self.nvme(*args))

    def _check(self, command, ioctl):
        # Without --dry-run the ioctl reaches the device, so the test
        # would notice it with --dry-run as well.
        self._run(command, self.ctrl)
        self.assertEqual([i.nr for i in self.server.raw_ioctls], [ioctl])

        self.server.raw_ioctls.clear()
        self._run(command, self.ctrl, '--dry-run')
        self.assertEqual(self.server.raw_ioctls, [])

    def test_reset(self):
        self._check('reset', NVME_IOCTL_RESET)

    def test_subsystem_reset(self):
        self._check('subsystem-reset', NVME_IOCTL_SUBSYS_RESET)

    def test_ns_rescan(self):
        self._check('ns-rescan', NVME_IOCTL_RESCAN)


if __name__ == '__main__':
    main()
