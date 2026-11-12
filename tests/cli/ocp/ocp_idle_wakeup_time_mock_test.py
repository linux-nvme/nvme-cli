#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp get-idle-wakeup-time" against a mocked controller.

The command is checked against the OCP specification (2.7 section
4.15.22, the first version to define FID CAh): Get Features returns the
Idle Wake Up Time in milliseconds in Dword 0 bits 15:0, 0000h meaning
disabled, bits 31:16 reserved (GIDLE-1, 2). The feature may be saved
(SIDLE-10).

Tests in this module verify:
  * The command reads with the SEL and NSID given and the OCP UUID index
    (UUID-3), or index 0 with --no-uuid.
  * A time of 0 is shown as disabled, any other as the time Dword 0
    reports, and SEL 3 as capabilities.
  * Without the OCP UUID nothing is read, and the command fails.

A known defect is covered by an expectedFailure test asserting the
behavior the specification defines: a disabled time with a reserved bit
set is shown as a time.

With SEL 3 the capabilities are also printed as a wake up time.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_idle_wakeup_time_mock_test.py <nvme-binary> <mock-lib>
"""
import re
import unittest

from tests.cli.nvme_mock import NSID_ALL, OPC_GET_FEATURES, main
from tests.cli.ocp.ocp_mock_test import (SEL_NAMES, UUID_INDEX,
                                         OCPFeatureController,
                                         OCPFeatureTestBase, OCPUUIDTests)

RESERVED_BIT = 1 << 16

COMMAND = 'get-idle-wakeup-time'
VALUE_RE = re.compile(
    r'get-feature:CAh[ ,]SEL=(\w+),IWUT (Disabled|is): ((?:0x)?[0-9a-f]+)')


class IdleWakeupTimeController(OCPFeatureController):

    fid = 0xCA

    def __init__(self, sock_path):
        super().__init__(sock_path)
        # Current 250 ms; the factory default is the shortest the device
        # supports (GIDLE-2); saved disabled.
        self.dword0.update({0: 250, 1: 100, 2: 0})


class TestGetIdleWakeupTime(OCPUUIDTests, OCPFeatureTestBase):

    controller_class = IdleWakeupTimeController
    without_uuid = (OPC_GET_FEATURES, COMMAND)

    def got(self, *args):
        """Run get-idle-wakeup-time; returns the (SEL name, state, value)
        printed and the Get Features sent."""
        result = self.assertOk(self.run_cmd(COMMAND, *args))
        match = VALUE_RE.search(result.stdout)
        self.assertIsNotNone(match, result.stdout)
        return ((match.group(1), match.group(2), int(match.group(3), 16)),
                self.only(OPC_GET_FEATURES))

    def test_sel(self):
        for sel, name in enumerate(SEL_NAMES):
            value = self.server.dword0[sel]
            with self.subTest(sel=sel):
                printed, cmd = self.got('--sel', str(sel))
                self.assertEqual(cmd.sel, sel)
                self.assertEqual(
                    printed, (name, 'is' if value else 'Disabled', value))

    def test_largest_time(self):
        self.server.dword0[0] = 0xFFFF
        printed, _ = self.got()
        self.assertEqual(printed, ('Current', 'is', 0xFFFF))

    def test_read_with_nsid_0_and_the_ocp_uuid_index(self):
        _, cmd = self.got()
        self.assertEqual((cmd.sel, cmd.nsid, cmd.uuid_index),
                         (0, 0, UUID_INDEX))

    def test_namespace_id(self):
        _, cmd = self.got('--namespace-id', str(NSID_ALL))
        self.assertEqual(cmd.nsid, NSID_ALL)

    def test_no_uuid_reads_index_0(self):
        _, cmd = self.got('--no-uuid')
        self.assertEqual(cmd.uuid_index, 0)

    def test_sel_3_prints_the_capabilities(self):
        result = self.assertOk(self.run_cmd(COMMAND, '--sel', '3'))
        self.assertIn('Feature is saveable', result.stdout)
        self.assertIn('Feature is changeable', result.stdout)
        self.assertNotIn('Feature is per-namespace', result.stdout)

    @unittest.expectedFailure
    def test_time_is_dword_0_bits_15_0(self):
        """Defect: disabled is decided from all of Dword 0 rather than
        bits 15:0 (GIDLE-2), so a set reserved bit among 31:16 (GIDLE-1)
        shows a disabled time as a time."""
        self.server.dword0[0] = RESERVED_BIT
        printed, _ = self.got()
        self.assertEqual(printed[1], 'Disabled')


if __name__ == '__main__':
    main()
