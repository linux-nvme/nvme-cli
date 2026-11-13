#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp eol-plp-failure-mode" against a mocked controller.

The command is checked against the OCP specification (2.7 sections
4.15.5 and 4.15.6, PLP Failure Mode): Set Features for FID C2h carries
the End of Life Behavior in CDW11 bits 31:30, bits 29:0 reserved
(SROWTM-13, 14), and may be saved (SROWTM-10); Get Features returns the
behavior in Dword 0 bits 2:0, bits 31:3 reserved (GROWTM-1, 2). The
behaviors are 01b/001b Read Only Mode, 10b/010b Write Through Mode and
11b/011b normal operation.

Tests in this module verify:
  * --mode sets the behavior, with Save for --save, NSID 0 (NVMe Base
    2.1 section 4.4) and the OCP UUID index (UUID-3), or index 0 with
    --no-uuid, and fails when Set Features fails; a mode with no End of
    Life Behavior value is refused.
  * Without --mode the behavior of the SEL given is read and named, and
    SEL 3 prints the capabilities.
  * Without the OCP UUID nothing is sent, and the command fails.

A known defect is covered by an expectedFailure test asserting the
behavior the specification defines: Get Features decodes bits 7:0 of
Dword 0 rather than bits 2:0.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_eol_plp_failure_mode_mock_test.py <nvme-binary> <mock-lib>
"""
import re
import unittest

from tests.cli.nvme_mock import (OPC_GET_FEATURES, OPC_SET_FEATURES,
                                 SC_INVALID_FIELD, main)
from tests.cli.ocp.ocp_mock_test import (SEL_NAMES, UUID_INDEX,
                                         OCPFeatureController,
                                         OCPFeatureTestBase, OCPUUIDTests)

COMMAND = 'eol-plp-failure-mode'
SV = 1 << 31
EOL_BEHAVIOR_SHIFT = 30

# The abbreviation each behavior's description carries.
BEHAVIORS = {1: 'ROM', 2: 'WTM', 3: 'normal'}

GET_RE = re.compile(r'End of Life Behavior \(feature: 0xc2\): \w+ '
                    r'\((\w+): ([^)]*\)?)\)')


class PlpFailureModeController(OCPFeatureController):

    fid = 0xC2

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.dword0.update({0: 0b010, 1: 0b001, 2: 0b011})


class PlpFailureModeTestBase(OCPFeatureTestBase):

    controller_class = PlpFailureModeController

    def run_eol(self, *args):
        return self.run_cmd(COMMAND, *args)

    def got(self, *args):
        """Read the behavior; returns the SEL name and behavior name
        printed and the Get Features sent."""
        result = self.assertOk(self.run_eol(*args))
        match = GET_RE.search(result.stdout)
        self.assertIsNotNone(match, result.stdout)
        return match.group(1), match.group(2), self.only(OPC_GET_FEATURES)

    def assertBehaviorName(self, name, behavior):
        self.assertIn(BEHAVIORS[behavior].casefold(), name.casefold())
        for other in set(BEHAVIORS) - {behavior}:
            self.assertNotIn(BEHAVIORS[other].casefold(), name.casefold())


class TestSetPlpFailureMode(OCPUUIDTests, PlpFailureModeTestBase):

    without_uuid = (OPC_SET_FEATURES, COMMAND, '--mode', '1')

    def test_mode_is_cdw11_bits_31_30(self):
        for mode in BEHAVIORS:
            with self.subTest(mode=mode):
                result = self.assertOk(self.run_eol('--mode', str(mode)))
                cmd = self.only(OPC_SET_FEATURES)
                self.assertEqual(
                    (cmd.cdw11, cmd.cdw10 & SV, cmd.nsid, cmd.uuid_index),
                    (mode << EOL_BEHAVIOR_SHIFT, 0, 0, UUID_INDEX))
                self.assertIn(BEHAVIORS[mode].casefold(),
                              result.stdout.casefold())
                self.assertEqual(self.cmds(OPC_GET_FEATURES), [])

    def test_save(self):
        self.assertOk(self.run_eol('--mode', '1', '--save'))
        self.assertEqual(self.only(OPC_SET_FEATURES).cdw10 & SV, SV)

    def test_no_uuid_sends_index_0(self):
        self.assertOk(self.run_eol('--mode', '1', '--no-uuid'))
        self.assertEqual(self.only(OPC_SET_FEATURES).uuid_index, 0)

    def test_failing_set_features_fails(self):
        self.server.set_status = SC_INVALID_FIELD
        self.assertNotEqual(self.run_eol('--mode', '1').returncode, 0)

    def test_mode_without_a_behavior_is_refused(self):
        """0 is the reserved 00b, and 4 to 7 do not fit the two-bit
        field."""
        for mode in (0, 4, 5, 6, 7):
            with self.subTest(mode=mode):
                result = self.run_eol('--mode', str(mode))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.cmds(OPC_SET_FEATURES), [])


class TestGetPlpFailureMode(OCPUUIDTests, PlpFailureModeTestBase):

    without_uuid = (OPC_GET_FEATURES, COMMAND)

    def test_current_behavior_is_read(self):
        sel_name, name, cmd = self.got()
        self.assertEqual((cmd.sel, cmd.nsid, cmd.uuid_index),
                         (0, 0, UUID_INDEX))
        self.assertEqual(sel_name, 'Current')
        self.assertBehaviorName(name, self.server.dword0[0])
        self.assertEqual(self.cmds(OPC_SET_FEATURES), [])

    def test_sel(self):
        for sel, sel_label in enumerate(SEL_NAMES):
            with self.subTest(sel=sel):
                sel_name, name, cmd = self.got('--sel', str(sel))
                self.assertEqual((cmd.sel, sel_name), (sel, sel_label))
                self.assertBehaviorName(name, self.server.dword0[sel])

    def test_behavior_names(self):
        for behavior in BEHAVIORS:
            with self.subTest(behavior=behavior):
                self.server.dword0[0] = behavior
                self.assertBehaviorName(self.got()[1], behavior)

    def test_no_uuid_reads_index_0(self):
        self.assertEqual(self.got('--no-uuid')[2].uuid_index, 0)

    def test_sel_3_prints_the_capabilities(self):
        result = self.assertOk(self.run_eol('--sel', '3'))
        self.assertIn('Feature is saveable', result.stdout)
        self.assertIn('Feature is changeable', result.stdout)
        self.assertNotIn('Feature is per-namespace', result.stdout)

    @unittest.expectedFailure
    def test_behavior_is_dword_0_bits_2_0(self):
        """Defect: the behavior is decoded from bits 7:0 of Dword 0 rather
        than 2:0 (GROWTM-2), so a set reserved bit among 7:3 (GROWTM-1)
        turns any behavior into "Reserved"."""
        self.server.dword0[0] = 0x08 | 0b010
        self.assertBehaviorName(self.got()[1], 0b010)


if __name__ == '__main__':
    main()
