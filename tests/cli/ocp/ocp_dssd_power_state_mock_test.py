#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp set-dssd-power-state-feature" and "nvme ocp
get-dssd-power-state-feature" against a mocked controller.

The commands are checked against the OCP specification (2.7 sections
4.15.15 and 4.15.16): Set Features for FID C7h carries the DSSD Power
State in watts in CDW11 bits 6:0, bits 31:7 reserved (SDSSDPS-13, 14),
and may be saved (SDSSDPS-10); Get Features returns it in Dword 0 bits
6:0 (GDSSDPS-2).

Tests in this module verify:
  * set-dssd-power-state-feature sends the power state, Save with
    --save, NSID 0 (NVMe Base 2.1 section 4.4) and the OCP UUID index
    (UUID-3), or index 0 with --no-uuid, and fails when Set Features
    fails; a power state too large for CDW11 bits 6:0, or none, is
    refused.
  * get-dssd-power-state-feature reads with the SEL given, or SEL 0, 1
    and 2 in turn with --all, and prints what Dword 0 reports, with SEL 3
    as capabilities, and fails with neither.
  * Without the OCP UUID neither command sends anything, and both fail.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_dssd_power_state_mock_test.py <nvme-binary> <mock-lib>
"""
from tests.cli.nvme_mock import (OPC_GET_FEATURES, OPC_SET_FEATURES,
                                 SC_INVALID_FIELD, main)
from tests.cli.ocp.ocp_mock_test import (SEL_NAMES, UUID_INDEX,
                                         OCPFeatureController,
                                         OCPFeatureTestBase, OCPUUIDTests)

SV = 1 << 31
POWER_STATE_MASK = 0x7F


class DssdPowerStateController(OCPFeatureController):

    fid = 0xC7

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.dword0.update({0: 25, 1: 40, 2: 30})


class DssdPowerStateTestBase(OCPFeatureTestBase):

    controller_class = DssdPowerStateController

    def sent(self, *args):
        result = self.assertOk(self.run_cmd('set-dssd-power-state-feature',
                                            *args))
        return result.stdout, self.only(OPC_SET_FEATURES)

    def values(self, *args):
        """Run get-dssd-power-state-feature, returning the (SEL name,
        value) pairs it prints and the SELs it sent."""
        result = self.assertOk(self.run_cmd('get-dssd-power-state-feature',
                                            *args))
        return (self.printed_values(result.stdout),
                [c.sel for c in self.cmds(OPC_GET_FEATURES)])


class TestSetDssdPowerState(OCPUUIDTests, DssdPowerStateTestBase):

    without_uuid = (OPC_SET_FEATURES, 'set-dssd-power-state-feature',
                    '--power-state', '25')

    def test_power_state_is_cdw11(self):
        stdout, cmd = self.sent('--power-state', '25')
        self.assertEqual((cmd.cdw11, cmd.cdw10 & SV, cmd.nsid,
                          cmd.uuid_index), (25, 0, 0, UUID_INDEX))
        self.assertIn('DSSD Power State: 0x19', stdout)

    def test_largest_power_state(self):
        _, cmd = self.sent('--power-state', str(POWER_STATE_MASK))
        self.assertEqual(cmd.cdw11, POWER_STATE_MASK)

    def test_save(self):
        stdout, cmd = self.sent('--power-state', '25', '--save')
        self.assertEqual(cmd.cdw10 & SV, SV)
        self.assertIn('Save bit Value: 0x1', stdout)

    def test_no_uuid_sends_index_0(self):
        _, cmd = self.sent('--power-state', '25', '--no-uuid')
        self.assertEqual(cmd.uuid_index, 0)

    def test_failing_set_features_fails(self):
        """DSSDPSS-2: a state below the minimum is Invalid Field."""
        self.server.set_status = SC_INVALID_FIELD
        result = self.run_cmd('set-dssd-power-state-feature',
                              '--power-state', '1')
        self.assertNotEqual(result.returncode, 0)

    def test_power_state_too_large_for_its_field_is_refused(self):
        """128 would set reserved bit 7 (SDSSDPS-13)."""
        result = self.run_cmd('set-dssd-power-state-feature',
                              '--power-state', '128')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.cmds(OPC_SET_FEATURES), [])

    def test_without_a_power_state_nothing_is_sent(self):
        self.run_cmd('set-dssd-power-state-feature')
        self.assertEqual(self.cmds(OPC_SET_FEATURES), [])

    def test_without_a_power_state_exits_nonzero(self):
        result = self.run_cmd('set-dssd-power-state-feature')
        self.assertNotEqual(result.returncode, 0)


class TestGetDssdPowerState(OCPUUIDTests, DssdPowerStateTestBase):

    without_uuid = (OPC_GET_FEATURES, 'get-dssd-power-state-feature',
                    '--sel', '0')

    def test_sel(self):
        for sel, name in enumerate(SEL_NAMES):
            with self.subTest(sel=sel):
                printed, sels = self.values('--sel', str(sel))
                self.assertEqual(sels, [sel])
                self.assertEqual(printed,
                                 [(name, self.server.dword0[sel])])

    def test_read_with_nsid_0_and_the_ocp_uuid_index(self):
        self.values('--sel', '0')
        cmd = self.only(OPC_GET_FEATURES)
        self.assertEqual((cmd.nsid, cmd.uuid_index), (0, UUID_INDEX))

    def test_no_uuid_reads_index_0(self):
        self.values('--sel', '0', '--no-uuid')
        self.assertEqual(self.only(OPC_GET_FEATURES).uuid_index, 0)

    def test_all_reads_current_default_and_saved(self):
        printed, sels = self.values('--all')
        self.assertEqual(sels, [0, 1, 2])
        self.assertEqual(printed, [(name, self.server.dword0[sel])
                                   for sel, name in enumerate(SEL_NAMES)])

    def test_sel_3_prints_the_capabilities(self):
        result = self.assertOk(self.run_cmd('get-dssd-power-state-feature',
                                            '--sel', '3'))
        self.assertIn('Feature is saveable', result.stdout)
        self.assertIn('Feature is changeable', result.stdout)
        self.assertNotIn('Feature is per-namespace', result.stdout)

    def test_without_sel_or_all_nothing_is_read(self):
        self.run_cmd('get-dssd-power-state-feature')
        self.assertEqual(self.cmds(OPC_GET_FEATURES), [])

    def test_without_sel_or_all_exits_nonzero(self):
        result = self.run_cmd('get-dssd-power-state-feature')
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    main()
