#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp set-telemetry-profile" and "nvme ocp
get-telemetry-profile" against a mocked controller.

The commands are checked against the OCP specification (2.7 sections
4.15.17 and 4.15.18): Set Features for FID C8h carries the Telemetry
Profile Select in CDW11 bits 7:0, bits 31:8 reserved (TEL-CFG-SF-13,
14), and saves it (TEL-CFG-SF-10; OCP 2.5 requires Save and NSID
FFFFFFFFh); Get Features returns it in Dword 0 bits 7:0 (TEL-CFG-GF-3).

Tests in this module verify:
  * set-telemetry-profile sends the profile with Save, NSID FFFFFFFFh and
    the OCP UUID index (UUID-3), and fails when Set Features fails.
  * get-telemetry-profile reads with the SEL and NSID given, the OCP UUID
    index or index 0 with --no-uuid, prints what Dword 0 reports, and
    SEL 3 as capabilities.

Known defects are covered by expectedFailure tests: set-telemetry-profile
without --telemetry-profile-select exits 0, and with no OCP UUID both
commands exit 0.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_telemetry_profile_mock_test.py <nvme-binary> <mock-lib>
"""
import unittest

from tests.cli.nvme_mock import (NSID_ALL, OPC_GET_FEATURES,
                                 OPC_SET_FEATURES, SC_INVALID_FIELD, main)
from tests.cli.ocp.ocp_mock_test import (SEL_NAMES, UUID_INDEX,
                                         OCPFeatureController,
                                         OCPFeatureTestBase, OCPUUIDTests)

SV = 1 << 31

GET_CMD = 'get-telemetry-profile'


class TelemetryProfileController(OCPFeatureController):

    fid = 0xC8

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.dword0.update({0: 0x02, 1: 0x00, 2: 0x01})


class TelemetryProfileTestBase(OCPFeatureTestBase):

    controller_class = TelemetryProfileController


class TestSetTelemetryProfile(OCPUUIDTests, TelemetryProfileTestBase):

    without_uuid = (OPC_SET_FEATURES, 'set-telemetry-profile', '-t', '1')

    def test_profile_is_cdw11(self):
        for tps in (0x01, 0xFF):
            with self.subTest(tps=tps):
                result = self.assertOk(self.run_cmd(
                    'set-telemetry-profile', '--telemetry-profile-select',
                    hex(tps)))
                cmd = self.only(OPC_SET_FEATURES)
                self.assertEqual(
                    (cmd.cdw11, cmd.cdw10 & SV, cmd.nsid, cmd.uuid_index),
                    (tps, SV, NSID_ALL, UUID_INDEX))
                self.assertIn(f'Telemetry Profile Select: {hex(tps)}',
                              result.stdout)

    def test_failing_set_features_fails(self):
        self.server.set_status = SC_INVALID_FIELD
        result = self.run_cmd('set-telemetry-profile', '-t', '1')
        self.assertNotEqual(result.returncode, 0)

    def test_without_a_profile_nothing_is_sent(self):
        result = self.run_cmd('set-telemetry-profile')
        self.assertIn('Telemetry Profile Select is a required argument',
                      result.stderr)
        self.assertEqual(self.cmds(OPC_SET_FEATURES), [])

    @unittest.expectedFailure
    def test_without_a_profile_exits_nonzero(self):
        """Defect: the command reports the missing argument and exits
        0."""
        self.assertNotEqual(
            self.run_cmd('set-telemetry-profile').returncode, 0)


class TestGetTelemetryProfile(OCPUUIDTests, TelemetryProfileTestBase):

    without_uuid = (OPC_GET_FEATURES, GET_CMD)

    def test_sel(self):
        for sel, name in enumerate(SEL_NAMES):
            with self.subTest(sel=sel):
                printed, cmd = self.get_value(GET_CMD, '--sel', str(sel))
                self.assertEqual(cmd.sel, sel)
                self.assertEqual(printed, (name, self.server.dword0[sel]))

    def test_read_with_nsid_0_and_the_ocp_uuid_index(self):
        _, cmd = self.get_value(GET_CMD)
        self.assertEqual((cmd.sel, cmd.nsid, cmd.uuid_index),
                         (0, 0, UUID_INDEX))

    def test_namespace_id(self):
        _, cmd = self.get_value(GET_CMD, '--namespace-id', str(NSID_ALL))
        self.assertEqual(cmd.nsid, NSID_ALL)

    def test_no_uuid_reads_index_0(self):
        _, cmd = self.get_value(GET_CMD, '--no-uuid')
        self.assertEqual(cmd.uuid_index, 0)

    def test_sel_3_prints_the_capabilities(self):
        result = self.assertOk(self.run_cmd(GET_CMD, '--sel', '3'))
        self.assertIn('Feature is saveable', result.stdout)
        self.assertIn('Feature is changeable', result.stdout)
        self.assertNotIn('Feature is per-namespace', result.stdout)


if __name__ == '__main__':
    main()
