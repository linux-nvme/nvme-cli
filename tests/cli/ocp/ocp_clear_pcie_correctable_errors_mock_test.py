#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp clear-pcie-correctable-errors" and "nvme ocp
get-clear-pcie-correctable-errors" against a mocked controller.

The commands are checked against the OCP specification (2.7 sections
4.15.7 and 4.15.8): Set Features for FID C3h clears the PCIe correctable
error counters with CDW11 bit 31, bits 30:0 reserved (CPCIE-13, 14), and
cannot be saved (CPCIE-10); Get Features returns Dword 0 cleared to zero
for SEL 0, 1 and 2 (GPCIE-1).

Tests in this module verify:
  * clear-pcie-correctable-errors sets bit 31 of CDW11 with NSID 0
    (NVMe Base 2.1 section 4.4), without Save, and the OCP UUID index
    (UUID-3), or index 0 with --no-uuid, and fails when Set Features
    fails.
  * get-clear-pcie-correctable-errors reads with the SEL and NSID given,
    the OCP UUID index or index 0 with --no-uuid, prints what Dword 0
    reports, and SEL 3 as capabilities.
  * Without the OCP UUID neither command sends anything, and both fail.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage:
    python3 ocp_clear_pcie_correctable_errors_mock_test.py
        <nvme-binary> <mock-lib>
"""
from tests.cli.nvme_mock import (NSID_ALL, OPC_GET_FEATURES,
                                 OPC_SET_FEATURES, SC_INVALID_FIELD, main)
from tests.cli.ocp.ocp_mock_test import (CHANGEABLE_CAPABILITIES, SEL_NAMES,
                                         UUID_INDEX, OCPFeatureController,
                                         OCPFeatureTestBase, OCPUUIDTests)

SV = 1 << 31
CLEAR = 1 << 31

CLEAR_CMD = 'clear-pcie-correctable-errors'
GET_CMD = 'get-clear-pcie-correctable-errors'


class ClearPcieController(OCPFeatureController):
    """Answers Get Features with Dword 0 cleared for SEL 0..2."""

    fid = 0xC3

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.dword0 = {3: CHANGEABLE_CAPABILITIES}


class TestClearPcieCorrectableErrors(OCPUUIDTests, OCPFeatureTestBase):

    controller_class = ClearPcieController
    without_uuid = (OPC_SET_FEATURES, CLEAR_CMD)

    def test_clear_sets_cdw11_bit_31(self):
        self.assertOk(self.run_cmd(CLEAR_CMD))
        cmd = self.only(OPC_SET_FEATURES)
        self.assertEqual(
            (cmd.cdw11, cmd.cdw10 & SV, cmd.nsid, cmd.uuid_index),
            (CLEAR, 0, 0, UUID_INDEX))

    def test_no_uuid_clears_with_index_0(self):
        self.assertOk(self.run_cmd(CLEAR_CMD, '--no-uuid'))
        self.assertEqual(self.only(OPC_SET_FEATURES).uuid_index, 0)

    def test_failing_set_features_fails(self):
        self.server.set_status = SC_INVALID_FIELD
        result = self.run_cmd(CLEAR_CMD)
        self.assertNotEqual(result.returncode, 0)


class TestGetClearPcieCorrectableErrors(OCPUUIDTests, OCPFeatureTestBase):

    controller_class = ClearPcieController
    without_uuid = (OPC_GET_FEATURES, GET_CMD)

    def test_sel(self):
        for sel, name in enumerate(SEL_NAMES):
            with self.subTest(sel=sel):
                printed, cmd = self.get_value(GET_CMD, '--sel', str(sel))
                self.assertEqual(cmd.sel, sel)
                self.assertEqual(printed, (name, 0))

    def test_value_is_dword_0(self):
        """A device outside GPCIE-1 shows what it returns."""
        self.server.dword0[0] = 0x1234
        printed, _ = self.get_value(GET_CMD)
        self.assertEqual(printed, ('Current', 0x1234))

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
        self.assertIn('Feature is changeable', result.stdout)
        self.assertNotIn('Feature is saveable', result.stdout)
        self.assertNotIn('Feature is per-namespace', result.stdout)


if __name__ == '__main__':
    main()
