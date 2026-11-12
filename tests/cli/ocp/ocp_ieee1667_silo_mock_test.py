#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Daniel Wagner <dwagner@suse.de>
#          Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp get-enable-ieee1667-silo" and "nvme ocp
set-enable-ieee1667-silo" against a mocked controller: the state the get
prints is the one Dword 0 of the completion of Get Features reports.

The commands are checked against the OCP specification (2.7 sections
4.15.9 and 4.15.10): Set Features for FID C4h enables the silo with
CDW11 bit 31, bits 30:0 reserved (S1667-13, 14), and may be saved
(S1667-10); Get Features returns the IEEE1667 Silo Enabled state in
Dword 0 bits 2:0 (G1667-2).

Tests in this module verify:
  * set-enable-ieee1667-silo sets bit 31 with --enable and clears it
    otherwise, Save with --save, NSID 0 (NVMe Base 2.1 section 4.4) and
    the OCP UUID index (UUID-3), or index 0 with --no-uuid, and fails
    when Set Features fails.
  * get-enable-ieee1667-silo reads with the SEL given, the OCP UUID index
    or index 0 with --no-uuid, and prints SEL 3 as capabilities only.
  * Without the OCP UUID neither command sends anything, and both fail.

A known defect is covered by an expectedFailure test asserting the
behavior the specification defines: the state is printed as "Sifo"
rather than Silo Enabled.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_ieee1667_silo_mock_test.py <nvme-binary> <mock-lib>
"""
import unittest

from tests.cli.nvme_mock import (OPC_GET_FEATURES, OPC_SET_FEATURES,
                                 SC_CMD_SEQ_ERROR, Reply, main)
from tests.cli.ocp.ocp_mock_test import (SEL_NAMES, UUID_INDEX,
                                         OCPController, OCPFeatureController,
                                         OCPFeatureTestBase, OCPMockTestBase,
                                         OCPUUIDTests)

FID_IEEE1667_SILO = 0xC4
SV = 1 << 31
ENABLE = 1 << 31

SET_CMD = 'set-enable-ieee1667-silo'
GET_CMD = 'get-enable-ieee1667-silo'


class SiloController(OCPController):
    """Reports @enabled in Dword 0 of Get Features of the silo feature."""

    enabled = 0

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.features[FID_IEEE1667_SILO] = lambda cmd: Reply(
            result=self.enabled)


class IEEE1667SiloTest(OCPMockTestBase):

    controller_class = SiloController

    def get(self):
        return self.assertOk(self.run_ocp('get-enable-ieee1667-silo'))

    def test_enabled(self):
        self.server.enabled = 1
        self.assertIn('0x1 (Current: enabled)', self.get().stdout)

    def test_disabled(self):
        self.server.enabled = 0
        self.assertIn('0x0 (Current: disabled)', self.get().stdout)


class SiloFeatureController(OCPFeatureController):

    fid = FID_IEEE1667_SILO

    def __init__(self, sock_path):
        super().__init__(sock_path)
        # Enabled now, disabled by default (G1667-2), and saved enabled.
        self.dword0.update({0: 1, 1: 0, 2: 1})


class SiloFeatureTestBase(OCPFeatureTestBase):

    controller_class = SiloFeatureController


class TestSetEnableIEEE1667Silo(OCPUUIDTests, SiloFeatureTestBase):

    without_uuid = (OPC_SET_FEATURES, SET_CMD, '--enable')

    def sent(self, *args):
        result = self.assertOk(self.run_cmd(SET_CMD, *args))
        return result.stdout, self.only(OPC_SET_FEATURES)

    def test_enable_is_cdw11_bit_31(self):
        stdout, cmd = self.sent('--enable')
        self.assertEqual(
            (cmd.cdw11, cmd.cdw10 & SV, cmd.nsid, cmd.uuid_index),
            (ENABLE, 0, 0, UUID_INDEX))
        self.assertIn('(Not save: Enabled)', stdout)

    def test_without_enable_the_silo_is_disabled(self):
        stdout, cmd = self.sent()
        self.assertEqual(cmd.cdw11, 0)
        self.assertIn('(Not save: Disabled)', stdout)

    def test_save(self):
        stdout, cmd = self.sent('--enable', '--save')
        self.assertEqual(cmd.cdw10 & SV, SV)
        self.assertIn('(Save: Enabled)', stdout)

    def test_no_uuid_sends_index_0(self):
        _, cmd = self.sent('--enable', '--no-uuid')
        self.assertEqual(cmd.uuid_index, 0)

    def test_failing_set_features_fails(self):
        """The silo can only be set while the Opal SSC is Manufactured
        Inactive (2.7 section 4.15.9)."""
        self.server.set_status = SC_CMD_SEQ_ERROR
        result = self.run_cmd(SET_CMD, '--enable')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Successfully', result.stdout)


class TestGetEnableIEEE1667Silo(OCPUUIDTests, SiloFeatureTestBase):

    without_uuid = (OPC_GET_FEATURES, GET_CMD)

    def got(self, *args):
        result = self.assertOk(self.run_cmd(GET_CMD, *args))
        return result.stdout, self.only(OPC_GET_FEATURES)

    def test_sel(self):
        for sel, name in enumerate(SEL_NAMES):
            state = 'enabled' if self.server.dword0[sel] else 'disabled'
            with self.subTest(sel=sel):
                stdout, cmd = self.got('--sel', str(sel))
                self.assertEqual(cmd.sel, sel)
                self.assertIn(f'0x{self.server.dword0[sel]:x} '
                              f'({name}: {state})', stdout)

    def test_read_with_nsid_0_and_the_ocp_uuid_index(self):
        _, cmd = self.got()
        self.assertEqual((cmd.sel, cmd.nsid, cmd.uuid_index),
                         (0, 0, UUID_INDEX))

    def test_no_uuid_reads_index_0(self):
        _, cmd = self.got('--no-uuid')
        self.assertEqual(cmd.uuid_index, 0)

    def test_sel_3_prints_only_the_capabilities(self):
        stdout, _ = self.got('--sel', '3')
        self.assertIn('Feature is saveable', stdout)
        self.assertIn('Feature is changeable', stdout)
        self.assertNotIn('Feature is per-namespace', stdout)
        self.assertNotIn('IEEE1667', stdout)

    @unittest.expectedFailure
    def test_state_is_named_silo_enabled(self):
        """Defect: the state is printed as "IEEE1667 Sifo Enabled"; the
        field is IEEE1667 Silo Enabled (G1667-2)."""
        stdout, _ = self.got()
        self.assertIn('IEEE1667 Silo Enabled', stdout)


if __name__ == '__main__':
    main()
