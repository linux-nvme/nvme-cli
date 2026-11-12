#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp set-dssd-async-event-config" and "nvme ocp
get-dssd-async-event-config" against a mocked controller.

The commands are checked against the OCP specification (2.7 sections
4.15.19 and 4.15.20): Set Features for FID C9h enables Error Reporting
AENs with CDW11 bit 0 (SDAEC-14; Panic AENs before 2.7) and Media Ready
AENs with bit 1 (SDAEC-18, from 2.7), bits 31:2 reserved; Get Features
returns the same bits in Dword 0 (GDAEC-1..3). OCP 2.5 lets the feature
be saved; from 2.6 the device aborts a Save with Feature Identifier Not
Saveable (SDAEC-10).

Tests in this module verify:
  * set-dssd-async-event-config sets bit 0 with --enable-panic-notices
    and nothing otherwise, Save with --save, NSID 0 (NVMe Base 2.1
    section 4.4) and the OCP UUID index (UUID-3), and fails when Set
    Features fails.
  * get-dssd-async-event-config reads with the SEL given and NSID 0,
    prints what Dword 0 reports, and SEL 3 as capabilities. It sends UUID
    index 0, which UUID-3 allows, so it needs no OCP UUID.
  * Without the OCP UUID set-dssd-async-event-config sends nothing and
    fails.

The plugin has no option for Enable Media Ready AENs, so every Set
clears bit 1, and it prints bit 0 by its pre-2.7 name.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage:
    python3 ocp_dssd_async_event_config_mock_test.py <nvme-binary> <mock-lib>
"""
from tests.cli.nvme_mock import OPC_SET_FEATURES, main
from tests.cli.ocp.ocp_mock_test import (CHANGEABLE_CAPABILITIES,
                                         SEL_NAMES, UUID_INDEX,
                                         OCPFeatureController,
                                         OCPFeatureTestBase, OCPUUIDTests)

SV = 1 << 31
ERROR_REPORTING_AENS = 1 << 0
MEDIA_READY_AENS = 1 << 1
FEATURE_ID_NOT_SAVEABLE = 0x010D

COMMAND = 'set-dssd-async-event-config'
GET_CMD = 'get-dssd-async-event-config'


class AsyncEventConfigController(OCPFeatureController):

    fid = 0xC9

    def __init__(self, sock_path):
        super().__init__(sock_path)
        # Both notices on; the default (and so the saved value) has Error
        # Reporting AENs only (GDAEC-2, 3).
        self.dword0.update({0: ERROR_REPORTING_AENS | MEDIA_READY_AENS,
                            1: ERROR_REPORTING_AENS,
                            2: ERROR_REPORTING_AENS,
                            3: CHANGEABLE_CAPABILITIES})


class AsyncEventConfigTestBase(OCPFeatureTestBase):

    controller_class = AsyncEventConfigController

    def sent(self, *args):
        result = self.assertOk(self.run_cmd(COMMAND, *args))
        return result.stdout, self.only(OPC_SET_FEATURES)


class TestSetDssdAsyncEventConfig(OCPUUIDTests, AsyncEventConfigTestBase):

    without_uuid = (OPC_SET_FEATURES, COMMAND)

    def test_enable_panic_notices_is_cdw11_bit_0(self):
        stdout, cmd = self.sent('--enable-panic-notices')
        self.assertEqual(
            (cmd.cdw11, cmd.cdw10 & SV, cmd.nsid, cmd.uuid_index),
            (ERROR_REPORTING_AENS, 0, 0, UUID_INDEX))
        self.assertIn('Enable Panic Notices bit Value: 0x1', stdout)

    def test_without_options_every_notice_is_disabled(self):
        stdout, cmd = self.sent()
        self.assertEqual((cmd.cdw11, cmd.cdw10 & SV), (0, 0))
        self.assertIn('Enable Panic Notices bit Value: 0x0', stdout)

    def test_save(self):
        """--save sets SV, which OCP 2.5 allows."""
        stdout, cmd = self.sent('--enable-panic-notices', '--save')
        self.assertEqual(cmd.cdw10 & SV, SV)
        self.assertIn('Save bit Value: 0x1', stdout)

    def test_failing_set_features_fails(self):
        """SDAEC-10: from OCP 2.6 a Save is aborted."""
        self.server.set_status = FEATURE_ID_NOT_SAVEABLE
        result = self.run_cmd(COMMAND, '--enable-panic-notices', '--save')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('bit Value', result.stdout)


class TestGetDssdAsyncEventConfig(AsyncEventConfigTestBase):

    def test_sel(self):
        for sel, name in enumerate(SEL_NAMES):
            with self.subTest(sel=sel):
                printed, cmd = self.get_value(GET_CMD, '--sel', str(sel))
                self.assertEqual(cmd.sel, sel)
                self.assertEqual(printed, (name, self.server.dword0[sel]))

    def test_read_with_nsid_0_and_uuid_index_0(self):
        _, cmd = self.get_value(GET_CMD)
        self.assertEqual((cmd.sel, cmd.nsid, cmd.uuid_index), (0, 0, 0))

    def test_without_the_ocp_uuid_reads_all_the_same(self):
        self.server.uuid_slot = None
        printed, _ = self.get_value(GET_CMD)
        self.assertEqual(printed, ('Current', self.server.dword0[0]))

    def test_sel_3_prints_the_capabilities(self):
        result = self.assertOk(self.run_cmd(GET_CMD, '--sel', '3'))
        self.assertIn('Feature is changeable', result.stdout)
        self.assertNotIn('Feature is saveable', result.stdout)
        self.assertNotIn('Feature is per-namespace', result.stdout)


if __name__ == '__main__':
    main()
