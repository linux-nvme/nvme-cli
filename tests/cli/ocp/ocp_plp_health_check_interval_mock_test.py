#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp set-plp-health-check-interval" and "nvme ocp
get-plp-health-check-interval" against a mocked controller.

The commands are checked against the OCP specification (2.7 sections
4.15.13 and 4.15.14): Set Features for FID C6h carries the interval in
minutes in CDW11 bits 31:16, bits 15:0 reserved (SPLPI-13, 14), and may
be saved (SPLPI-10); Get Features returns the interval in Dword 0 bits
15:0 (GPLPI-2).

Tests in this module verify:
  * set-plp-health-check-interval sends the interval, 0 included, which
    disables the check, with Save for --save, NSID 0 (NVMe Base 2.1
    section 4.4) and the OCP UUID index (UUID-3), or index 0 with
    --no-uuid, and fails when Set Features fails.
  * get-plp-health-check-interval reads with the SEL given and NSID 0,
    prints what Dword 0 reports, and SEL 3 as capabilities. It sends UUID
    index 0, which UUID-3 allows.
  * Without the OCP UUID set-plp-health-check-interval sends nothing
    and fails.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage:
    python3 ocp_plp_health_check_interval_mock_test.py <nvme-binary> <mock-lib>
"""
from tests.cli.nvme_mock import OPC_SET_FEATURES, SC_INVALID_FIELD, main
from tests.cli.ocp.ocp_mock_test import (SEL_NAMES, UUID_INDEX,
                                         OCPFeatureController,
                                         OCPFeatureTestBase, OCPUUIDTests)

SV = 1 << 31
INTERVAL_SHIFT = 16


class PlpIntervalController(OCPFeatureController):

    fid = 0xC6

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.dword0.update({0: 0x003C, 1: 0x000F, 2: 0x0000})


class PlpIntervalTestBase(OCPFeatureTestBase):

    controller_class = PlpIntervalController

    def sent(self, *args):
        result = self.assertOk(self.run_cmd('set-plp-health-check-interval',
                                            *args))
        return result.stdout, self.only(OPC_SET_FEATURES)


class TestSetPlpHealthCheckInterval(OCPUUIDTests, PlpIntervalTestBase):

    without_uuid = (OPC_SET_FEATURES, 'set-plp-health-check-interval',
                    '-p', '15')

    def test_interval_is_cdw11_bits_31_16(self):
        for interval in (0x0000, 0x000F, 0x7FFF, 0xFFFF):
            with self.subTest(interval=interval):
                stdout, cmd = self.sent('--plp_health_interval',
                                        hex(interval))
                self.assertEqual(
                    (cmd.cdw11, cmd.cdw10 & SV, cmd.nsid, cmd.uuid_index),
                    (interval << INTERVAL_SHIFT, 0, 0, UUID_INDEX))
                self.assertIn(f'PLP Health Check Interval: {interval:#x}',
                              stdout)

    def test_save(self):
        stdout, cmd = self.sent('--plp_health_interval', '15', '--save')
        self.assertEqual(cmd.cdw10 & SV, SV)
        self.assertIn('Save bit Value: 0x1', stdout)

    def test_no_uuid_sends_index_0(self):
        _, cmd = self.sent('--plp_health_interval', '15', '--no-uuid')
        self.assertEqual(cmd.uuid_index, 0)

    def test_failing_set_features_fails(self):
        self.server.set_status = SC_INVALID_FIELD
        result = self.run_cmd('set-plp-health-check-interval', '-p', '15')
        self.assertNotEqual(result.returncode, 0)


class TestGetPlpHealthCheckInterval(PlpIntervalTestBase):

    def test_sel(self):
        for sel, name in enumerate(SEL_NAMES):
            with self.subTest(sel=sel):
                printed, cmd = self.get_value(
                    'get-plp-health-check-interval', '--sel', str(sel))
                self.assertEqual((cmd.sel, cmd.nsid, cmd.uuid_index),
                                 (sel, 0, 0))
                self.assertEqual(printed, (name, self.server.dword0[sel]))

    def test_sel_3_prints_the_capabilities(self):
        result = self.assertOk(self.run_cmd('get-plp-health-check-interval',
                                            '--sel', '3'))
        self.assertIn('Feature is saveable', result.stdout)
        self.assertIn('Feature is changeable', result.stdout)
        self.assertNotIn('Feature is per-namespace', result.stdout)


if __name__ == '__main__':
    main()
