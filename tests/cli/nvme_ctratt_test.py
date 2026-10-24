#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the commands which act on a CTRATT bit of Identify Controller.

CTRATT is a little endian field: a command which tests the bits without
converting it sees other bits on a big endian host. The mocked
controller reports a single CTRATT bit; the tests check that the
command follows it.

Usage: python3 nvme_ctratt_test.py <nvme-binary> <mock-lib>
"""
from tests.cli.nvme_mock import CNS_CTRL, MockTestCase, id_ctrl, main

_OPC_NS_MGMT = 0x0d
_OPC_RESV_REPORT = 0x0e
_CNS_NS_GRANULARITY = 0x16

# CTRATT bits
_CTRATT_HIDS = 1 << 0
_CTRATT_NG = 1 << 7


class CtrattTest(MockTestCase):
    """A controller which reports the CTRATT of a test."""

    def _run(self, ctratt, *args):
        self.server.identify[CNS_CTRL] = id_ctrl(ctratt=ctratt)
        result = self.nvme(*args)
        if 'invalid sub-command' in result.stderr:
            self.skipTest(f'{args[0]} plugin not built')
        self.assertOk(result)

    def _resv_report_eds(self, ctratt):
        self._run(ctratt, 'resv', 'report', self.ctrl, '-n', '1')
        reports = self.server.io_cmds(_OPC_RESV_REPORT)
        self.assertTrue(reports)
        return all(c.cdw11 & 1 for c in reports)

    def test_resv_report_eds_with_hids(self):
        """With 128 bit Host Identifiers, the report uses the extended
        data structure."""
        self.assertTrue(self._resv_report_eds(_CTRATT_HIDS))

    def test_resv_report_no_eds(self):
        self.assertFalse(self._resv_report_eds(_CTRATT_NG))

    def _ns_create_reads_granularity(self, ctratt):
        self._run(ctratt, 'ns', 'create', self.ctrl, '--nsze=0x1000',
                  '--ncap=0x1000', '--flbas=0')
        self.assertTrue(self.server.admin_cmds(_OPC_NS_MGMT))
        return bool(self.server.identifies(_CNS_NS_GRANULARITY))

    def test_ns_create_granularity(self):
        """With Namespace Granularity, create reads the granularity
        list."""
        self.assertTrue(self._ns_create_reads_granularity(_CTRATT_NG))

    def test_ns_create_no_granularity(self):
        self.assertFalse(self._ns_create_reads_granularity(_CTRATT_HIDS))


if __name__ == '__main__':
    main()
