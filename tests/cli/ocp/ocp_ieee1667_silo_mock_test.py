#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for "nvme ocp get-enable-ieee1667-silo" against a mocked
controller: the state it prints is the one Dword 0 of the completion of
Get Features reports.

Usage: python3 ocp_ieee1667_silo_mock_test.py <nvme-binary> <mock-lib>
"""
from tests.cli.nvme_mock import Reply, main
from tests.cli.ocp.ocp_mock_test import OCPController, OCPMockTestBase

FID_IEEE1667_SILO = 0xC4


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


if __name__ == '__main__':
    main()
