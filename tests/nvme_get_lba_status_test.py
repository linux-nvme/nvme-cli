# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli
#
# Copyright (c) 2022 Samsung Electronics Co., Ltd. All Rights Reserved.
#
# Author: Arunpandian J <apj.arun@samsung.com>

"""
NVMe LBA Status Log Testcase :-

    1. Execute get-lba-status on a device.
"""

import subprocess

from nvme_test import TestNVMe


class TestNVMeGetLbaStatusCmd(TestNVMe):

    """
    Represents Get LBA Status test.
    """

    def setUp(self):
        """ Pre Section for TestNVMeGetLbaStatusCmd. """
        super().setUp()
        if not self.get_lba_status_supported():
            self.skipTest("because: Optional Admin Command 'Get LBA Status' (OACS->GLSS) not supported")
        self.start_lba = 0
        self.block_count = 0
        self.max_dw = 1
        self.action = 0x11
        self.range_len = 1
        self.setup_log_dir(self.__class__.__name__)

    def tearDown(self):
        """
        Post Section for TestNVMeGetLbaStatusCmd.

            - Call super class's destructor.
        """
        super().tearDown()

    def get_lba_status(self):
        """ Wrapper for executing nvme get-lba-status.
            - Args:
                - None
            - Returns:
                - 0 on success, error code on failure.
        """
        get_lba_status_cmd = f"{self.nvme_bin} get-lba-status {self.ctrl} " + \
            f"--namespace-id={str(self.ns1)} " + \
            f"--start-lba={str(self.start_lba)} " + \
            f"--max-dw={str(self.max_dw)} " + \
            f"--action={str(self.action)} " + \
            f"--range-len={str(self.range_len)}"
        proc = subprocess.Popen(get_lba_status_cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                encoding='utf-8')
        return proc.wait()

    def test_get_lba_status(self):
        """ Testcase main """
        self.assertEqual(self.get_lba_status(), 0)
