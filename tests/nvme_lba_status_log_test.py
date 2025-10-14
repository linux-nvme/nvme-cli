# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli
#
# Copyright (c) 2022 Samsung Electronics Co., Ltd. All Rights Reserved.
#
# Author: Arunpandian J <apj.arun@samsung.com>

"""
NVMe LBA Status Log Testcase :-

    1. Execute lba-status-log on a device.
"""

import subprocess

from nvme_test import TestNVMe


class TestNVMeLbaStatLogCmd(TestNVMe):

    """
    Represents LBA Status Log test.
    """

    def setUp(self):
        """ Pre Section for TestNVMeLbaStatLogCmd. """
        super().setUp()
        if not self.get_lba_status_supported():
            self.skipTest("because: Optional Admin Command 'Get LBA Status' (OACS->GLSS) not supported")
        self.setup_log_dir(self.__class__.__name__)

    def tearDown(self):
        """
        Post Section for TestNVMeLbaStatLogCmd.

            - Call super class's destructor.
        """
        super().tearDown()

    def get_lba_stat_log(self):
        """ Wrapper for executing nvme lba-status-log.
            - Args:
                - None
            - Returns:
                - 0 on success, error code on failure.
        """
        lba_stat_log_cmd = f"{self.nvme_bin} lba-status-log {self.ctrl}"
        proc = subprocess.Popen(lba_stat_log_cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                encoding='utf-8')
        return proc.wait()

    def test_lba_stat_log(self):
        """ Testcase main """
        self.assertEqual(self.get_lba_stat_log(), 0)
