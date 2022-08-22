# SPDX-License-Identifier: GPL-2.0-only
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
        self.start_lba = 0
        self.block_count = 0
        self.namespace = 1
        self.max_dw = 1
        self.action = 11
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
        err = 0
        get_lba_status_cmd = "nvme get-lba-status " + self.ctrl + \
                             " --namespace-id=" + str(self.namespace) + \
                             " --start-lba=" + str(self.start_lba) + \
                             " --max-dw=" + str(self.max_dw) + \
                             " --action=" + str(self.action) + \
                             " --range-len=" + str(self.range_len)
        proc = subprocess.Popen(get_lba_status_cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                encoding='utf-8')
        get_lba_status_output = proc.communicate()[0]
        print("\n" + get_lba_status_output + "\n")
        err = proc.wait()
        return err

    def test_get_lba_status(self):
        """ Testcase main """
        self.assertEqual(self.get_lba_status(), 0)
