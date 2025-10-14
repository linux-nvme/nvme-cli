# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli
#
# Copyright (c) 2022 Samsung Electronics Co., Ltd. All Rights Reserved.
#
# Author: Arunpandian J <apj.arun@samsung.com>

"""
NVMe DSM Testcase:-

    1. Issue DSM command on set of block; shall pass.

"""

from nvme_test import TestNVMe


class TestNVMeDsm(TestNVMe):

    """
    Represents NVMe Verify testcase.
        - Attributes:
              - start_block :   starting block of to verify operation.
              - range :         Range of blocks for DSM operation.
              - test_log_dir :  directory for logs, temp files.
    """

    def setUp(self):
        """ Pre Section for TestNVMeDsm """
        super().setUp()
        self.start_block = 0
        self.range = 0
        self.namespace = 1
        self.setup_log_dir(self.__class__.__name__)

    def tearDown(self):
        """ Post Section for TestNVMeDsm """
        super().tearDown()

    def dsm(self):
        """ Wrapper for nvme verify
            - Args:
                - None
            - Returns:
                - return code for nvme dsm command.
        """
        dsm_cmd = f"{self.nvme_bin} dsm {self.ctrl} " + \
            f"--namespace-id={str(self.namespace)} " + \
            f"--blocks={str(self.range)} --slbs={str(self.start_block)}"
        return self.exec_cmd(dsm_cmd)

    def test_dsm(self):
        """ Testcase main """
        self.assertEqual(self.dsm(), 0)
