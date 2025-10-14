# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli
#
# Copyright (c) 2022 Samsung Electronics Co., Ltd. All Rights Reserved.
#
# Author: Arunpandian J <apj.arun@samsung.com>

"""
NVMe Verify Testcase:-

    1. Issue verify command on set of block; shall pass.

"""

from nvme_test import TestNVMe, to_decimal


class TestNVMeVerify(TestNVMe):

    """
    Represents NVMe Verify testcase.
        - Attributes:
              - start_block : starting block of to verify operation.
              - test_log_dir : directory for logs, temp files.
    """

    def verify_cmd_supported(self):
        """ Wrapper for extracting optional NVM 'verify' command support
            - Args:
                - None
            - Returns:
                - True if 'verify' is supported, otherwise False
        """
        return to_decimal(self.get_id_ctrl_field_value("oncs")) & (1 << 7)

    def setUp(self):
        """ Pre Section for TestNVMeVerify """
        super().setUp()
        if not self.verify_cmd_supported():
            self.skipTest(
                "because: Optional NVM Command 'Verify' (NVMVFYS) not supported")
        self.start_block = 0
        self.block_count = 0
        self.namespace = 1
        self.setup_log_dir(self.__class__.__name__)

    def tearDown(self):
        """ Post Section for TestNVMeVerify """
        super().tearDown()

    def verify(self):
        """ Wrapper for nvme verify
            - Args:
                - None
            - Returns:
                - return code for nvme verify command.
        """
        verify_cmd = f"{self.nvme_bin} verify {self.ctrl} " + \
            f"--namespace-id={str(self.namespace)} " + \
            f"--start-block={str(self.start_block)} " + \
            f"--block-count={str(self.block_count)}"
        return self.exec_cmd(verify_cmd)

    def test_verify(self):
        """ Testcase main """
        self.assertEqual(self.verify(), 0)
