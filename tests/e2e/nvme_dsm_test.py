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
    2. Issue DSM command with the Deallocate attribute; shall pass.
    3. Issue DSM command with the integral dataset attributes; shall be
       rejected on Windows, where DSM is translated to SCSI UNMAP.

"""

from ..nvme_test import TestNVMe


class TestNVMeDsm(TestNVMe):

    """
    Represents NVMe DSM testcase.
        - Attributes:
              - start_block :   starting block of the DSM operation.
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

    def dsm(self, attributes=""):
        """ Wrapper for nvme dsm
            - Args:
                - attributes : extra attribute options to pass to the command.
            - Returns:
                - return code for nvme dsm command.
        """
        dsm_cmd = f"{self.nvme_bin} dsm {self.ctrl} " + \
            f"--namespace-id={str(self.namespace)} " + \
            f"--blocks={str(self.range)} --slbs={str(self.start_block)}"
        if attributes:
            dsm_cmd += f" {attributes}"
        return self.exec_cmd(dsm_cmd)

    def test_dsm(self):
        """ Testcase main """
        if self.is_windows():
            # Windows only supports DSM with Deallocate and no integral dataset attributes
            self.assertNotEqual(self.dsm(), 0)
            self.assertEqual(self.dsm("--ad"), 0)
            self.assertNotEqual(self.dsm("--ad --idr"), 0)
            self.assertNotEqual(self.dsm("--ad --idw"), 0)
        else:
            self.assertEqual(self.dsm(), 0)
