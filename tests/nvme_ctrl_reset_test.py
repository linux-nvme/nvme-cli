# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli
#
# Copyright (c) 2023 Samsung Electronics Co., Ltd. All Rights Reserved.
#
# Author: Arunpandian J <arun.j@samsung.com>

"""
NVMe controller reset Testcase:-

    1. Execute nvme controller reset.

"""

from nvme_test import TestNVMe


class TestNVMeCtrlReset(TestNVMe):

    """
    Represents NVMe Controller reset testcase.
        - Attributes:
              - test_log_dir :  directory for logs, temp files.
    """

    def setUp(self):
        """ Pre Section for TestNVMeCtrlReset """
        super().setUp()
        self.setup_log_dir(self.__class__.__name__)

    def tearDown(self):
        """ Post Section for TestNVMeCtrlReset """
        super().tearDown()

    def ctrl_reset(self):
        """ Wrapper for nvme controller reset
            - Args:
                - None
            - Returns:
                - return code for nvme controller reset.
        """
        ctrl_reset_cmd = f"{self.nvme_bin} reset {self.ctrl}"
        return self.exec_cmd(ctrl_reset_cmd)

    def test_ctrl_reset(self):
        """ Testcase main """
        self.assertEqual(self.ctrl_reset(), 0)
        # Check if sqs and cqs are setup again and I/O operations are possible
        self.run_ns_io(self.default_nsid, 0, 10)
