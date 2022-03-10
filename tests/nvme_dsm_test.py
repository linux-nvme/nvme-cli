# SPDX-License-Identifier: GPL-2.0-only
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

from nose.tools import assert_equal
from nvme_test import TestNVMe


class TestNVMeDsm(TestNVMe):

    """
    Represents NVMe Verify testcase.
        - Attributes:
              - start_block :   starting block of to verify operation.
              - range :         Range of blocks for DSM operation.
              - test_log_dir :  directory for logs, temp files.
    """

    def __init__(self):
        """ Pre Section for TestNVMeDsm """
        TestNVMe.__init__(self)
        self.start_block = 0
        self.range = 0
        self.namespace = 1
        self.setup_log_dir(self.__class__.__name__)

    def __del__(self):
        """ Post Section for TestNVMeDsm """
        TestNVMe.__del__(self)

    def dsm(self):
        """ Wrapper for nvme verify
            - Args:
                - None
            - Returns:
                - return code for nvme dsm command.
        """
        dsm_cmd = "nvme dsm " + self.ctrl + \
                  " --namespace-id=" + str(self.namespace) + \
                  " --blocks=" + str(self.range) + \
                  " --slbs=" + str(self.start_block)
        return self.exec_cmd(dsm_cmd)

    def test_dsm(self):
        """ Testcase main """
        assert_equal(self.dsm(), 0)
