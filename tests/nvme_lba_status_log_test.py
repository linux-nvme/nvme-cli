# SPDX-License-Identifier: GPL-2.0-only
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

from nose.tools import assert_equal
from nvme_test import TestNVMe


class TestNVMeLbaStatLogCmd(TestNVMe):

    """
    Represents LBA Status Log test.
    """

    def __init__(self):
        """ Pre Section for TestNVMeLbaStatLogCmd. """
        TestNVMe.__init__(self)
        self.setup_log_dir(self.__class__.__name__)

    def __del__(self):
        """
        Post Section for TestNVMeLbaStatLogCmd.

            - Call super class's destructor.
        """
        TestNVMe.__del__(self)

    def get_lba_stat_log(self):
        """ Wrapper for executing nvme lba-status-log.
            - Args:
                - None
            - Returns:
                - 0 on success, error code on failure.
        """
        err = 0
        lba_stat_log_cmd = "nvme lba-status-log " + self.ctrl
        proc = subprocess.Popen(lba_stat_log_cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                encoding='utf-8')
        lba_stat_log_output = proc.communicate()[0]
        print("\n" + lba_stat_log_output + "\n")
        err = proc.wait()
        return err

    def test_lba_stat_log(self):
        """ Testcase main """
        assert_equal(self.get_lba_stat_log(), 0)
