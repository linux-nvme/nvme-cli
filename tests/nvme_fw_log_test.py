# Copyright (c) 2015-2016 Western Digital Corporation or its affiliates.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA  02110-1301, USA.
#
#   Author: Madhusudhana S.J <madhusudhana.sj@wdc.com>
#   Author: Dong Ho <dong.ho@wdc.com>
#
"""
NVMe Firmware Log Testcase :-

    1. Execute fw-log on a device.
"""

import subprocess
from nose.tools import assert_equal
from nvme_test import TestNVMe


class TestNVMeFwLogCmd(TestNVMe):

    """
    Represents NVMe Firmware Log test.
    """

    def __init__(self):
        """ Pre Section for TestNVMeFwLogCmd. """
        TestNVMe.__init__(self)
        self.setup_log_dir(self.__class__.__name__)

    def __del__(self):
        """
        Post Section for TestNVMeSimpleTestTemplate.

            - Call super class's destructor.
        """
        TestNVMe.__del__(self)

    def get_fw_log(self):
        """ Wrapper for executing nvme fw-log.
            - Args:
                - None
            - Returns:
                - 0 on success, error code on failure.
        """
        err = 0
        fw_log_cmd = "nvme fw-log " + self.ctrl
        proc = subprocess.Popen(fw_log_cmd,
                                shell=True,
                                stdout=subprocess.PIPE)
        fw_log_output = proc.communicate()[0]
        print(fw_log_output + "\n")
        err = proc.wait()
        return err

    def test_fw_log(self):
        """ Testcase main """
        assert_equal(self.get_fw_log(), 0)
