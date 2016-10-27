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
#   Author: Chaitanya Kulkarni <chaitanya.kulkarni@hgst.com>
#
"""
NVMe Flush Command Testcase:-

    1. Execute nvme flush on controller.

"""

from nose.tools import assert_equal
from nvme_test import TestNVMe


class TestNVMeFlushCmd(TestNVMe):

    """
    Represents Flush Testcase. Inherits TestNVMe class.

        - Attributes:
    """

    def __init__(self):
        """ Pre Section for TestNVMeFlushCmd """
        TestNVMe.__init__(self)
        self.setup_log_dir(self.__class__.__name__)

    def __del__(self):
        """ Post Section for TestNVMeFlushCmd """
        TestNVMe.__del__(self)

    def nvme_flush(self):
        """ Wrapper for nvme flush command.
           - Args:
               - None
           - Returns:
               - None
        """
        flush_cmd = "nvme flush " + self.ctrl + " -n " + str(self.default_nsid)
        print flush_cmd
        return self.exec_cmd(flush_cmd)

    def test_nvme_flush(self):
        """ Testcase main """
        assert_equal(self.nvme_flush(), 0)
