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
NVMe Smart Log Verification Testcase:-

    1. Execute smat-log on controller.
    2. Execute smart-log on each available namespace.

"""

from nose.tools import assert_equal
from nvme_test import TestNVMe


class TestNVMeSmartLogCmd(TestNVMe):

    """
    Represents Smart Log testcae.

        - Attributes:
    """

    def __init__(self):
        """ Pre Section for TestNVMeSmartLogCmd """
        TestNVMe.__init__(self)
        self.setup_log_dir(self.__class__.__name__)

    def __del__(self):
        """
        Post Section for TestNVMeSmartLogCmd

            - Call super class's destructor.
        """
        TestNVMe.__del__(self)

    def get_smart_log_ctrl(self):
        """ Wrapper for executing smart-log on controller.
            - Args:
                - None:
            - Returns:
                - 0 on success, error code on failure.
        """
        return self.get_smart_log("0xFFFFFFFF")

    def get_smart_log_ns(self, nsid):
        """ Wrapper for executing smart-log on a namespace.
            - Args:
                - nsid: namespace id to be used in smart-log command.
            - Returns:
                - 0 on success, error code on failure.
        """
        return self.get_smart_log(nsid)

    def get_smart_log_all_ns(self):
        """ Wrapper for executing smart-log on all the namespaces.
            - Args:
                - None:
            - Returns:
                - 0 on success, error code on failure.
        """
        ns_list = self.get_ns_list()
        for nsid in range(0, len(ns_list)):
            self.get_smart_log_ns(ns_list[nsid])
        return 0

    def test_smart_log(self):
        """ Testcase main """
        assert_equal(self.get_smart_log_ctrl(), 0)
        assert_equal(self.get_smart_log_all_ns(), 0)
