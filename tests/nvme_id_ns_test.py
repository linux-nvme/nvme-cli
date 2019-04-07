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
NVme Identify Namespace Testcase:-

    1. Execute id-ns on a namespace
    2. Execute id-ns on all namespaces
"""

import subprocess
from nose.tools import assert_equal
from nvme_test import TestNVMe


class TestNVMeIdentifyNamespace(TestNVMe):

    """
    Represents Identify Namesepace testcase
    """

    def __init__(self):
        """ Pre Section for TestNVMeIdentifyNamespace. """
        TestNVMe.__init__(self)
        self.setup_log_dir(self.__class__.__name__)
        self.ns_list = self.get_ns_list()

    def __del__(self):
        """
        Post Section for TestNVMeIdentifyNamespace

            - Call super class's destructor.
        """
        TestNVMe.__del__(self)

    def get_id_ns(self, nsid):
        """
        Wrapper for executing nvme id-ns on a namespace.
            - Args:
                - nsid : namespace id to get info from.
            - Returns:
                - 0 on success, error code on failure.
        """
        err = 0
        id_ns_cmd = "nvme id-ns " + self.ctrl + "n" + str(nsid)
        proc = subprocess.Popen(id_ns_cmd,
                                shell=True,
                                stdout=subprocess.PIPE)
        id_ns_output = proc.communicate()[0]
        print(id_ns_output + "\n")
        err = proc.wait()
        return err

    def get_id_ns_all(self):
        """
        Wrapper for executing nvme id-ns on all namespaces.
            - Args:
                - None
            - Returns:
                - 0 on success, error code on failure.
        """
        err = 0
        for namespace  in self.ns_list:
            err = self.get_id_ns(str(namespace).split("x", 1)[1])
        return err

    def test_id_ns(self):
        """ Testcase main """
        assert_equal(self.get_id_ns(1), 0)
        assert_equal(self.get_id_ns_all(), 0)
