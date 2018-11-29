
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
NVMe Identify ctrl Testcase:-

  1. Execute id-ctrl on ctrl
  2. Execute id-ctrl vendor specific on ctrl

"""

from nose.tools import assert_equal
from nvme_test import TestNVMe


class TestNVMeIdctrlCmd(TestNVMe):

    """
    Represents Id ctrl testcase
    """

    def __init__(self):
        """ Pre Section for TestNVMeIdctrlCmd. """
        TestNVMe.__init__(self)
        self.setup_log_dir(self.__class__.__name__)

    def __del__(self):
        """ Post Section for TestNVMeIdctrlCmd

            Call super class's destructor.
        """
        TestNVMe.__del__(self)

    def test_id_ctrl(self):
        """ Testcase main """
        vendor = True
        assert_equal(self.get_id_ctrl(), 0)
        assert_equal(self.get_id_ctrl(vendor), 0)
