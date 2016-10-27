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
NVMe Compare Command Testcase:-

    1. Create a data file 1 with pattern 1515 to write.
    2. Create a data file 2 with pattern 2525 to compare with.
    3. Write a block of data pattern using data file1.
    4. Compare written block to data file 2's pattern; shall fail.
    5. Compare written block to data file1's pattern; shall pass.

"""

from nose.tools import assert_equal, assert_not_equal
from nvme_test_io import TestNVMeIO


class TestNVMeCompareCmd(TestNVMeIO):

    """
    Represents Compare Testcase. Inherits TestNVMeIO class.

        - Attributes:
              - data_size : data size to perform IO.
              - start_block : starting block of to perform IO.
              - compare_file : data file to use in nvme comapre commmand.
              - test_log_dir : directory for logs, temp files.
    """

    def __init__(self):
        """ Pre Section for TestNVMeCompareCmd """
        TestNVMeIO.__init__(self)
        self.data_size = 1024
        self.start_block = 1023
        self.setup_log_dir(self.__class__.__name__)
        self.compare_file = self.test_log_dir + "/" + "compare_file.txt"
        self.write_file = self.test_log_dir + "/" + self.write_file
        self.create_data_file(self.write_file, self.data_size, "15")
        self.create_data_file(self.compare_file, self.data_size, "25")

    def __del__(self):
        """ Post Section for TestNVMeCompareCmd """
        TestNVMeIO.__del__(self)

    def nvme_compare(self, cmp_file):
        """ Wrapper for nvme compare command.
           - Args:
               - cmp_file : data file used in nvme compare command.
           - Returns:
               - return code of the nvme compare command.
        """
        compare_cmd = "nvme compare " + self.ns1 + " --start-block=" + \
                      str(self.start_block) + " --block-count=" + \
                      str(self.block_count) + " --data-size=" + \
                      str(self.data_size) + " --data=" + cmp_file
        return self.exec_cmd(compare_cmd)

    def test_nvme_compare(self):
        """ Testcase main """
        assert_equal(self.nvme_write(), 0)
        assert_not_equal(self.nvme_compare(self.compare_file), 0)
        assert_equal(self.nvme_compare(self.write_file), 0)
