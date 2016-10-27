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
NVMe Write Zeros:-

    1. Issue a write command to block of data.
    2. Read from same block to verify data pattern.
    3. Issue write zeros to the block of data.
    4. Read from same block, should be all zeroes.

"""

import filecmp
from nose.tools import assert_equal
from nvme_test_io import TestNVMeIO


class TestNVMeWriteZeros(TestNVMeIO):

    """
    Represents NVMe Write Zero Testcase.

        - Attributes:
              - zero_file : file with all '\0' to compare the zero data.
              - data_size : data size to perform IO.
              - start_block : starting block of to perform IO.
              - block_count: Number of blocks to use in IO.
              - test_log_dir : directory for logs, temp files.
    """
    def __init__(self):
        """ Pre Section for TestNVMeWriteZeros """
        TestNVMeIO.__init__(self)
        self.start_block = 1023
        self.block_count = 0
        self.setup_log_dir(self.__class__.__name__)
        self.write_file = self.test_log_dir + "/" + self.write_file
        self.read_file = self.test_log_dir + "/" + self.read_file
        self.zero_file = self.test_log_dir + "/" + "zero_file.txt"
        self.create_data_file(self.write_file, self.data_size, "15")
        self.create_data_file(self.zero_file, self.data_size, '\0')
        open(self.read_file, 'a').close()

    def __del__(self):
        """ Post Section for TestNVMeWriteZeros """
        TestNVMeIO.__del__(self)

    def write_zeroes(self):
        """ Wrapper for nvme write-zeroe
            - Args:
                - None
            - Returns:
                - return code for nvme write command.
        """
        write_zeroes_cmd = "nvme write-zeroes " + self.ns1 + \
                           " --start-block=" + str(self.start_block) + \
                           " --block-count=" + str(self.block_count)
        return self.exec_cmd(write_zeroes_cmd)

    def validate_write_read(self):
        """ Validate the file which had been read from the device
            - Args:
                - None
            - Returns:
                - 0 on success, 1 on failure
        """
        return 0 if filecmp.cmp(self.write_file, self.read_file) is True else 1

    def validate_zeroes(self):
        """
        Validate the data which is zeroed out via write-zeroes
            - Args:
                - None
            - Returns:
                - 0 on success, 1 on failure
         """
        return 0 if filecmp.cmp(self.zero_file, self.read_file) is True else 1

    def test_write_zeros(self):
        """ Testcae main """
        assert_equal(self.nvme_write(), 0)
        assert_equal(self.nvme_read(), 0)
        assert_equal(self.validate_write_read(), 0)
        assert_equal(self.write_zeroes(), 0)
        assert_equal(self.nvme_read(), 0)
        assert_equal(self.validate_zeroes(), 0)
