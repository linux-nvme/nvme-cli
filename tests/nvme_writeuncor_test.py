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
NVMe Write Compare Testcae:-

    1. Read block of data successfully.
    2. Issue write uncorrectable to block of data.
    3. Attempt to read from same block; shall fail.
    4. Issue a write command to first block of data.
    5. Read from the same block; shall pass.

"""

from nose.tools import assert_equal, assert_not_equal
from nvme_test_io import TestNVMeIO


class TestNVMeUncor(TestNVMeIO):

    """
    Represents NVMe Write Uncorrecatble testcase.
        - Attributes:
              - start_block : starting block of to perform IO.
              - test_log_dir : directory for logs, temp files.
    """

    def __init__(self):
        """ Constructor TestNVMeUncor """
        TestNVMeIO.__init__(self)
        self.start_block = 1023
        self.setup_log_dir(self.__class__.__name__)
        self.write_file = self.test_log_dir + "/" + self.write_file
        self.read_file = self.test_log_dir + "/" + self.read_file
        self.create_data_file(self.write_file, self.data_size, "15")
        open(self.read_file, 'a').close()

    def __del__(self):
        """ Post Section for TestNVMeUncor """
        TestNVMeIO.__del__(self)

    def write_uncor(self):
        """ Wrapper for nvme write uncorrectable
            - Args:
                - None
            - Returns:
                - return code of nvme write uncorrectable command.
        """
        write_uncor_cmd = "nvme write-uncor " + self.ns1 + \
                          " --start-block=" + str(self.start_block) + \
                          " --block-count=" + str(self.block_count)
        return self.exec_cmd(write_uncor_cmd)

    def test_write_uncor(self):
        """ Testcase main """
        assert_equal(self.nvme_read(), 0)
        assert_equal(self.write_uncor(), 0)
        assert_not_equal(self.nvme_read(), 0)
        assert_equal(self.nvme_write(), 0)
        assert_equal(self.nvme_read(), 0)
