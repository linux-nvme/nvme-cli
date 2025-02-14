# SPDX-License-Identifier: GPL-2.0-or-later
#
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

from nvme_test import to_decimal
from nvme_test_io import TestNVMeIO


class TestNVMeCompareCmd(TestNVMeIO):

    """
    Represents Compare Testcase. Inherits TestNVMeIO class.

        - Attributes:
              - data_size : data size to perform IO.
              - start_block : starting block of to perform IO.
              - compare_file : data file to use in nvme compare command.
              - test_log_dir : directory for logs, temp files.
    """

    def compare_cmd_supported(self):
        """ Wrapper for extracting optional NVM 'compare' command support
            - Args:
                - None
            - Returns:
                - True if 'compare' is supported, otherwise False
        """
        return to_decimal(self.get_id_ctrl_field_value("oncs")) & (1 << 0)

    def setUp(self):
        """ Pre Section for TestNVMeCompareCmd """
        super().setUp()
        if not self.compare_cmd_supported():
            self.skipTest("because: Optional NVM Command 'Compare' (NVMCMPS) not supported")
        self.data_size = 1024
        self.start_block = 1023
        self.setup_log_dir(self.__class__.__name__)
        self.compare_file = self.test_log_dir + "/" + "compare_file.txt"
        self.write_file = self.test_log_dir + "/" + self.write_file
        self.create_data_file(self.write_file, self.data_size, "15")
        self.create_data_file(self.compare_file, self.data_size, "25")

    def tearDown(self):
        """ Post Section for TestNVMeCompareCmd """
        super().tearDown()

    def nvme_compare(self, cmp_file):
        """ Wrapper for nvme compare command.
           - Args:
               - cmp_file : data file used in nvme compare command.
           - Returns:
               - return code of the nvme compare command.
        """
        compare_cmd = f"{self.nvme_bin} compare {self.ns1} " + \
            f"--start-block={str(self.start_block)} " + \
            f"--block-count={str(self.block_count)} " + \
            f"--data-size={str(self.data_size)} --data={cmp_file}"
        return self.exec_cmd(compare_cmd)

    def test_nvme_compare(self):
        """ Testcase main """
        self.assertEqual(self.nvme_write(), 0)
        self.assertNotEqual(self.nvme_compare(self.compare_file), 0)
        self.assertEqual(self.nvme_compare(self.write_file), 0)
