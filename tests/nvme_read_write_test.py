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
NVMe Read/Write Testcae:-

    1. Create data file with specific pattern outside of the device under test.
    2. Write data file on the namespace under test.
    3. Read the data from the namespace under test into different file.
    4. Compare file in #1 and #3.
"""

import filecmp

from nvme_test_io import TestNVMeIO


class TestNVMeReadWriteTest(TestNVMeIO):

    """
    Represents NVMe read, write testcase.

        - Attributes:
              - start_block : starting block of to perform IO.
              - compare_file : data file to use in nvme compare command.
              - test_log_dir : directory for logs, temp files.
    """

    def setUp(self):
        """ Pre Section for TestNVMeReadWriteTest """
        super().setUp()
        self.start_block = 1023
        self.test_log_dir = self.log_dir + "/" + self.__class__.__name__
        self.setup_log_dir(self.__class__.__name__)
        self.write_file = self.test_log_dir + "/" + self.write_file
        self.read_file = self.test_log_dir + "/" + self.read_file
        self.create_data_file(self.write_file, self.data_size, "15")
        open(self.read_file, 'a').close()

    def tearDown(self):
        """ Post Section for TestNVMeReadWriteTest """
        super().tearDown()

    def read_validate(self):
        """ Validate the data file read
            - Args:
                - None
            - Returns:
                - returns 0 on success, 1 on failure.
        """
        return 0 if filecmp.cmp(self.read_file, self.write_file) else 1

    def test_nvme_write(self):
        """ Testcaes main  """
        self.assertEqual(self.nvme_write(), 0)
        self.assertEqual(self.nvme_read(), 0)
        self.assertEqual(self.read_validate(), 0)
