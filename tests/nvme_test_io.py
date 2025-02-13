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
""" Inherit TestNVMeIO for nvme read/write operations """

import os

from nvme_test import TestNVMe


class TestNVMeIO(TestNVMe):

    """
    Variable and Methods required to perform nvme read/write.

        - Attributes:
              - data_size : data size to perform IO.
              - start_block : starting block of to perform IO.
              - block_count : Number of blocks to use in IO.
              - write_file : data file to use in nvme write command.
              - read_file : data file to use in nvme read command.
    """

    def setUp(self):
        """ Pre Section for TestNVMeIO """
        super().setUp()
        # common code used in various testcases.
        (self.data_size, _) = self.get_lba_format_size()
        self.start_block = 0
        self.block_count = 0
        self.write_file = "write_file.txt"
        self.read_file = "read_file.txt"

    def tearDown(self):
        """ Post Section for TestNVMeIO """
        super().tearDown()

    def create_data_file(self, pathname, data_size, pattern):
        """ Creates data file with specific pattern
            - Args:
                - pathname : data file path name.
                - data_size : total size of the data.
                - pattern : data pattern to create file.
            - Returns:
            None
        """
        pattern_len = len(pattern)
        data_file = open(pathname, "w")
        for i in range(0, data_size):
            data_file.write(pattern[i % pattern_len])
        data_file.flush()
        os.fsync(data_file.fileno())
        data_file.close()

    def nvme_write(self):
        """ Wrapper for nvme write operation
            - Args:
                - None
            - Returns:
                - return code for nvme write command.
        """
        write_cmd = f"{self.nvme_bin} write {self.ns1} " + \
            f"--start-block={str(self.start_block)} " + \
            f"--block-count={str(self.block_count)} " + \
            f"--data-size={str(self.data_size)} --data={self.write_file}"
        return self.exec_cmd(write_cmd)

    def nvme_read(self):
        """ Wrapper for nvme read operation
            - Args:
                - None
            - Returns:
                - return code for nvme read command.
        """
        read_cmd = f"{self.nvme_bin} read {self.ns1} " + \
            f"--start-block={str(self.start_block)} " + \
            f"--block-count={str(self.block_count)} " + \
            f"--data-size={str(self.data_size)} --data={self.read_file}"
        return self.exec_cmd(read_cmd)
