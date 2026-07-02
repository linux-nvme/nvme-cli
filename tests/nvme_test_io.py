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
        self._init_io_params()

    def _init_io_params(self):
        """ (Re)compute the IO parameters (metadata size, prinfo, data size and
            the data/metadata file basenames) for the namespace currently under
            test. This is also called after a testcase reformats the namespace
            to a different LBA format so that the parameters match the new
            format.
        """
        self.ms, self.prinfo, self.data_size = self._get_rw_io_params_per_lba()
        self.start_block = 0
        self.block_count = 0
        self.write_file = "write_file.txt"
        self.read_file = "read_file.txt"
        # Basename only; subclasses must prepend the test_log_dir path before
        # use (same convention as write_file and read_file above).
        if self.ms > 0 and not self.ns_meta_ext:
            self.write_meta_file = "write_meta_file.bin"
            self.read_meta_file = "read_meta_file.bin"
        else:
            self.write_meta_file = None
            self.read_meta_file = None

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

    def create_meta_file(self, pathname, meta_size):
        """ Creates a binary file of meta_size zero bytes for use as a
            separate-metadata buffer in nvme write/read/compare commands.
            - Args:
                - pathname : metadata file path name.
                - meta_size : total size of the metadata in bytes.
            - Returns:
            None
        """
        with open(pathname, "wb") as meta_file:
            meta_file.write(bytes(meta_size))

    def nvme_write(self):
        """ Wrapper for nvme write operation
            - Args:
                - None
            - Returns:
                - return code for nvme write command.
        """
        metadata_size = self.ms if self.ms > 0 and not self.ns_meta_ext else 0
        write_cmd = self._build_nvme_rw_cmd("write", self.ns1, self.start_block,
                                            self.block_count,self.data_size,
                                            self.write_file, self.prinfo,
                                            metadata_size, self.write_meta_file)
        return self.exec_cmd(write_cmd)

    def nvme_read(self):
        """ Wrapper for nvme read operation
            - Args:
                - None
            - Returns:
                - return code for nvme read command.
        """
        metadata_size = self.ms if self.ms > 0 and not self.ns_meta_ext else 0
        read_cmd = self._build_nvme_rw_cmd("read", self.ns1, self.start_block,
                                           self.block_count, self.data_size,
                                           self.read_file, self.prinfo,
                                           metadata_size, self.read_meta_file)
        return self.exec_cmd(read_cmd)
