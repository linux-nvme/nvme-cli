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
        (ds, ms) = self.get_lba_format_size()
        self.ms = ms
        # PI type occupies bits 2:0 of the DPS field; bits 5:3 are PIF.
        pi_type = self.ns_dps & 0x7
        if pi_type != 0 and ms != 0 and self.ns_meta_ext:
            # PI active + extended LBA (metadata appended to data buffer).
            # Use PRACT=1 (--prinfo=8) so the controller inserts and strips PI
            # automatically.  With PRACT=1 the PI bytes are not transferred
            # over the host interface, so data_size equals the logical block
            # data size only (ds), not ds+ms.  This works for all PI sizes
            # (8 bytes for PIF 0/2, 16 bytes for PIF 1) and all guard widths
            # (16-bit, 32-bit, 64-bit CRC) because the controller handles
            # the PI entirely.
            self.prinfo = 8
            self.data_size = ds
        elif pi_type != 0 and ms != 0 and not self.ns_meta_ext:
            # PI active + separate metadata (flbas bit 4 clear).  PRACT=1
            # (--prinfo=8) is invalid for the Compare command on this format
            # (NVMe spec: PRACT=1 for Compare requires PI in the host data
            # buffer, which only applies to the extended-LBA layout).  Use
            # prinfo=0 (PRACT=0, PRCHK=0) for all operations and supply an
            # explicit zero-filled metadata buffer of ms bytes so that the
            # stored metadata and the compared metadata are both known zeros.
            # PRCHK=0 skips PI validation, so the zero PI bytes are accepted
            # by the controller on write and matched exactly on compare.  This
            # is PI-format and guard-width agnostic: the entire ms-byte
            # metadata slot (whether holding an 8-byte PI with 16-bit or
            # 32-bit guard, or a 16-byte PI with 64-bit guard) is zeroed.
            self.prinfo = 0
            self.data_size = ds
        else:
            # No PI.  For extended LBA format (metadata appended to the data
            # buffer) include the metadata bytes so that the controller sees
            # a consistent data+metadata unit.  For separate metadata format
            # (flbas bit 4 clear) the metadata is transferred via a different
            # pointer and must NOT be folded into the data buffer; use ds only
            # so that the data transfer length matches exactly one LBA.
            self.prinfo = 0
            self.data_size = ds + ms if self.ns_meta_ext else ds
        self.start_block = 0
        self.block_count = 0
        self.write_file = "write_file.txt"
        self.read_file = "read_file.txt"
        # Basename only; subclasses must prepend the test_log_dir path before
        # use (same convention as write_file and read_file above).
        if self.ms > 0 and not self.ns_meta_ext:
            self.write_meta_file = "write_meta_file.bin"
            self.read_meta_file = "read_meta_file.bin"

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
        write_cmd = f"{self.nvme_bin} write {self.ns1} " + \
            f"--start-block={str(self.start_block)} " + \
            f"--block-count={str(self.block_count)} " + \
            f"--data-size={str(self.data_size)} --data={self.write_file}"
        if self.prinfo:
            write_cmd += f" --prinfo={self.prinfo}"
        if self.ms > 0 and not self.ns_meta_ext:
            write_cmd += \
                f" --metadata-size={self.ms} --metadata={self.write_meta_file}"
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
        if self.prinfo:
            read_cmd += f" --prinfo={self.prinfo}"
        if self.ms > 0 and not self.ns_meta_ext:
            read_cmd += \
                f" --metadata-size={self.ms} --metadata={self.read_meta_file}"
        return self.exec_cmd(read_cmd)
