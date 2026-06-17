# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Western Digital Corporation or its affiliates.
#
#   Author: Dennis Maisenbacher <dennis.maisenbacher@wdc.com>
#
"""
NVMe QPIF (Qualified Protection Information Format) Testcase:-

    1. Look for an available LBA format that supports the Qualified Protection
       Information Format (PIF == Qualified Type with a Storage Tag defined) and
       reformat the device under test to use it (with end-to-end protection
       enabled).
    2. Create a data file with a specific pattern outside the device under test.
    3. Write the data file to the namespace using the Storage Tag fields exposed
       by the Qualified Protection Information Format.
    4. Read the data back into a different file.
    5. Compare the file from step 2 with the file from step 4.

    NOTE: Reformatting the device requires Namespace Management.
    The test is skipped if namespace management is unavailable or if no LBA format
    supports a Qualified Protection Information Format with a Storage Tag.
"""

import filecmp

from nvme_test_io import TestNVMeIO


class TestNVMeQPIFTest(TestNVMeIO):

    """
    NVMe QPIF write/read/compare testcase.

        - Attributes:
              - start_block : starting block to perform IO.
              - storage_tag : Storage Tag value passed to the I/O commands.
              - test_log_dir : directory for logs, temp files.
    """

    def setUp(self):
        """ Pre Section for TestNVMeQPIFTest """
        super().setUp()
        self.original_lbafee = None

        # Reformatting the device to a QPIF capable LBA format with a non-zero
        # Storage Tag Size.
        if not self.ns_mgmt_supported:
            self.skipTest("Namespace Management / Attach not supported; "
                          "cannot format a QPIF namespace")

        lbaf_index = self.find_qpif_lbaf()
        if lbaf_index is None:
            self.skipTest("no LBA format with a Qualified Protection "
                          "Information Format and a Storage Tag found")

        self.setup_qpif_ns(lbaf_index)

        self.start_block = 1023
        self.storage_tag = 0x1
        self.test_log_dir = self.log_dir + "/" + self.__class__.__name__
        self.setup_log_dir(self.__class__.__name__)
        self.write_file = self.test_log_dir + "/" + self.write_file
        self.read_file = self.test_log_dir + "/" + self.read_file
        self.create_data_file(self.write_file, self.data_size, "15")
        open(self.read_file, 'a').close()
        if self.ms > 0 and not self.ns_meta_ext:
            self.write_meta_file = self.test_log_dir + "/" + self.write_meta_file
            self.read_meta_file = self.test_log_dir + "/" + self.read_meta_file
            self.create_meta_file(self.write_meta_file, self.ms)

    def tearDown(self):
        """ Post Section for TestNVMeQPIFTest """
        if self.original_lbafee is not None:
            self.run_cmd(f"{self.nvme_bin} feat host-behavior-support "
                         f"{self.ctrl} --lbafee={self.original_lbafee}")
        super().tearDown()

    def find_qpif_lbaf(self):
        """ Search the NVM Command Set Identify Namespace data structure for an
            available LBA format that uses the Qualified Protection Information
            Format.

            A format qualifies when the namespace advertises Qualified
            Protection Information Format Support (QPIFS, bit 3 of PIC) and the
            extended LBA format has its Protection Information Format (PIF) field
            set to Qualified Type (3) with a non-zero Storage Tag Size (STS) so
            that a Storage Tag field is defined.
            - Args:
                - None
            - Returns:
                - lbaf index (int) of a qualifying format, or None if none
                  exists or nvm-id-ns is not supported.
        """
        nvm_id_ns_cmd = f"{self.nvme_bin} nvm-id-ns {self.ns1} " + \
            "--output-format=json"
        result = self.run_cmd(nvm_id_ns_cmd)
        if result.returncode != 0:
            return None
        json_output = self.parse_json_output(result.stdout, "nvme nvm-id-ns")
        if not (int(json_output.get('pic', 0)) & 0x8):
            return None
        elbafs = json_output.get('elbafs', [])
        self.assertIsInstance(elbafs, list,
                              f"ERROR : nvm-id-ns returned invalid elbafs type: {type(elbafs).__name__}")
        for i, elbaf in enumerate(elbafs):
            self.assertIsInstance(elbaf, dict,
                                  f"ERROR : invalid elbaf entry: {elbaf!r}")
            if int(elbaf.get('pif', 0)) == 3 and int(elbaf.get('sts', 0)) != 0:
                return i
        return None

    def build_dps(self):
        """ Build a Data Protection Type Settings (DPS) value that enables a
            Protection Information type supported by the namespace. QPIF only
            applies when end-to-end protection is enabled.

            The supported PI types and placements are read from the Data
            Protection Capabilities (DPC) field of id-ns:
              DPC bits 2:0 - PI Type 1/2/3 supported
              DPC bit 3    - PI in the first eight bytes of metadata supported
              DPC bit 4    - PI in the last eight bytes of metadata supported
            - Args:
                - None
            - Returns:
                - dps value (int), or None if no PI type is supported.
        """
        dpc = int(self.get_id_ns_field_value("dpc"))
        pi_type = next((t for t in (1, 2, 3) if dpc & (1 << (t - 1))), 0)
        if pi_type == 0:
            return None
        if dpc & (1 << 3):
            return pi_type | (1 << 3)
        return pi_type

    def enable_lbafee(self):
        """ Best-effort enable of the host LBA Format Extension Enable (LBAFEE)
            setting, which a controller may require before creating a namespace
            with an extended (e.g. QPIF) LBA format. The previous value is saved
            in self.original_lbafee so tearDown can restore it.
            - Args:
                - None
            - Returns:
                - None
        """
        get_cmd = f"{self.nvme_bin} feat host-behavior-support " + \
            f"{self.ctrl} --output-format=json"
        result = self.run_cmd(get_cmd)
        if result.returncode != 0:
            return
        data = self.parse_json_output(result.stdout, "nvme feat host-behavior-support")
        fields = data.get("Feature: 0x16", [{}])[0]
        enabled = fields.get("LBA Format Extension Enable (LBAFEE)") == "True"
        if enabled:
            return
        self.original_lbafee = 0
        self.run_cmd(f"{self.nvme_bin} feat host-behavior-support "
                     f"{self.ctrl} --lbafee=1")

    def setup_qpif_ns(self, lbaf_index):
        """ Delete the existing namespace(s) and recreate the default namespace
            using the QPIF capable LBA format with end-to-end protection
            enabled, attach it, and recompute the IO parameters for the new
            namespace.
            - Args:
                - lbaf_index : index of the QPIF capable LBA format.
            - Returns:
                - None
        """
        dps = self.build_dps()
        if dps is None:
            self.skipTest("namespace does not support any Protection "
                          "Information type required for QPIF")

        self.enable_lbafee()

        # Encode lbaf_index into the 8-bit flbas field:
        #   flbas[3:0] = lbaf_index[3:0], flbas[6:5] = lbaf_index[5:4]
        flbas = (lbaf_index & 0xF) | (((lbaf_index >> 4) & 0x3) << 5)

        # get_lba_format_size() indexes the id-ns lbafs[] array by self.flbas.
        self.flbas = lbaf_index
        (ds, ms) = self.get_lba_format_size()
        if ds == 0:
            self.skipTest(f"lbaf {lbaf_index} reports zero data size")
        ncap = int(self.get_ncap() / (ds + ms))

        ctrl_id = self.get_ctrl_id()
        self.delete_all_ns()
        err = self.create_and_validate_ns(self.default_nsid, ncap, ncap, flbas, dps)
        self.assertEqual(err, 0,
                         f"ERROR: failed to create QPIF namespace with lbaf "
                         f"{lbaf_index} (flbas={flbas:#x}, dps={dps:#x})")
        self.assertEqual(self.attach_ns(ctrl_id, self.default_nsid), 0,
                         "ERROR: failed to attach QPIF namespace")

        # Refresh the protection/format attributes and recompute the IO
        # parameters (data/metadata sizes, prinfo) for the new namespace.
        self.ns_dps = self._get_ns_dps()
        self.ns_meta_ext = self._is_metadata_ext()
        self.pif = self._get_pif()
        self._init_io_params()

    def nvme_write_qpif(self):
        """ Write data with the Storage Tag (QPIF) fields set.
            - Args:
                - None
            - Returns:
                - return code for the nvme write command.
        """
        write_cmd = f"{self.nvme_bin} write {self.ns1} " + \
            f"--start-block={str(self.start_block)} " + \
            f"--block-count={str(self.block_count)} " + \
            f"--data-size={str(self.data_size)} --data={self.write_file} " + \
            f"--storage-tag={hex(self.storage_tag)} --storage-tag-check"
        if self.prinfo:
            write_cmd += f" --prinfo={self.prinfo}"
        if self.ms > 0 and not self.ns_meta_ext:
            write_cmd += \
                f" --metadata-size={self.ms} --metadata={self.write_meta_file}"
        return self.exec_cmd(write_cmd)

    def nvme_read_qpif(self):
        """ Read data back with the Storage Tag (QPIF) fields set.
            - Args:
                - None
            - Returns:
                - return code for the nvme read command.
        """
        read_cmd = f"{self.nvme_bin} read {self.ns1} " + \
            f"--start-block={str(self.start_block)} " + \
            f"--block-count={str(self.block_count)} " + \
            f"--data-size={str(self.data_size)} --data={self.read_file} " + \
            f"--storage-tag={hex(self.storage_tag)} --storage-tag-check"
        if self.prinfo:
            read_cmd += f" --prinfo={self.prinfo}"
        if self.ms > 0 and not self.ns_meta_ext:
            read_cmd += \
                f" --metadata-size={self.ms} --metadata={self.read_meta_file}"
        return self.exec_cmd(read_cmd)

    def read_validate(self):
        """ Validate the data file read
            - Args:
                - None
            - Returns:
                - returns 0 on success, 1 on failure.
        """
        return 0 if filecmp.cmp(self.read_file, self.write_file) else 1

    def test_nvme_write_qpif(self):
        """ Testcase main """
        self.assertEqual(self.nvme_write_qpif(), 0)
        self.assertEqual(self.nvme_read_qpif(), 0)
        self.assertEqual(self.read_validate(), 0)
