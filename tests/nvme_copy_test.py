# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli
#
# Copyright (c) 2022 Samsung Electronics Co., Ltd. All Rights Reserved.
#
# Authors: Arunpandian J <apj.arun@samsung.com>
#          Joy Gu <jgu@purestorage.com>

"""
NVMe Copy Testcase:-

    1. Issue copy command on set of block; shall pass.
    2. If cross-namespace copy formats are supported, enable and test
       cross-namespace copy formats.

"""

import json

from nvme_test import TestNVMe


class TestNVMeCopy(TestNVMe):

    """
    Represents NVMe Copy testcase.
        - Attributes:
              - ocfs : optional copy formats supported
              - original_cdfe : saved cdfe value to restore during teardown, or None
              - test_log_dir :  directory for logs, temp files.
    """

    def setUp(self):
        """ Pre Section for TestNVMeCopy """
        super().setUp()
        self.ocfs = self.get_ocfs()
        self.original_cdfe = None
        cross_namespace_copy = self.ocfs & 0xc
        if cross_namespace_copy:
            get_features_cmd = f"{self.nvme_bin} feat host-behavior-support " + \
                f"{self.ctrl} --output-format=json"
            result = self.run_cmd(get_features_cmd)
            self.assertEqual(result.returncode, 0,
                             "ERROR : nvme feat host-behavior-support failed")
            data = json.loads(result.stdout)
            fields = data.get("Feature: 0x16", [{}])[0]
            current_cdfe = (
                (0x4 if fields.get("Copy Descriptor Format 2h Enable (CDF2E)") == "True" else 0) |
                (0x8 if fields.get("Copy Descriptor Format 3h Enable (CDF3E)") == "True" else 0) |
                (0x10 if fields.get("Copy Descriptor Format 4h Enable (CDF4E)") == "True" else 0)
            )
            if current_cdfe & cross_namespace_copy:
                print("Cross-namespace copy already enabled, skipping set-features")
            else:
                self.original_cdfe = current_cdfe
                new_cdfe = current_cdfe | cross_namespace_copy
                set_features_cmd = f"{self.nvme_bin} feat host-behavior-support " + \
                    f"{self.ctrl} --cdfe={new_cdfe}"
                result = self.run_cmd(set_features_cmd)
                self.assertEqual(result.returncode, 0,
                                 "Failed to enable cross-namespace copy formats")
        get_ns_id_cmd = f"{self.nvme_bin} get-ns-id {self.ns1}"
        result = self.run_cmd(get_ns_id_cmd)
        err = result.returncode
        self.assertEqual(err, 0, "ERROR : nvme get-ns-id failed")
        output = result.stdout
        self.ns1_nsid = int(output.strip().split(':')[-1])
        self.setup_log_dir(self.__class__.__name__)

    def tearDown(self):
        """ Post Section for TestNVMeCopy """
        if self.original_cdfe is not None:
            set_features_cmd = f"{self.nvme_bin} feat host-behavior-support " + \
                f"{self.ctrl} --cdfe={self.original_cdfe}"
            self.run_cmd(set_features_cmd)
        super().tearDown()

    def _check_format_supported(self, desc_format):
        """ Skip test if the given copy descriptor format is not supported """
        if not self.ocfs & (1 << desc_format):
            self.skipTest(f"descriptor format {desc_format} is not supported")

    def copy(self, sdlba, blocks, slbs, **kwargs):
        """ Wrapper for nvme copy
            - Args:
                - sdlba : destination logical block address
                - blocks : number of logical blocks (0-based)
                - slbs : source range logical block address
                - descriptor_format : copy descriptor format (optional)
                - snsids : source namespace id (optional)
                - sopts : source options (optional)
            - Returns:
                - None
        """
        desc_format = kwargs.get("descriptor_format", 0)
        # build copy command
        copy_cmd = f"{self.nvme_bin} copy {self.ns1} " + \
            f"--format={desc_format} --sdlba={sdlba} --blocks={blocks} " + \
            f"--slbs={slbs}"
        if "snsids" in kwargs:
            copy_cmd += f" --snsids={kwargs['snsids']}"
        if "sopts" in kwargs:
            copy_cmd += f" --sopts={kwargs['sopts']}"
        # run and assert success
        self.assertEqual(self.exec_cmd(copy_cmd), 0)

    def test_copy_format_0(self):
        """ Test copy with descriptor format 0 """
        self._check_format_supported(0)
        self.copy(0, 1, 2, descriptor_format=0)

    def test_copy_format_1(self):
        """ Test copy with descriptor format 1 """
        self._check_format_supported(1)
        self.copy(0, 1, 2, descriptor_format=1)

    def test_copy_format_2(self):
        """ Test copy with descriptor format 2 """
        self._check_format_supported(2)
        self.copy(0, 1, 2, descriptor_format=2, snsids=self.ns1_nsid)

    def test_copy_format_2_sopts(self):
        """ Test copy with descriptor format 2 and source options """
        self._check_format_supported(2)
        self.copy(0, 1, 2, descriptor_format=2, snsids=self.ns1_nsid, sopts=0)

    def test_copy_format_3(self):
        """ Test copy with descriptor format 3 """
        self._check_format_supported(3)
        self.copy(0, 1, 2, descriptor_format=3, snsids=self.ns1_nsid)

    def test_copy_format_3_sopts(self):
        """ Test copy with descriptor format 3 and source options """
        self._check_format_supported(3)
        self.copy(0, 1, 2, descriptor_format=3, snsids=self.ns1_nsid, sopts=0)
