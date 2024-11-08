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

import subprocess

from nvme_test import TestNVMe


class TestNVMeCopy(TestNVMe):

    """
    Represents NVMe Copy testcase.
        - Attributes:
              - ocfs : optional copy formats supported
              - host_behavior_data : host behavior support data to restore during teardown
              - test_log_dir :  directory for logs, temp files.
    """

    def setUp(self):
        """ Pre Section for TestNVMeCopy """
        super().setUp()
        self.ocfs = self.get_ocfs()
        self.host_behavior_data = None
        cross_namespace_copy = self.ocfs & 0xc
        if cross_namespace_copy:
            # get host behavior support data
            get_features_cmd = f"{self.nvme_bin} get-feature {self.ctrl} " + \
                "--feature-id=0x16 --data-len=512 --raw-binary"
            proc = subprocess.Popen(get_features_cmd,
                                    shell=True,
                                    stdout=subprocess.PIPE,
                                    encoding='utf-8')
            err = proc.wait()
            self.assertEqual(err, 0, "ERROR : nvme get-feature failed")
            self.host_behavior_data = proc.stdout.read()
            # enable cross-namespace copy formats
            if self.host_behavior_data[4] & cross_namespace_copy:
                # skip if already enabled
                print("Cross-namespace copy already enabled, skipping set-features")
                self.host_behavior_data = None
            else:
                data = self.host_behavior_data[:4] + cross_namespace_copy.to_bytes(2, 'little') + self.host_behavior_data[6:]
                set_features_cmd = f"{self.nvme_bin} set-feature " + \
                    f"{self.ctrl} --feature-id=0x16 --data-len=512"
                proc = subprocess.Popen(set_features_cmd,
                                        shell=True,
                                        stdout=subprocess.PIPE,
                                        stdin=subprocess.PIPE,
                                        encoding='utf-8')
                proc.communicate(input=data)
                self.assertEqual(proc.returncode, 0, "Failed to enable cross-namespace copy formats")
        get_ns_id_cmd = f"{self.nvme_bin} get-ns-id {self.ns1}"
        proc = subprocess.Popen(get_ns_id_cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                encoding='utf-8')
        err = proc.wait()
        self.assertEqual(err, 0, "ERROR : nvme get-ns-id failed")
        output = proc.stdout.read()
        self.ns1_nsid = int(output.strip().split(':')[-1])
        self.setup_log_dir(self.__class__.__name__)

    def tearDown(self):
        """ Post Section for TestNVMeCopy """
        if self.host_behavior_data:
            # restore saved host behavior support data
            set_features_cmd = f"{self.nvme_bin} set-feature {self.ctrl} " + \
                "--feature-id=0x16 --data-len=512"
            proc = subprocess.Popen(set_features_cmd,
                                    shell=True,
                                    stdout=subprocess.PIPE,
                                    stdin=subprocess.PIPE,
                                    encoding='utf-8')
            proc.communicate(input=self.host_behavior_data)
        super().tearDown()

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
        # skip if descriptor format not supported (default format is 0)
        desc_format = kwargs.get("descriptor_format", 0)
        if not self.ocfs & (1 << desc_format):
            print(f"Skip copy because descriptor format {desc_format} is not supported")
            return
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

    def test_copy(self):
        """ Testcase main """
        self.copy(0, 1, 2, descriptor_format=0)
        self.copy(0, 1, 2, descriptor_format=1)
        self.copy(0, 1, 2, descriptor_format=2, snsids=self.ns1_nsid)
        self.copy(0, 1, 2, descriptor_format=2, snsids=self.ns1_nsid, sopts=0)
        self.copy(0, 1, 2, descriptor_format=3, snsids=self.ns1_nsid)
        self.copy(0, 1, 2, descriptor_format=3, snsids=self.ns1_nsid, sopts=0)
