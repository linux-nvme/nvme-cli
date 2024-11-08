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
Namespace Format testcase :-

    1. Create, attach, detach, delete primary namespace and
       extract the supported format information from default namespace:-
           - List of the supported format.
           - List of Metadata Size per format. Based on this we calculate
             data protection parameter at the time of namespace.
           - List of LBA Data Size per format.
    2. Use the collected information and iterate through each supported
       format:-
           - Create namespace.
           - Attach namespace.
           - Run IOs on the namespace under test.
           - Detach namespace
           - Delete Namespace.
"""

import json
import math
import subprocess

from nvme_test import TestNVMe


class TestNVMeFormatCmd(TestNVMe):

    """
    Represents Format testcase.

        - Attributes:
              - dps : data protection information.
              - flabs : LBA format information.
              - nsze : namespace size.
              - ncap : namespace capacity.
              - ctrl_id : controller id.
              - lba_format_list : json list of supported format.
              - test_log_dir : directory for logs, temp files.
    """

    def setUp(self):
        """ Pre Section for TestNVMeFormatCmd """
        super().setUp()
        self.dps = 0
        self.flbas = 0
        # Assuming run_ns_io with 4KiB * 10 writes.
        # Calculating minimum required ncap for this workload
        (ds, _) = self.get_lba_format_size()
        ncap = int(math.ceil((4096*10)/ds))
        self.ncap = ncap
        self.nsze = ncap
        self.ctrl_id = self.get_ctrl_id()
        self.lba_format_list = []
        self.test_log_dir = self.log_dir + "/" + self.__class__.__name__
        self.setup_log_dir(self.__class__.__name__)
        self.delete_all_ns()

    def tearDown(self):
        """
        Post Section for TestNVMeFormatCmd

            - Create primary namespace.
            - Attach it to controller.
            - Call super class's destructor.
        """
        self.assertEqual(self.create_and_validate_ns(self.default_nsid,
                                                     self.nsze,
                                                     self.ncap,
                                                     self.flbas,
                                                     self.dps), 0)
        self.attach_ns(self.ctrl_id, self.default_nsid)
        super().tearDown()

    def attach_detach_primary_ns(self):
        """ Extract supported format information using default namespace """
        self.assertEqual(self.create_and_validate_ns(self.default_nsid,
                                                     self.nsze,
                                                     self.ncap,
                                                     self.flbas,
                                                     self.dps), 0)
        self.assertEqual(self.attach_ns(self.ctrl_id, self.default_nsid), 0)
        # read lbaf information
        id_ns_cmd = f"{self.nvme_bin} id-ns {self.ctrl} " + \
            f"--namespace-id={self.default_nsid} --output-format=json"
        proc = subprocess.Popen(id_ns_cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                encoding='utf-8')
        err = proc.wait()
        self.assertEqual(err, 0, "ERROR : nvme id-ns failed")
        json_output = json.loads(proc.stdout.read())
        self.lba_format_list = json_output['lbafs']
        self.assertTrue(len(self.lba_format_list) > 0,
                        "ERROR : nvme id-ns could not find any lba formats")
        self.assertEqual(self.detach_ns(self.ctrl_id, self.default_nsid), 0)
        self.assertEqual(self.delete_and_validate_ns(self.default_nsid), 0)
        self.nvme_reset_ctrl()

    def test_format_ns(self):
        """ Testcase main """
        # extract the supported format information.
        self.attach_detach_primary_ns()

        print("##### Testing lba formats:")
        # iterate through all supported format
        for flbas, lba_format in enumerate(self.lba_format_list):
            ds = lba_format['ds']
            ms = lba_format['ms']
            print(f"\nlba format {str(flbas)}"
                  f"\nds         {str(ds)}"
                  f"\nms         {str(ms)}")
            dps = 1 if str(ms) == '8' else 0
            err = self.create_and_validate_ns(self.default_nsid,
                                              self.nsze,
                                              self.ncap,
                                              flbas,
                                              dps)
            self.assertEqual(err, 0)
            self.assertEqual(self.attach_ns(self.ctrl_id, self.default_nsid), 0)
            self.run_ns_io(self.default_nsid, int(ds))
            self.assertEqual(self.detach_ns(self.ctrl_id, self.default_nsid), 0)
            self.assertEqual(self.delete_and_validate_ns(self.default_nsid), 0)
            self.nvme_reset_ctrl()
