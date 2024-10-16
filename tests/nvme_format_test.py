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

import math
import subprocess
import time

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
              - lba_format_list : lis of supported format.
              - ms_list : list of metadat size per format.
              - lbads_list : list of LBA data size per format.
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
        self.ms_list = []
        self.lbads_list = []
        self.test_log_dir = self.log_dir + "/" + self.__class__.__name__
        self.setup_log_dir(self.__class__.__name__)
        self.delete_all_ns()
        time.sleep(1)

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
        id_ns = "nvme id-ns " + self.ctrl + \
                " -n1 | grep ^lbaf | awk '{print $2}' | tr -s \"\\n\" \" \""
        proc = subprocess.Popen(id_ns, shell=True, stdout=subprocess.PIPE,
                                encoding='utf-8')
        self.lba_format_list = proc.stdout.read().strip().split(" ")
        if proc.wait() == 0:
            # read lbads information
            id_ns = "nvme id-ns " + self.ctrl + \
                    " -n1 | grep ^lbaf | awk '{print $5}'" + \
                    " | cut -f 2 -d ':' | tr -s \"\\n\" \" \""
            proc = subprocess.Popen(id_ns, shell=True, stdout=subprocess.PIPE,
                                    encoding='utf-8')
            self.lbads_list = proc.stdout.read().strip().split(" ")
            # read metadata information
            id_ns = "nvme id-ns " + self.ctrl + \
                    " -n1 | grep ^lbaf | awk '{print $4}'" + \
                    " | cut -f 2 -d ':' | tr -s \"\\n\" \" \""
            proc = subprocess.Popen(id_ns, shell=True, stdout=subprocess.PIPE,
                                    encoding='utf-8')
            self.ms_list = proc.stdout.read().strip().split(" ")
            self.assertEqual(self.detach_ns(self.ctrl_id, self.default_nsid), 0)
            self.assertEqual(self.delete_and_validate_ns(self.default_nsid), 0)
            self.nvme_reset_ctrl()

    def test_format_ns(self):
        """ Testcase main """
        # extract the supported format information.
        self.attach_detach_primary_ns()

        # iterate through all supported format
        for i in range(0, len(self.lba_format_list)):
            print("\nlba format " + str(self.lba_format_list[i]) +
                  " lbad       " + str(self.lbads_list[i]) +
                  " ms         " + str(self.ms_list[i]))
            metadata_size = 1 if self.ms_list[i] == '8' else 0
            err = self.create_and_validate_ns(self.default_nsid,
                                              self.nsze,
                                              self.ncap,
                                              self.lba_format_list[i],
                                              metadata_size)
            self.assertEqual(err, 0)
            self.assertEqual(self.attach_ns(self.ctrl_id, self.default_nsid), 0)
            self.run_ns_io(self.default_nsid, self.lbads_list[i])
            time.sleep(5)
            self.assertEqual(self.detach_ns(self.ctrl_id, self.default_nsid), 0)
            self.assertEqual(self.delete_and_validate_ns(self.default_nsid), 0)
            self.nvme_reset_ctrl()
