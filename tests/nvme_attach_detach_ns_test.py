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
NVMe Namespace Management Testcase:-

    1. Create Namespace and validate.
    2. Attach Namespace to controller.
    3. Run IOs on Namespace under test.
    4. Detach Namespace from controller.
    5. Delete Namespace.
"""

from nvme_test import TestNVMe


class TestNVMeAttachDetachNSCmd(TestNVMe):

    """
    Represents Attach, Detach namespace testcase.

        - Attributes:
              - dps : data protection information.
              - flabs : LBA format information.
              - nsze : namespace size.
              - ncap : namespace capacity.
              - ctrl_id : controller id.
    """

    def setUp(self):
        """ Pre Section for TestNVMeAttachDetachNSCmd """
        super().setUp()
        self.dps = 0
        self.flbas = 0
        (ds, ms) = self.get_lba_format_size()
        ncap = int(self.get_ncap() / (ds+ms))
        self.nsze = ncap
        self.ncap = ncap
        self.setup_log_dir(self.__class__.__name__)
        self.ctrl_id = self.get_ctrl_id()
        self.delete_all_ns()

    def tearDown(self):
        """
        Post Section for TestNVMeAttachDetachNSCmd

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

    def test_attach_detach_ns(self):
        """ Testcase main """
        err = self.create_and_validate_ns(self.default_nsid,
                                          self.nsze,
                                          self.ncap,
                                          self.flbas,
                                          self.dps)
        self.assertEqual(err, 0)
        self.assertEqual(self.attach_ns(self.ctrl_id, self.default_nsid), 0)

        self.run_ns_io(self.default_nsid, 0)

        self.assertEqual(self.detach_ns(self.ctrl_id, self.default_nsid), 0)
        self.assertEqual(self.delete_and_validate_ns(self.default_nsid), 0)
        self.nvme_reset_ctrl()
