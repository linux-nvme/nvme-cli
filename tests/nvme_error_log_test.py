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
NVMe Smart Log Verification Testcase:-

    1. Execute error-log on controller.

"""

from nvme_test import TestNVMe


class TestNVMeErrorLogCmd(TestNVMe):

    """
    Represents Smart Log testcae.

        - Attributes:
    """

    def setUp(self):
        """ Pre Section for TestNVMeErrorLogCmd """
        super().setUp()
        self.setup_log_dir(self.__class__.__name__)

    def tearDown(self):
        """
        Post Section for TestNVMeErrorLogCmd

            - Call super class's destructor.
        """
        super().tearDown()

    def get_error_log_ctrl(self):
        """ Wrapper for executing error-log on controller.
            - Args:
                - None:
            - Returns:
                - 0 on success, error code on failure.
        """
        return self.get_error_log()

    def test_get_error_log(self):
        """ Testcase main """
        self.assertEqual(self.get_error_log_ctrl(), 0)
