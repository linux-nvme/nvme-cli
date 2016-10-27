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
""" Simple Template test example :-
"""

from nvme_test import TestNVMe


class TestNVMeSimpleTestTemplate(TestNVMe):

    """ Represents Simple NVMe test """

    def __init__(self):
        """ Pre Section for TestNVMeSimpleTestTemplate. """
        TestNVMe.__init__(self)
        self.setup_log_dir(self.__class__.__name__)
        # Add this test specific variables here

    def __del__(self):
        """ Post Section for TestNVMeSimpleTestTemplate

            Call super class's destructor.
        """
        # Add this test specific cleanup code here
        TestNVMe.__del__(self)

    def simple_template_test(self):
        """ Wrapper for this test specific functions
            - Args:
                - None
            - Returns:
                - None
        """
        pass

    def test_get_mandetory_features(self):
        """ Testcase main """
        self.simple_template_test()
