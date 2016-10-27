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
Get Features Testcase:-

Test the Mandetory features with get features command:-
    1. 01h rbitration.
    2. 02h M Power Management.
    3. 04h M Temperature Threshold.
    4. 05h M Error Recovery.
    5. 07h M Number of Queues.
    6. 08h M Interrupt Coalescing.
    7. 09h M Interrupt Vector Configuration.
    8. 0Ah M Write Atomicity Normal.
    9. 0Bh M Asynchronous Event Configuration.
"""

import subprocess
from nose.tools import assert_equal
from nvme_test import TestNVMe


class TestNVMeGetMandetoryFeatures(TestNVMe):

    """
    Represents Get Features testcase.

        - Attributes:
              - feature_id_list : list of the mandetory features.
              - get_vector_list_cmd : vector list collection for 09h.
              - vector_list : vector list to hold the interrupt vectors.
    """

    def __init__(self):
        """ Pre Section for TestNVMeGetMandetoryFeatures """
        TestNVMe.__init__(self)
        self.setup_log_dir(self.__class__.__name__)
        self.feature_id_list = ["0x01", "0x02", "0x04", "0x05", "0x07",
                                "0x08", "0x09", "0x0A", "0x0B"]
        get_vector_list_cmd = "cat /proc/interrupts | grep nvme |" \
                              " cut -d : -f 1 | tr -d ' ' | tr '\n' ' '"
        proc = subprocess.Popen(get_vector_list_cmd,
                                shell=True,
                                stdout=subprocess.PIPE)
        self.vector_list = []
        self.vector_list = proc.stdout.read().strip().split(" ")

    def __del__(self):
        """ Post Section for TestNVMeGetMandetoryFeatures

            Call super class's destructor.
        """
        TestNVMe.__del__(self)

    def get_mandetory_features(self, feature_id):
        """ Wrapper for NVMe get features command
            - Args:
                - feature_id : feature id to be used with get feature command.
            - Returns:
                - None
        """
        if str(feature_id) == "0x09":
            for vector in self.vector_list:
                get_feat_cmd = "nvme get-feature " + self.ctrl + \
                               " --feature-id=" + str(feature_id) + \
                               " --cdw11=" + str(vector)
                proc = subprocess.Popen(get_feat_cmd,
                                        shell=True,
                                        stdout=subprocess.PIPE)
                feature_output = proc.communicate()[0]
                print feature_output
                assert_equal(proc.wait(), 0)
        else:
            get_feat_cmd = "nvme get-feature " + self.ctrl + \
                           " --feature-id=" + str(feature_id)
            proc = subprocess.Popen(get_feat_cmd,
                                    shell=True,
                                    stdout=subprocess.PIPE)
            feature_output = proc.communicate()[0]
            print feature_output
            assert_equal(proc.wait(), 0)

    def test_get_mandetory_features(self):
        """ Testcase main """
        for feature_id in self.feature_id_list:
            self.get_mandetory_features(feature_id)
