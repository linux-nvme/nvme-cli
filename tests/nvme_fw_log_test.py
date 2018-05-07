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
#   Author: Madhusudhana S.J <madhusudhana.sj@wdc.com>
#
"""
NVMe nvme-fw-log  Testcase:-

    1. Send NVMe Firmware log page request, returns result and log
    2. Retrieves the NVMe Firmware log page from an NVMe device and report format to normal, json, or binary
    3. Retrieve the firmware log for the specified device in either decoded format(default) or binary
"""

import subprocess
from nose.tools import assert_equal
from nvme_test import TestNVMe
import time

class TestNVMe_fw_log(TestNVMe):

	"""
	Represents Firmware log testcase.

        - Attributes:
                     - nvme-fw-log : list of Firmware log page request actions.     
	"""
	def __init__(self):
         	""" Pre Section for TestNVMe_fw_log mandatory Actions """
		TestNVMe.__init__(self)
        	self.setup_log_dir(self.__class__.__name__)
        	self.fw_log_action_list = ["--raw-binary", "-b"]
        	self.fw_log_outtput_format_list = ["normal", "json","binary"]
	
	def __del__(self):
		""" Post Section for TestNVMe_fw_log mandatory Actions

            	     Call super class's destructor.
		"""
		TestNVMe.__del__(self)
 
	def get_fw_log(self):
        	""" Wrapper for NVMe fw_log  command
                - Args:
                       - fw-log: NVMe character device to be used to check the fw-log page.
                - Returns: None
        	"""
        	get_fw_log_cmd = "nvme fw-log /dev/nvme0"
		print "nvme fw-log command :",get_fw_log_cmd, "\n"
		proc = subprocess.Popen(get_fw_log_cmd,shell=True,stdout=subprocess.PIPE)
		fw_log_output = proc.communicate()[0]
		print "command_output : "
		print fw_log_output, "\n"
        	assert_equal(proc.wait(), 0)
 
	def get_mandetory_fw_log_action(self,fw_log_action):
			""" Wrapper for NVMe fw-log  command 
				- Args: NVMe character device ex: /dev/nvme0
				- nvme-fw-log : list of Firmware log page request actions.
				- Returns: None
			"""
			print "fw_log_action value:", fw_log_action
			if str(fw_log_action) in ["-b","--raw-binary"]:
				get_fw_log_cmd = "nvme fw-log /dev/nvme0" + " " +  fw_log_action + " | hexdump -C"
				print "get_fw_log_cmd with binary :",get_fw_log_cmd,"\n"
				proc = subprocess.Popen(get_fw_log_cmd,shell=True,stdout=subprocess.PIPE)
				fw_log_output = proc.communicate()[0]
				print "command_output : "
				print fw_log_output, "\n"
				assert_equal(proc.wait(), 0)
			else:
				get_fw_log_cmd = "nvme fw-log /dev/nvme0" 
				print "command executing to retrive fw log :",get_fw_log_cmd
               			proc = subprocess.Popen(get_fw_log_cmd,shell=True,stdout=subprocess.PIPE)
                		fw_log_output = proc.communicate()[0]
				print "command_output : "
				print fw_log_output, "\n"
                        assert_equal(proc.wait(), 0)
	def get_mandetory_fw_log_outputformat(self,fw_log_outputformat):
                        """ Wrapper for NVMe FW-LOG command
                                - Args:
                                - fw_log_action : output format  to be used with fw-log command.
                                - Returns: None
                        """
                        print "fw_log_outputformat Type:", fw_log_outputformat
                        if str(fw_log_outputformat) == "binary":
                                get_fw_log_cmd = "nvme fw-log /dev/nvme0 " + " --output-format=binary | hexdump -C"
                                print "get_fw_log command with output format:",get_fw_log_cmd
				print "\n"
                                proc = subprocess.Popen(get_fw_log_cmd,shell=True,stdout=subprocess.PIPE)
                                fw_log_output = proc.communicate()[0]
                                print "command_output : "
                                print fw_log_output, "\n"
                                assert_equal(proc.wait(), 0)
                        else:
                                get_fw_log_cmd = "nvme fw-log /dev/nvme0 " + " --output-format=" + fw_log_outputformat
                                print "command executing to get fw_log of the given NVMe device :",get_fw_log_cmd
                                proc = subprocess.Popen(get_fw_log_cmd,shell=True,stdout=subprocess.PIPE)
                                fw_log_output = proc.communicate()[0]
                                print "command_output : "
                                print fw_log_output, "\n"
                                assert_equal(proc.wait(), 0)

	def test_fw_log_actions(self):
        		""" Testcase main """ 
			print "calling main function ..!"
			self.get_fw_log()
       			for fw_log_action in self.fw_log_action_list:
				if str(fw_log_action) in ["-b", "--raw-binary"]:
					self.get_mandetory_fw_log_action(fw_log_action)
				else:
					self.get_mandetory_fw_log_action(fw_log_action)
			for fw_log_outputformat in self.fw_log_outtput_format_list:
				if str(fw_log_outputformat) == "binary":
					self.get_mandetory_fw_log_outputformat(fw_log_outputformat)
				else:
					self.get_mandetory_fw_log_outputformat(fw_log_outputformat)
