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
NVMe Identify Namespace  Testcase:-

    1. Send an Identify Namespace command to the given device.
    2. Specified namespace in either human-readable,--vendor-specific or binary format.
    3. Specified namespace in --output-format  -o in normal|json|binary
"""

import subprocess
from nose.tools import assert_equal
from nvme_test import TestNVMe
import time

class TestNVMeIdentifyNamespaceActions(TestNVMe):

	"""
	Represents Identify Namespace testcase.

        - Attributes:
                     - Identify Namespace : list of Identify Namespace actions.     
	"""
	def __init__(self):
         	""" Pre Section for TestNVMeIdentify Namespace mandatory Actions """
		TestNVMe.__init__(self)
        	self.setup_log_dir(self.__class__.__name__)
        	self.identifynamespace__action_list = ["--human-readable","--raw-binary","--vendor-specific","-b"]
        	self.identifynamespace__outtput_format_list = ["normal", "json","binary"]
	
	def __del__(self):
		""" Post Section for TestNVMeIdentify Namespace mandatory Actions

            	     Call super class's destructor.
		"""
		TestNVMe.__del__(self)
 
	def get_identifynamespace(self):
        	""" Wrapper for NVMe Identify Namespace command
                - Args:
                       - Identify Namespace : Namespace id to be used to check the Identify Namespace.
                - Returns: None
        	"""
        	get_identifynamespace_cmd = "nvme id-ns /dev/nvme0 --namespace-id=" + str(self.default_nsid) 
		print "Identify Namespace command:",get_identifynamespace_cmd, "\n"
		proc = subprocess.Popen(get_identifynamespace_cmd,shell=True,stdout=subprocess.PIPE)
		identifynamespace_output = proc.communicate()[0]
		print "command_output : "
		print identifynamespace_output, "\n"
        	assert_equal(proc.wait(), 0)
 
	def get_mandetory_identifynamespace_action(self,identifynamespace_action):
			""" Wrapper for NVMe Identify Namespace  command 
				- Args:
				- identifynamespace_action : action id to be used with identifynamespace_action  command.
				- Returns: None
			"""
			print "identifynamespace_action value:", identifynamespace_action
			if str(identifynamespace_action) in ["-b","--raw-binary"]:
				get_identifynamespace_cmd = "nvme id-ns /dev/nvme0 --namespace-id=" \
                                + str(self.default_nsid) + " " + identifynamespace_action + " | hexdump -C"
				print "get_identifynamespace_cmd with --binary :",get_identifynamespace_cmd,"\n"
				proc = subprocess.Popen(get_identifynamespace_cmd,shell=True,stdout=subprocess.PIPE)
				identifynamespace_output = proc.communicate()[0]
				print "command_output : "
				print identifynamespace_output, "\n"
				assert_equal(proc.wait(), 0)
			else:
				get_identifynamespace_cmd = "nvme id-ns /dev/nvme0 --namespace-id=" \
				+ str(self.default_nsid) + " " + identifynamespace_action 
				print "command executing to get id_ns of the given namespace :",get_identifynamespace_cmd
               			proc = subprocess.Popen(get_identifynamespace_cmd,shell=True,stdout=subprocess.PIPE)
                		identifynamespace_output = proc.communicate()[0]
				print "command_output : "
				print identifynamespace_output, "\n"
                		assert_equal(proc.wait(), 0)
	def get_mandetory_identifynamespace_outputformat(self,identifynamespace_outputformat):
                        """ Wrapper for NVMe Identify Namespace command
                                - Args:
                                - identifynamespace_action : output format  to be used with identifynamespace  command.
                                - Returns: None
                        """
                        print "identifynamespace_outputformat Type:", identifynamespace_outputformat
                        if str(identifynamespace_outputformat) == "binary":
                                get_identifynamespace_cmd = "nvme id-ns /dev/nvme0 --namespace-id=" \
                                + str(self.default_nsid) + " --output-format=binary | hexdump -C"
                                print "get_identifynamespace_cmd with binary output format:",get_identifynamespace_cmd
				print "\n"
                                proc = subprocess.Popen(get_identifynamespace_cmd,shell=True,stdout=subprocess.PIPE)
                                identifynamespace_output = proc.communicate()[0]
                                print "command_output : "
                                print identifynamespace_output, "\n"
                                assert_equal(proc.wait(), 0)
                        else:
                                get_identifynamespace_cmd = "nvme id-ns /dev/nvme0 --namespace-id=" \
                                + str(self.default_nsid) + " --output-format=" + identifynamespace_outputformat
                                print "command executing to get id_ns of the given namespace :",get_identifynamespace_cmd
                                proc = subprocess.Popen(get_identifynamespace_cmd,shell=True,stdout=subprocess.PIPE)
                                identifynamespace_output = proc.communicate()[0]
                                print "command_output : "
                                print identifynamespace_output, "\n"
                                assert_equal(proc.wait(), 0)

	def test_get_identify_namespace_actions(self):
        		""" Testcase main """ 
			print "calling main function ..!"
			self.get_identifynamespace()
       			for identifynamespace_action in self.identifynamespace__action_list:
				if str(identifynamespace_action) in ["-b", "--raw-binary"]:
					self.get_mandetory_identifynamespace_action(identifynamespace_action)
				else:
					self.get_mandetory_identifynamespace_action(identifynamespace_action)
			for identifynamespace_outputformat in self.identifynamespace__outtput_format_list:
				if str(identifynamespace_outputformat) == "binary":
					self.get_mandetory_identifynamespace_outputformat(identifynamespace_outputformat)
				else:
					self.get_mandetory_identifynamespace_outputformat(identifynamespace_outputformat)
