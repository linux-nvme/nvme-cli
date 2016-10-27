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
""" Base class for all the testcases
"""

import re
import os
import sys
import json
import mmap
import stat
import time
import shutil
import string
import subprocess
from nose import tools
from nose.tools import assert_equal
from nvme_test_logger import TestNVMeLogger


class TestNVMe(object):

    """
    Represents a testcase, each testcase shuold inherit this
    class or appropriate subclass which is a child of this class.

    Common utility functions used in various testcases.

        - Attributes:
            - ctrl : NVMe Controller.
            - ns1 : default namespace.
            - default_nsid : default namespace id.
            - config_file : configuration file.
            - clear_log_dir : default log directory.
    """

    def __init__(self):
        """ Pre Section for TestNVMe. """
        # common code used in various testcases.
        self.ctrl = "XXX"
        self.ns1 = "XXX"
        self.test_log_dir = "XXX"
        self.default_nsid = 0x1
        self.config_file = 'config.json'

        self.load_config()
        self.validate_pci_device()

    def __del__(self):
        """ Post Section for TestNVMe. """
        if self.clear_log_dir is True:
            shutil.rmtree(self.log_dir, ignore_errors=True)

    @tools.nottest
    def validate_pci_device(self):
        """ Validate underlaying device belogs to pci subsystem.
            - Args:
                - None
            - Returns:
                - None
        """
        cmd = cmd = "find /sys/devices -name \\*nvme0 | grep -i pci"
        err = subprocess.call(cmd, shell=True)
        assert_equal(err, 0, "ERROR : Only NVMe PCI subsystem is supported")

    @tools.nottest
    def load_config(self):
        """ Load Basic test configuration.
            - Args:
                - None
            - Returns:
                - None
        """
        with open(self.config_file) as data_file:
            config = json.load(data_file)
            self.ctrl = config['controller']
            self.ns1 = config['ns1']
            self.log_dir = config['log_dir']
            self.clear_log_dir = False

            if self.clear_log_dir is True:
                shutil.rmtree(self.log_dir, ignore_errors=True)

            if not os.path.exists(self.log_dir):
                os.makedirs(self.log_dir)

    @tools.nottest
    def setup_log_dir(self, test_name):
        """ Set up the log directory for a testcase
            Args:
              - test_name : name of the testcase.
            Returns:
              - None
        """
        self.test_log_dir = self.log_dir + "/" + test_name
        if not os.path.exists(self.test_log_dir):
            os.makedirs(self.test_log_dir)
        sys.stdout = TestNVMeLogger(self.test_log_dir + "/" + "stdout.log")
        sys.stderr = TestNVMeLogger(self.test_log_dir + "/" + "stderr.log")

    @tools.nottest
    def exec_cmd(self, cmd):
        """ Wrapper for executing a shell command and return the result. """
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        return proc.wait()

    @tools.nottest
    def nvme_reset_ctrl(self):
        """ Wrapper for nvme reset command.
            - Args:
                - None:
            - Returns:
                - None
        """
        nvme_reset_cmd = "nvme reset " + self.ctrl
        err = subprocess.call(nvme_reset_cmd,
                              shell=True,
                              stdout=subprocess.PIPE)
        assert_equal(err, 0, "ERROR : nvme reset failed")
        time.sleep(5)
        rescan_cmd = "echo 1 > /sys/bus/pci/rescan"
        proc = subprocess.Popen(rescan_cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        time.sleep(5)
        assert_equal(proc.wait(), 0, "ERROR : pci rescan failed")

    @tools.nottest
    def get_ctrl_id(self):
        """ Wrapper for extracting the controller id.
            - Args:
                - None
            - Returns:
                - controller id.
        """
        get_ctrl_id = "nvme list-ctrl " + self.ctrl
        proc = subprocess.Popen(get_ctrl_id,
                                shell=True,
                                stdout=subprocess.PIPE)
        err = proc.wait()
        assert_equal(err, 0, "ERROR : nvme list-ctrl failed")
        line = proc.stdout.readline()
        ctrl_id = line.split(":")[1].strip()
        return ctrl_id

    @tools.nottest
    def get_ns_list(self):
        """ Wrapper for extrating the namespace list.
            - Args:
                - None
            - Returns:
                - List of the namespaces.
        """
        ns_list = []
        ns_list_cmd = "nvme list-ns " + self.ctrl
        proc = subprocess.Popen(ns_list_cmd,
                                shell=True,
                                stdout=subprocess.PIPE)
        assert_equal(proc.wait(), 0, "ERROR : nvme list namespace failed")
        for line in proc.stdout:
            ns_list.append(string.replace(line.split(":")[1], '\n', ''))

        return ns_list

    @tools.nottest
    def get_max_ns(self):
        """ Wrapper for extracting maximum number of namspaces supported.
            - Args:
                - None
            - Returns:
                - maximum number of namespaces supported.
        """
        pattern = re.compile("^nn[ ]+: [0-9]", re.IGNORECASE)
        max_ns = -1
        max_ns_cmd = "nvme id-ctrl " + self.ctrl
        proc = subprocess.Popen(max_ns_cmd,
                                shell=True,
                                stdout=subprocess.PIPE)
        err = proc.wait()
        assert_equal(err, 0, "ERROR : reading maximum namespace count failed")

        for line in proc.stdout:
            if pattern.match(line):
                max_ns = line.split(":")[1].strip()
                break
        print max_ns
        return int(max_ns)

    @tools.nottest
    def delete_all_ns(self):
        """ Wrapper for deleting all the namespaces.
            - Args:
                - None
            - Returns:
                - None
        """
        delete_ns_cmd = "nvme delete-ns " + self.ctrl + " -n 0xFFFFFFFF"
        assert_equal(self.exec_cmd(delete_ns_cmd), 0)
        list_ns_cmd = "nvme list-ns " + self.ctrl + " --all | wc -l"
        proc = subprocess.Popen(list_ns_cmd,
                                shell=True,
                                stdout=subprocess.PIPE)
        output = proc.stdout.read().strip()
        assert_equal(output, '0', "ERROR : deleting all namespace failed")

    @tools.nottest
    def create_ns(self, nsze, ncap, flbas, dps):
        """ Wrapper for creating a namespace.
            - Args:
                - nsze : new namespace size.
                - ncap : new namespace capacity.
                - flbas : new namespace format.
                - dps : new namespace data protection information.
            - Returns:
                - return code of the nvme create namespace command.
        """
        create_ns_cmd = "nvme create-ns " + self.ctrl + " --nsze=" + \
                        str(nsze) + " --ncap=" + str(ncap) + \
                        " --flbas=" + str(flbas) + " --dps=" + str(dps)
        return self.exec_cmd(create_ns_cmd)

    @tools.nottest
    def create_and_validate_ns(self, nsid, nsze, ncap, flbas, dps):
        """ Wrapper for creating and validating a namespace.
            - Args:
                - nsid : new namespace id.
                - nsze : new namespace size.
                - ncap : new namespace capacity.
                - flbas : new namespace format.
                - dps : new namespace data protection information.
            - Returns:
                - return 0 on success, error code on failure.
        """
        err = self.create_ns(nsze, ncap, flbas, dps)
        if err == 0:
            time.sleep(2)
            id_ns_cmd = "nvme id-ns " + self.ctrl + " -n " + str(nsid)
            err = subprocess.call(id_ns_cmd,
                                  shell=True,
                                  stdout=subprocess.PIPE)
        return err

    @tools.nottest
    def attach_ns(self, ctrl_id, ns_id):
        """ Wrapper for attaching the namespace.
            - Args:
                - ctrl_id : controller id to which namespace to be attched.
                - nsid : new namespace id.
            - Returns:
                - 0 on success, error code on failure.
        """
        attach_ns_cmd = "nvme attach-ns " + self.ctrl + \
                        " --namespace-id=" + str(ns_id) + \
                        " --controllers=" + ctrl_id
        err = subprocess.call(attach_ns_cmd,
                              shell=True,
                              stdout=subprocess.PIPE)
        time.sleep(5)
        if err == 0:
            # enumerate new namespace block device
            self.nvme_reset_ctrl()
            time.sleep(5)
            # check if new namespace block device exists
            err = 0 if stat.S_ISBLK(os.stat(self.ns1).st_mode) else 1
        return err

    @tools.nottest
    def detach_ns(self, ctrl_id, nsid):
        """ Wrapper for detaching the namespace.
            - Args:
                - ctrl_id : controller id to which namespace to be attched.
                - nsid : new namespace id.
            - Returns:
                - 0 on success, error code on failure.
        """
        detach_ns_cmd = "nvme detach-ns " + self.ctrl + \
                        " --namespace-id=" + str(nsid) + \
                        " --controllers=" + ctrl_id
        return subprocess.call(detach_ns_cmd,
                               shell=True,
                               stdout=subprocess.PIPE)

    @tools.nottest
    def delete_and_validate_ns(self, nsid):
        """ Wrapper for deleting and validating that namespace is deleted.
            - Args:
                - nsid : new namespace id.
            - Returns:
                - 0 on success, 1 on failure.
        """
        # delete the namespace
        delete_ns_cmd = "nvme delete-ns " + self.ctrl + " -n " + str(nsid)
        err = subprocess.call(delete_ns_cmd,
                              shell=True,
                              stdout=subprocess.PIPE)
        assert_equal(err, 0, "ERROR : delete namespace failed")
        return err

    def get_smart_log(self, nsid):
        """ Wrapper for nvme smart-log command.
            - Args:
                - nsid : namespace id to get smart log from.
            - Returns:
                - 0 on success, error code on failure.
        """
        smart_log_cmd = "nvme smart-log " + self.ctrl + " -n " + str(nsid)
        print smart_log_cmd
        proc = subprocess.Popen(smart_log_cmd,
                                shell=True,
                                stdout=subprocess.PIPE)
        err = proc.wait()
        assert_equal(err, 0, "ERROR : nvme smart log failed")

        for line in proc.stdout:
            if "data_units_read" in line:
                data_units_read = \
                    string.replace(line.split(":")[1].strip(), ",", "")
            if "data_units_written" in line:
                data_units_written = \
                    string.replace(line.split(":")[1].strip(), ",", "")
            if "host_read_commands" in line:
                host_read_commands = \
                    string.replace(line.split(":")[1].strip(), ",", "")
            if "host_write_commands" in line:
                host_write_commands = \
                    string.replace(line.split(":")[1].strip(), ",", "")

        print "data_units_read " + data_units_read
        print "data_units_written " + data_units_written
        print "host_read_commands " + host_read_commands
        print "host_write_commands " + host_write_commands
        return err

    def get_error_log(self, nsid):
        """ Wrapper for nvme error-log command.
            - Args:
                - nsid : namespace id to get error log from.
            - Returns:
                - 0 on success, error code on failure.
        """
        pattern = re.compile("^ Entry\[[ ]*[0-9]+\]")
        error_log_cmd = "nvme error-log " + self.ctrl + " -n " + str(nsid)
        proc = subprocess.Popen(error_log_cmd,
                                shell=True,
                                stdout=subprocess.PIPE)
        err = proc.wait()
        assert_equal(err, 0, "ERROR : nvme error log failed")
        line = proc.stdout.readline()
        err_log_entry_count = int(line.split(" ")[5].strip().split(":")[1])
        entry_count = 0
        for line in proc.stdout:
            if pattern.match(line):
                entry_count += 1

        return 0 if err_log_entry_count == entry_count else 1

    def run_ns_io(self, nsid, lbads):
        """ Wrapper to run ios on namespace under test.
            - Args:
                - lbads : LBA Data size supported in power of 2 format.
            - Returns:
                - None
        """
        block_size = mmap.PAGESIZE if lbads < 9 else 2 ** int(lbads)
        ns_path = self.ctrl + "n" + str(nsid)
        io_cmd = "dd if=" + ns_path + " of=/dev/null" + " bs=" + \
                 str(block_size) + " count=10 > /dev/null 2>&1"
        print io_cmd
        run_io = subprocess.Popen(io_cmd, shell=True, stdout=subprocess.PIPE)
        run_io_result = run_io.communicate()[1]
        assert_equal(run_io_result, None)
        io_cmd = "dd if=/dev/zero of=" + ns_path + " bs=" + \
                 str(block_size) + " count=10 > /dev/null 2>&1"
        print io_cmd
        run_io = subprocess.Popen(io_cmd, shell=True, stdout=subprocess.PIPE)
        run_io_result = run_io.communicate()[1]
        assert_equal(run_io_result, None)
