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
""" Base class for all the testcases
"""

import json
import mmap
import os
import re
import shutil
import stat
import subprocess
import sys
import unittest
import time

from nvme_test_logger import TestNVMeLogger


def to_decimal(value):
    """ Wrapper for converting numbers to base 10 decimal
        - Args:
            - value: A number in any common base
        - Returns:
            - Decimal integer
    """
    return int(str(value), 0)


class TestNVMe(unittest.TestCase):

    """
    Represents a testcase, each testcase should inherit this
    class or appropriate subclass which is a child of this class.

    Common utility functions used in various testcases.

        - Attributes:
            - ctrl : NVMe Controller.
            - ns1 : default namespace.
            - default_nsid : default namespace id.
            - config_file : configuration file.
            - clear_log_dir : default log directory.
    """

    def setUp(self):
        """ Pre Section for TestNVMe. """
        # common code used in various testcases.
        self.ctrl = "XXX"
        self.ns1 = "XXX"
        self.test_log_dir = "XXX"
        self.nvme_bin = "nvme"
        self.do_validate_pci_device = True
        self.default_nsid = 0x1
        self.flbas = 0
        self.config_file = 'tests/config.json'

        self.load_config()
        if self.do_validate_pci_device:
            self.validate_pci_device()
        self.create_and_attach_default_ns()
        print(f"\nsetup: ctrl: {self.ctrl}, ns1: {self.ns1}, default_nsid: {self.default_nsid}, flbas: {self.flbas}\n")

    def tearDown(self):
        """ Post Section for TestNVMe. """
        if self.clear_log_dir is True:
            shutil.rmtree(self.log_dir, ignore_errors=True)
        self.create_and_attach_default_ns()
        print(f"\nteardown: ctrl: {self.ctrl}, ns1: {self.ns1}, default_nsid: {self.default_nsid}, flbas: {self.flbas}\n")

    @classmethod
    def tearDownClass(cls):
        print("\n")

    def create_and_attach_default_ns(self):
        """ Creates a default namespace with the full capacity of the ctrls NVM
            - Args:
                - None
            - Returns:
                - None
        """
        self.dps = 0
        self.flbas = 0
        (ds, ms) = self.get_lba_format_size()
        ncap = int(self.get_ncap() / (ds+ms))
        self.nsze = ncap
        self.ncap = ncap
        self.ctrl_id = self.get_ctrl_id()
        self.delete_all_ns()
        err = self.create_and_validate_ns(self.default_nsid,
                                          self.nsze,
                                          self.ncap,
                                          self.flbas,
                                          self.dps)
        self.assertEqual(err, 0)
        self.assertEqual(self.attach_ns(self.ctrl_id, self.default_nsid), 0)

    def validate_pci_device(self):
        """ Validate underlying device belongs to pci subsystem.
            - Args:
                - None
            - Returns:
                - None
        """
        x1, x2, dev = self.ctrl.split('/')
        cmd = "find /sys/devices -name \\*" + dev + " | grep -i pci"
        err = subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL)
        self.assertEqual(err, 0, "ERROR : Only NVMe PCI subsystem is supported")

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
            self.nvme_bin = config.get('nvme_bin', self.nvme_bin)
            print(f"\nUsing nvme binary '{self.nvme_bin}'")
            self.do_validate_pci_device = config.get(
                'do_validate_pci_device', self.do_validate_pci_device)
            self.clear_log_dir = False

            if self.clear_log_dir is True:
                shutil.rmtree(self.log_dir, ignore_errors=True)

            if not os.path.exists(self.log_dir):
                os.makedirs(self.log_dir)

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

    def exec_cmd(self, cmd):
        """ Wrapper for executing a shell command and return the result. """
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                encoding='utf-8')
        return proc.wait()

    def nvme_reset_ctrl(self):
        """ Wrapper for nvme reset command.
            - Args:
                - None:
            - Returns:
                - None
        """
        nvme_reset_cmd = f"{self.nvme_bin} reset {self.ctrl}"
        err = subprocess.call(nvme_reset_cmd,
                              shell=True,
                              stdout=subprocess.DEVNULL)
        self.assertEqual(err, 0, "ERROR : nvme reset failed")
        rescan_cmd = "echo 1 > /sys/bus/pci/rescan"
        proc = subprocess.Popen(rescan_cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                encoding='utf-8')
        self.assertEqual(proc.wait(), 0, "ERROR : pci rescan failed")

    def get_ctrl_id(self):
        """ Wrapper for extracting the first controller id.
            - Args:
                - None
            - Returns:
                - controller id.
        """
        get_ctrl_id = f"{self.nvme_bin} list-ctrl {self.ctrl} " + \
            "--output-format=json"
        proc = subprocess.Popen(get_ctrl_id,
                                shell=True,
                                stdout=subprocess.PIPE,
                                encoding='utf-8')
        err = proc.wait()
        self.assertEqual(err, 0, "ERROR : nvme list-ctrl failed")
        json_output = json.loads(proc.stdout.read())
        self.assertTrue(len(json_output['ctrl_list']) > 0,
                        "ERROR : nvme list-ctrl could not find ctrl")
        return str(json_output['ctrl_list'][0]['ctrl_id'])

    def get_nsid_list(self):
        """ Wrapper for extracting the namespace list.
            - Args:
                - None
            - Returns:
                - List of the namespaces.
        """
        ns_list = []
        ns_list_cmd = f"{self.nvme_bin} list-ns {self.ctrl} " + \
            "--output-format=json"
        proc = subprocess.Popen(ns_list_cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                encoding='utf-8')
        self.assertEqual(proc.wait(), 0, "ERROR : nvme list namespace failed")
        json_output = json.loads(proc.stdout.read())

        for ns in json_output['nsid_list']:
            ns_list.append(ns['nsid'])

        return ns_list

    def get_max_ns(self):
        """ Wrapper for extracting maximum number of namespaces supported.
            - Args:
                - None
            - Returns:
                - maximum number of namespaces supported.
        """
        max_ns_cmd = f"{self.nvme_bin} id-ctrl {self.ctrl} " + \
            "--output-format=json"
        proc = subprocess.Popen(max_ns_cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                encoding='utf-8')
        err = proc.wait()
        self.assertEqual(err, 0, "ERROR : reading maximum namespace count failed")
        json_output = json.loads(proc.stdout.read())
        return int(json_output['nn'])

    def get_lba_status_supported(self):
        """ Check if 'Get LBA Status' command is supported by the device
            - Args:
                - None
            - Returns:
                - True if 'Get LBA Status' command is supported, otherwise False
        """
        return to_decimal(self.get_id_ctrl_field_value("oacs")) & (1 << 9)

    def get_lba_format_size(self):
        """ Wrapper for extracting lba format size of the given flbas
            - Args:
                - None
            - Returns:
                - lba format size as a tuple of (data_size, metadata_size) in bytes.
        """
        nvme_id_ns_cmd = f"{self.nvme_bin} id-ns {self.ns1} " + \
            "--output-format=json"
        proc = subprocess.Popen(nvme_id_ns_cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                encoding='utf-8')
        err = proc.wait()
        self.assertEqual(err, 0, "ERROR : reading id-ns")
        json_output = json.loads(proc.stdout.read())
        self.assertTrue(len(json_output['lbafs']) > self.flbas,
                        "Error : could not match the given flbas to an existing lbaf")
        lbaf_json = json_output['lbafs'][int(self.flbas)]
        ms_expo = int(lbaf_json['ms'])
        ds_expo = int(lbaf_json['ds'])
        ds = 0
        ms = 0
        if ds_expo > 0:
            ds = (1 << ds_expo)
        if ms_expo > 0:
            ms = (1 << ms_expo)
        return (ds, ms)

    def get_ncap(self):
        """ Wrapper for extracting capacity.
            - Args:
                - None
            - Returns:
                - Total NVM capacity.
        """
        return to_decimal(self.get_id_ctrl_field_value("tnvmcap"))

    def get_id_ctrl_field_value(self, field):
        """ Wrapper for extracting id-ctrl field values
            - Args:
                - None
            - Returns:
                - Filed value of the given field
        """
        id_ctrl_cmd = f"{self.nvme_bin} id-ctrl {self.ctrl} " + \
            "--output-format=json"
        proc = subprocess.Popen(id_ctrl_cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                encoding='utf-8')
        err = proc.wait()
        self.assertEqual(err, 0, "ERROR : reading id-ctrl failed")
        json_output = json.loads(proc.stdout.read())
        self.assertTrue(field in json_output,
                        f"ERROR : reading field '{field}' failed")
        return str(json_output[field])

    def get_ocfs(self):
        """ Wrapper for extracting optional copy formats supported
            - Args:
                - None
            - Returns:
                - Optional Copy Formats Supported
        """
        return to_decimal(self.get_id_ctrl_field_value("ocfs"))

    def delete_all_ns(self):
        """ Wrapper for deleting all the namespaces.
            - Args:
                - None
            - Returns:
                - None
        """
        delete_ns_cmd = f"{self.nvme_bin} delete-ns {self.ctrl} " + \
            "--namespace-id=0xFFFFFFFF"
        self.assertEqual(self.exec_cmd(delete_ns_cmd), 0)
        list_ns_cmd = f"{self.nvme_bin} list-ns {self.ctrl} --all " + \
            "--output-format=json"
        proc = subprocess.Popen(list_ns_cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                encoding='utf-8')
        self.assertEqual(proc.wait(), 0, "ERROR : nvme list-ns failed")
        json_output = json.loads(proc.stdout.read())
        self.assertEqual(len(json_output['nsid_list']), 0,
                         "ERROR : deleting all namespace failed")

    def create_ns(self, nsze, ncap, flbas, dps):
        """ Wrapper for creating a namespace.
            - Args:
                - nsze : new namespace size.
                - ncap : new namespace capacity.
                - flbas : new namespace format.
                - dps : new namespace data protection information.
            - Returns:
                - Popen object of the nvme create namespace command.
        """
        create_ns_cmd = f"{self.nvme_bin} create-ns {self.ctrl} " + \
            f"--nsze={str(nsze)} --ncap={str(ncap)} --flbas={str(flbas)} " + \
            f"--dps={str(dps)} --verbose --output-format=json"
        return subprocess.Popen(create_ns_cmd, shell=True,
                                stdout=subprocess.PIPE, encoding='utf-8')

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
        proc = self.create_ns(nsze, ncap, flbas, dps)
        err = proc.wait()
        if err == 0:
            json_output = json.loads(proc.stdout.read())
            self.assertEqual(int(json_output['nsid']), nsid,
                             "ERROR : create namespace failed")
            id_ns_cmd = f"{self.nvme_bin} id-ns {self.ctrl} " + \
                f"--namespace-id={str(nsid)}"
            err = subprocess.call(id_ns_cmd,
                                  shell=True,
                                  stdout=subprocess.DEVNULL)
        return err

    def attach_ns(self, ctrl_id, nsid):
        """ Wrapper for attaching the namespace.
            - Args:
                - ctrl_id : controller id to which namespace to be attached.
                - nsid : new namespace id.
            - Returns:
                - 0 on success, error code on failure.
        """
        attach_ns_cmd = f"{self.nvme_bin} attach-ns {self.ctrl} " + \
            f"--namespace-id={str(nsid)} --controllers={ctrl_id} --verbose"
        err = subprocess.call(attach_ns_cmd,
                              shell=True,
                              stdout=subprocess.DEVNULL)
        if err != 0:
            return err

        # Try to find block device for 5 seconds
        device_path = f"{self.ctrl}n{str(nsid)}"
        stop_time = time.time() + 5
        while time.time() < stop_time:
            if os.path.exists(device_path) and stat.S_ISBLK(os.stat(device_path).st_mode):
                return 0
            time.sleep(0.1)

        return 1

    def detach_ns(self, ctrl_id, nsid):
        """ Wrapper for detaching the namespace.
            - Args:
                - ctrl_id : controller id to which namespace to be attached.
                - nsid : new namespace id.
            - Returns:
                - 0 on success, error code on failure.
        """
        detach_ns_cmd = f"{self.nvme_bin} detach-ns {self.ctrl} " + \
            f"--namespace-id={str(nsid)} --controllers={ctrl_id} --verbose"
        return subprocess.call(detach_ns_cmd,
                               shell=True,
                               stdout=subprocess.DEVNULL)

    def delete_and_validate_ns(self, nsid):
        """ Wrapper for deleting and validating that namespace is deleted.
            - Args:
                - nsid : new namespace id.
            - Returns:
                - 0 on success, 1 on failure.
        """
        # delete the namespace
        delete_ns_cmd = f"{self.nvme_bin} delete-ns {self.ctrl} " + \
            f"--namespace-id={str(nsid)} --verbose"
        err = subprocess.call(delete_ns_cmd,
                              shell=True,
                              stdout=subprocess.DEVNULL)
        self.assertEqual(err, 0, "ERROR : delete namespace failed")
        return err

    def get_smart_log(self, nsid):
        """ Wrapper for nvme smart-log command.
            - Args:
                - nsid : namespace id to get smart log from.
            - Returns:
                - 0 on success, error code on failure.
        """
        smart_log_cmd = f"{self.nvme_bin} smart-log {self.ctrl} " + \
            f"--namespace-id={str(nsid)}"
        proc = subprocess.Popen(smart_log_cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                encoding='utf-8')
        err = proc.wait()
        self.assertEqual(err, 0, "ERROR : nvme smart log failed")
        return err

    def get_id_ctrl(self, vendor=False):
        """ Wrapper for nvme id-ctrl command.
            - Args:
              - None
            - Returns:
              - 0 on success, error code on failure.
        """
        if not vendor:
            id_ctrl_cmd = f"{self.nvme_bin} id-ctrl {self.ctrl}"
        else:
            id_ctrl_cmd = f"{self.nvme_bin} id-ctrl " +\
                f"--vendor-specific {self.ctrl}"
        proc = subprocess.Popen(id_ctrl_cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                encoding='utf-8')
        err = proc.wait()
        self.assertEqual(err, 0, "ERROR : nvme id controller failed")
        return err

    def get_error_log(self):
        """ Wrapper for nvme error-log command.
            - Args:
                - None
            - Returns:
                - 0 on success, error code on failure.
        """
        pattern = re.compile(r"^ Entry\[[ ]*[0-9]+\]")
        error_log_cmd = f"{self.nvme_bin} error-log {self.ctrl}"
        proc = subprocess.Popen(error_log_cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                encoding='utf-8')
        err = proc.wait()
        self.assertEqual(err, 0, "ERROR : nvme error log failed")
        # This sanity checkes the 'normal' output
        line = proc.stdout.readline()
        err_log_entry_count = int(line.split(" ")[5].strip().split(":")[1])
        entry_count = 0
        for line in proc.stdout:
            if pattern.match(line):
                entry_count += 1

        return 0 if err_log_entry_count == entry_count else 1

    def run_ns_io(self, nsid, lbads, count=10):
        """ Wrapper to run ios on namespace under test.
            - Args:
                - lbads : LBA Data size supported in power of 2 format.
            - Returns:
                - None
        """
        (ds, _) = self.get_lba_format_size()
        block_size = ds if int(lbads) < 9 else 2 ** int(lbads)
        ns_path = self.ctrl + "n" + str(nsid)
        io_cmd = "dd if=" + ns_path + " of=/dev/null" + " bs=" + \
                 str(block_size) + " count=" + str(count) + " > /dev/null 2>&1"
        print(f"Running io: {io_cmd}")
        run_io = subprocess.Popen(io_cmd, shell=True, stdout=subprocess.PIPE,
                                  encoding='utf-8')
        run_io_result = run_io.communicate()[1]
        self.assertEqual(run_io_result, None)
        io_cmd = "dd if=/dev/zero of=" + ns_path + " bs=" + \
                 str(block_size) + " count=" + str(count) + " > /dev/null 2>&1"
        print(f"Running io: {io_cmd}")
        run_io = subprocess.Popen(io_cmd, shell=True, stdout=subprocess.PIPE,
                                  encoding='utf-8')
        run_io_result = run_io.communicate()[1]
        self.assertEqual(run_io_result, None)
