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
import logging
import mmap
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import unittest
import time

from nvme_test_logger import TestNVMeLogger

logger = logging.getLogger(__name__)


def to_decimal(value):
    """ Wrapper for converting numbers to base 10 decimal
        - Args:
            - value: A number in any common base
        - Returns:
            - Decimal integer
    """
    val = 0
    try:
        val = int(str(value), 0)
    except (TypeError, ValueError):
        raise ValueError(f"Invalid value: {value!r}")
    return val


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

    def is_windows(self):
        return platform.system() == 'Windows'

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
        self.ns_dps = 0
        self.ns_meta_ext = False
        self.pif = 0
        self.config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')

        self.load_config()
        if self.do_validate_pci_device:
            self.validate_pci_device()
        self.ns_mgmt_supported = self.get_ns_mgmt_support()
        if self.ns_mgmt_supported:
            self.create_and_attach_default_ns()
        else:
            self.flbas = self._get_active_lbaf_index()
            self.ns_dps = self._get_ns_dps()
            self.ns_meta_ext = self._is_metadata_ext()
            self.pif = self._get_pif()
        logger.debug("setup: ctrl: %s, ns1: %s, default_nsid: %s, flbas: %s",
                     self.ctrl, self.ns1, self.default_nsid, self.flbas)

    def tearDown(self):
        """ Post Section for TestNVMe. """
        if self.clear_log_dir is True:
            shutil.rmtree(self.log_dir, ignore_errors=True)
        if self.ns_mgmt_supported:
            self.create_and_attach_default_ns()

    @classmethod
    def tearDownClass(cls):
        pass

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
        if self.is_windows():
            return

        x1, x2, dev = self.ctrl.split('/')
        cmd = "find /sys/devices -name \\*" + dev + " | grep -i pci"
        err = self.run_cmd(cmd).returncode
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
            self.do_validate_pci_device = config.get(
                'do_validate_pci_device', self.do_validate_pci_device)
            self.clear_log_dir = False

            log_level_str = config.get('log_level',
                                       'DEBUG' if config.get('debug', False) else 'WARNING')
            log_level = getattr(logging, log_level_str.upper(), logging.WARNING)
            if not logging.getLogger().handlers:
                logging.basicConfig(format='%(message)s', stream=sys.stdout)
            logging.getLogger().setLevel(log_level)
            logger.debug("Using nvme binary '%s'", self.nvme_bin)

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

    def run_cmd(self, cmd, stdin_data=None):
        """ Run a shell command using subprocess.run, log the command and its
            output, and return the CompletedProcess result.
            - Args:
                - cmd : shell command string to execute.
                - stdin_data : optional string to pass as stdin input.
            - Returns:
                - CompletedProcess result.
        """
        logger.debug(f"Running: {cmd}")
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, encoding='utf-8',
                                input=stdin_data)
        if result.stdout:
            logger.debug(result.stdout)
        if result.stderr:
            logger.debug(result.stderr)
        return result

    def parse_json_output(self, output, context, expected_type=dict):
        """Parse JSON output and fail test clearly on malformed or wrong-typed data.

        context should identify the command/action that produced output.
        Pass expected_type=None to skip type validation.
        """
        try:
            data = json.loads(output)
        except (TypeError, json.JSONDecodeError) as exc:
            self.fail(f"ERROR : invalid JSON from {context}: {exc}; output={output!r}")

        if expected_type is not None and not isinstance(data, expected_type):
            self.fail(
                "ERROR : unexpected JSON type from "
                f"{context}: expected {expected_type.__name__}, got {type(data).__name__}"
            )
        return data

    def json_get(self, data, key, default=None, context="JSON output", required=False):
        """Return key from JSON dict and optionally fail if key is missing."""
        if not isinstance(data, dict):
            self.fail(
                f"ERROR : expected JSON object for {context}, got {type(data).__name__}"
            )
        if required and key not in data:
            self.fail(f"ERROR : missing key '{key}' in {context}: {data!r}")
        return data.get(key, default)

    def exec_cmd(self, cmd):
        """ Wrapper for executing a shell command and return the result. """
        return self.run_cmd(cmd).returncode

    def nvme_reset_ctrl(self):
        """ Wrapper for nvme reset command.
            - Args:
                - None:
            - Returns:
                - None
        """
        nvme_reset_cmd = f"{self.nvme_bin} reset {self.ctrl}"
        err = self.run_cmd(nvme_reset_cmd).returncode
        self.assertEqual(err, 0, "ERROR : nvme reset failed")

        if not self.is_windows():   # Rescan occurs during reset on Windows
            rescan_cmd = "echo 1 > /sys/bus/pci/rescan"
            result = self.run_cmd(rescan_cmd)
            self.assertEqual(result.returncode, 0, "ERROR : pci rescan failed")

    def get_ctrl_id(self):
        """ Wrapper for extracting the first controller id.
            - Args:
                - None
            - Returns:
                - controller id.
        """
        get_ctrl_id = f"{self.nvme_bin} list-ctrl {self.ctrl} " + \
            "--output-format=json"
        result = self.run_cmd(get_ctrl_id)
        self.assertEqual(result.returncode, 0, "ERROR : nvme list-ctrl failed")
        json_output = self.parse_json_output(result.stdout, "nvme list-ctrl")
        ctrl_list = self.json_get(json_output, 'ctrl_list', context="nvme list-ctrl", required=True)
        self.assertIsInstance(ctrl_list, list,
                              "ERROR : nvme list-ctrl returned invalid ctrl_list type")
        self.assertTrue(len(ctrl_list) > 0,
                        "ERROR : nvme list-ctrl could not find ctrl")
        first_ctrl = ctrl_list[0]
        self.assertIsInstance(first_ctrl, dict,
                              "ERROR : nvme list-ctrl returned invalid controller entry")
        self.assertIn('ctrl_id', first_ctrl,
                      f"ERROR : nvme list-ctrl missing ctrl_id: {first_ctrl!r}")
        return str(first_ctrl['ctrl_id'])

    def get_ns_mgmt_support(self):
        """
        Determine whether Namespace Management and Namespace Attachment
        operations are supported by the controller.

        This method reads the Optional Admin Command Support (OACS) field
        from the Identify Controller data structure and evaluates specific
        bits that indicate support for:
          - Namespace Management (bit 3)
          - Namespace Attachment (bit 4)

        Both features must be supported for this function to return True.

        Returns:
            bool: True if both Namespace Management and Namespace Attachment
            are supported, False otherwise.
        """
        if self.is_windows():
            return False    # Namespace management not supported on Windows

        oacs = to_decimal(self.get_id_ctrl_field_value("oacs"))

        ns_mgmt_supported = bool(oacs & (1 << 3))
        ns_attach_supported = bool(oacs & (1 << 4))

        return ns_mgmt_supported and ns_attach_supported

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
        result = self.run_cmd(ns_list_cmd)
        self.assertEqual(result.returncode, 0, "ERROR : nvme list namespace failed")
        json_output = self.parse_json_output(result.stdout, "nvme list-ns")

        nsid_list = self.json_get(json_output, 'nsid_list', context="nvme list-ns", required=True)
        self.assertIsInstance(nsid_list, list,
                              "ERROR : nvme list-ns returned invalid nsid_list type")
        for ns in nsid_list:
            self.assertIsInstance(ns, dict,
                                  f"ERROR : nvme list-ns returned invalid namespace entry: {ns!r}")
            self.assertIn('nsid', ns,
                          f"ERROR : nvme list-ns entry missing nsid: {ns!r}")
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
        result = self.run_cmd(max_ns_cmd)
        self.assertEqual(result.returncode, 0, "ERROR : reading maximum namespace count failed")
        json_output = self.parse_json_output(result.stdout, "nvme id-ctrl")
        nn = self.json_get(json_output, 'nn', context="nvme id-ctrl", required=True)
        self.assertIsNotNone(nn, "ERROR : reading maximum namespace count failed")
        return int(nn)

    def get_lba_status_supported(self):
        """ Check if 'Get LBA Status' command is supported by the device
            - Args:
                - None
            - Returns:
                - True if 'Get LBA Status' command is supported, otherwise False
        """
        return to_decimal(self.get_id_ctrl_field_value("oacs")) & (1 << 9)

    def _get_active_lbaf_index(self):
        """ Return the index of the currently active LBA format for ns1.
            - Args:
                - None
            - Returns:
                - lbaf index (int) of the format whose in_use flag is set,
                  or 0 if no in_use entry is found.
        """
        nvme_id_ns_cmd = f"{self.nvme_bin} id-ns {self.ns1} " + \
            "--output-format=json"
        result = self.run_cmd(nvme_id_ns_cmd)
        self.assertEqual(result.returncode, 0, "ERROR : reading id-ns")
        json_output = self.parse_json_output(result.stdout, "nvme id-ns")
        for lbaf in json_output.get('lbafs', []):
            self.assertIsInstance(lbaf, dict,
                                  f"ERROR : id-ns returned invalid lbaf entry: {lbaf!r}")
            if lbaf.get('in_use') == 1:
                self.assertIn('lbaf', lbaf,
                              f"ERROR : id-ns lbaf entry missing lbaf index: {lbaf!r}")
                return int(lbaf['lbaf'])
        return 0

    def _get_ns_dps(self):
        """ Return the Data Protection Settings (DPS) field for ns1.
            - Args:
                - None
            - Returns:
                - dps value (int); bits 2:0 are the PI type (non-zero means
                  end-to-end PI is enabled), bits 5:3 are the Protection
                  Information Format (PIF) on NVMe 2.0+ devices.
        """
        nvme_id_ns_cmd = f"{self.nvme_bin} id-ns {self.ns1} " + \
            "--output-format=json"
        result = self.run_cmd(nvme_id_ns_cmd)
        self.assertEqual(result.returncode, 0, "ERROR : reading id-ns")
        json_output = self.parse_json_output(result.stdout, "nvme id-ns")
        return int(json_output.get('dps', 0))

    def _get_pif(self):
        """ Return the Protection Information Format (PIF) for ns1.

            The PIF is stored in bits 5:3 of the DPS field (NVMe 2.0+):
              PIF 0 - 8-byte PI, 16-bit CRC guard (Type 1/2/3, all NVMe 1.x)
              PIF 1 - 16-byte PI, 64-bit CRC guard
              PIF 2 - 8-byte PI, 32-bit CRC guard

            NVMe 1.x devices always return 0 for these bits.

            - Args:
                - None
            - Returns:
                - pif value (int, 0-7).
        """
        nvme_id_ns_cmd = f"{self.nvme_bin} id-ns {self.ns1} " + \
            "--output-format=json"
        result = self.run_cmd(nvme_id_ns_cmd)
        self.assertEqual(result.returncode, 0, "ERROR : reading id-ns")
        json_output = self.parse_json_output(result.stdout, "nvme id-ns")
        dps = int(json_output.get('dps', 0))
        return (dps >> 3) & 0x7

    def _is_metadata_ext(self):
        """ Return True if the active LBA format uses extended LBA (bit 4 of
            the flbas field is set, meaning metadata is appended at the end of
            the data buffer). Return False if bit 4 is clear, meaning metadata
            is transferred as a separate, contiguous buffer.
        """
        nvme_id_ns_cmd = f"{self.nvme_bin} id-ns {self.ns1} " + \
            "--output-format=json"
        result = self.run_cmd(nvme_id_ns_cmd)
        self.assertEqual(result.returncode, 0, "ERROR : reading id-ns")
        json_output = self.parse_json_output(result.stdout, "nvme id-ns")
        flbas = int(json_output.get('flbas', 0))
        return bool(flbas & (1 << 4))

    def get_lba_format_size(self):
        """ Wrapper for extracting lba format size of the given flbas
            - Args:
                - None
            - Returns:
                - lba format size as a tuple of (data_size, metadata_size) in bytes.
        """
        nvme_id_ns_cmd = f"{self.nvme_bin} id-ns {self.ns1} " + \
            "--output-format=json"
        result = self.run_cmd(nvme_id_ns_cmd)
        self.assertEqual(result.returncode, 0, "ERROR : reading id-ns")
        json_output = self.parse_json_output(result.stdout, "nvme id-ns")
        lbafs = self.json_get(json_output, 'lbafs', context="nvme id-ns", required=True)
        self.assertIsInstance(lbafs, list,
                              f"ERROR : id-ns returned invalid lbafs type, expected list, got {type(lbafs).__name__}")
        self.assertTrue(len(lbafs) > self.flbas,
                        "ERROR : could not match the given flbas to an existing lbaf")
        lbaf_json = lbafs[int(self.flbas)]
        self.assertIsInstance(lbaf_json, dict,
                              f"ERROR : id-ns returned invalid lbaf entry, expected dict, got {type(lbaf_json).__name__}")
        self.assertIn('ms', lbaf_json, "ERROR : id-ns lbaf missing 'ms'")
        self.assertIn('ds', lbaf_json, "ERROR : id-ns lbaf missing 'ds'")
        ms = int(lbaf_json['ms'])
        ds_expo = int(lbaf_json['ds'])
        ds = (1 << ds_expo) if ds_expo > 0 else 0
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
        result = self.run_cmd(id_ctrl_cmd)
        self.assertEqual(result.returncode, 0, "ERROR : reading id-ctrl failed")
        json_output = self.parse_json_output(result.stdout, "nvme id-ctrl")
        self.assertTrue(field in json_output,
                        f"ERROR : reading field '{field}' failed")
        return str(json_output[field])

    def get_id_ns_field_value(self, field):
        """ Wrapper for extracting id-ns field values
            - Args:
                - field : field name to extract
            - Returns:
                - Field value of the given field as a string
        """
        id_ns_cmd = f"{self.nvme_bin} id-ns {self.ns1} " + \
            "--output-format=json"
        result = self.run_cmd(id_ns_cmd)
        self.assertEqual(result.returncode, 0, "ERROR : reading id-ns failed")
        json_output = self.parse_json_output(result.stdout, "nvme id-ns")
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
        result = self.run_cmd(list_ns_cmd)
        self.assertEqual(result.returncode, 0, "ERROR : nvme list-ns failed")
        json_output = self.parse_json_output(result.stdout, "nvme list-ns")
        nsid_list = self.json_get(json_output, 'nsid_list', context="nvme list-ns", required=True)
        self.assertIsInstance(nsid_list, list,
                              "ERROR : nvme list-ns returned invalid nsid_list type")
        self.assertEqual(len(nsid_list), 0,
                         "ERROR : deleting all namespace failed")

    def create_ns(self, nsze, ncap, flbas, dps):
        """ Wrapper for creating a namespace.
            - Args:
                - nsze : new namespace size.
                - ncap : new namespace capacity.
                - flbas : new namespace format.
                - dps : new namespace data protection information.
            - Returns:
                - Tuple of (returncode, stdout) from the nvme create-ns command.
        """
        create_ns_cmd = f"{self.nvme_bin} create-ns {self.ctrl} " + \
            f"--nsze={str(nsze)} --ncap={str(ncap)} --flbas={str(flbas)} " + \
            f"--dps={str(dps)} --verbose --output-format=json"
        result = self.run_cmd(create_ns_cmd)
        return result.returncode, result.stdout

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
        err, stdout = self.create_ns(nsze, ncap, flbas, dps)
        if err == 0:
            json_output = self.parse_json_output(stdout, "nvme create-ns")
            created_nsid = self.json_get(json_output, "nsid", "nvme create-ns", required=True)
            self.assertEqual(int(created_nsid), nsid,
                             "ERROR : create namespace failed")
            id_ns_cmd = f"{self.nvme_bin} id-ns {self.ctrl} " + \
                f"--namespace-id={str(nsid)}"
            err = self.run_cmd(id_ns_cmd).returncode
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
        err = self.run_cmd(attach_ns_cmd).returncode
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
        return self.run_cmd(detach_ns_cmd).returncode

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
        err = self.run_cmd(delete_ns_cmd).returncode
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
        result = self.run_cmd(smart_log_cmd)
        err = result.returncode
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
        result = self.run_cmd(id_ctrl_cmd)
        err = result.returncode
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
        result = self.run_cmd(error_log_cmd)
        err = result.returncode
        self.assertEqual(err, 0, "ERROR : nvme error log failed")
        # This sanity checkes the 'normal' output
        lines = result.stdout.splitlines()
        if not lines:
            return 1
        err_log_entry_count = int(lines[0].split(" ")[5].strip().split(":")[1])
        entry_count = sum(1 for line in lines[1:] if pattern.match(line))

        return 0 if err_log_entry_count == entry_count else 1

    def _get_rw_io_params_per_lba(self, lba_size=None, update_cache=False):
        """Return (ms, prinfo, data_size_per_lba).

        ms: metadata size per LBA.
        prinfo: NVMe Protection Information setting (0 or 8).
        data_size_per_lba: data payload per LBA (block_size + metadata if extended).

        Args:
            lba_size:     Optional LBA data size in bytes. If 0 or None, uses
                          namespace's default LBA data size.
            update_cache: If True, refresh cached namespace parameters
                          from the device. Defaults to False.

        PI type occupies bits 2:0 of the DPS field; bits 5:3 are PIF.
        """
        # Update cached values in case they were changed by a previous action.
        if update_cache:
            self.ns_dps = self._get_ns_dps()
            self.ns_meta_ext = self._is_metadata_ext()
            self.flbas = self._get_active_lbaf_index()
        (ds, ms) = self.get_lba_format_size()

        # Determine block size from provided size, or use namespace default.
        block_size = ds if lba_size in (None, 0) else int(lba_size)

        pi_type = self.ns_dps & 0x7

        if pi_type != 0 and ms != 0 and self.ns_meta_ext:
            # PI active + extended LBA (metadata appended to data buffer).
            # Use PRACT=1 (--prinfo=8) so the controller inserts and strips PI
            # automatically. With PRACT=1 the PI bytes are not transferred
            # over the host interface, so data_size equals the logical block
            # data size only (block_size), not block_size+ms. This works for all PI sizes
            # (8 bytes for PIF 0/2, 16 bytes for PIF 1) and all guard widths
            # (16-bit, 32-bit, 64-bit CRC) because the controller handles
            # the PI entirely.
            prinfo = 8
            data_size = block_size
        elif pi_type != 0 and ms != 0 and not self.ns_meta_ext:
            # PI active + separate metadata (flbas bit 4 clear). PRACT=1
            # (--prinfo=8) is invalid for the Compare command on this format
            # (NVMe spec: PRACT=1 for Compare requires PI in the host data
            # buffer, which only applies to the extended-LBA layout). Use
            # prinfo=0 (PRACT=0, PRCHK=0) for all operations and supply an
            # explicit zero-filled metadata buffer of ms bytes so that the
            # stored metadata and the compared metadata are both known zeros.
            # PRCHK=0 skips PI validation, so the zero PI bytes are accepted
            # by the controller on write and matched exactly on compare. This
            # is PI-format and guard-width agnostic: the entire ms-byte
            # metadata slot (whether holding an 8-byte PI with 16-bit or
            # 32-bit guard, or a 16-byte PI with 64-bit guard) is zeroed.
            prinfo = 0
            data_size = block_size
        else:
            # No PI. For extended LBA format (metadata appended to the data
            # buffer) include the metadata bytes so that the controller sees
            # a consistent data+metadata unit. For separate metadata format
            # (flbas bit 4 clear) metadata is transferred via a different
            # pointer and must NOT be folded into the data buffer; use block_size only
            # so that the data transfer length matches exactly one LBA.
            prinfo = 0
            data_size = block_size + ms if self.ns_meta_ext else block_size

        return ms, prinfo, data_size

    def _build_nvme_rw_cmd(self, opcode, ns_path, start_block, block_count,
                           data_size, data_file, prinfo=0,
                           metadata_size=0, metadata_file=None):
        """Build nvme read/write command with optional PI/metadata options."""
        cmd = f'{self.nvme_bin} {opcode} {ns_path} ' + \
            f'--start-block={str(start_block)} ' + \
            f'--block-count={str(block_count)} ' + \
            f'--data-size={str(data_size)} --data="{data_file}"'

        if prinfo:
            cmd += f" --prinfo={prinfo}"
        if metadata_size > 0 and metadata_file is not None:
            cmd += f' --metadata-size={metadata_size} --metadata="{metadata_file}"'

        return cmd

    def run_ns_io(self, nsid, lbads, count=10):
        """ Wrapper to run ios on namespace under test.
            - Args:
                - lbads : LBA Data size supported in power of 2 format.
            - Returns:
                - None
        """
        count = int(count)
        lbads = 0 if lbads is None else int(lbads)
        lba_size = 0 if lbads < 9 else 2 ** lbads
        ms, prinfo, data_size_per_lba = self._get_rw_io_params_per_lba(lba_size, True)
        ns_path = self.ns1 if int(nsid) == int(self.default_nsid) else self.ctrl + "n" + str(nsid)
        block_count = count - 1
        data_size = data_size_per_lba * count
        metadata_size = ms * count if ms > 0 and not self.ns_meta_ext else 0

        log_root = self.test_log_dir if self.test_log_dir != "XXX" else self.log_dir
        if not os.path.exists(log_root):
            os.makedirs(log_root)

        write_file = os.path.join(log_root, f"run_ns_io_write_{nsid}.bin")
        read_file = os.path.join(log_root, f"run_ns_io_read_{nsid}.bin")
        write_meta_file = os.path.join(log_root, f"run_ns_io_write_meta_{nsid}.bin")
        read_meta_file = os.path.join(log_root, f"run_ns_io_read_meta_{nsid}.bin")

        with open(write_file, "wb") as out_file:
            out_file.write(bytes(data_size))
        open(read_file, 'a').close()

        if metadata_size > 0:
            with open(write_meta_file, "wb") as meta_out:
                meta_out.write(bytes(metadata_size))
            open(read_meta_file, 'a').close()

        read_cmd = self._build_nvme_rw_cmd("read", ns_path, 0, block_count,
                                           data_size, read_file, prinfo,
                                           metadata_size, read_meta_file)
        self.assertEqual(self.run_cmd(read_cmd).returncode, 0)

        write_cmd = self._build_nvme_rw_cmd("write", ns_path, 0, block_count,
                                            data_size, write_file, prinfo,
                                            metadata_size, write_meta_file)
        self.assertEqual(self.run_cmd(write_cmd).returncode, 0)
