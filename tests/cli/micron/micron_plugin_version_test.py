#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron plugin-version commands.

plugin-version and cloud-SSD-plugin-version both print a static version
string built from the plugin's version macros and perform no device I/O at
all.  They are registered with .no_device = true, so they run without a device
argument and ignore one if given, which means they need neither a real drive
nor the command mock.

Tests in this module verify:
  * The exact version string and a zero exit status for both commands.
  * The cloud SSD version being the major.minor prefix of the plugin version,
    since both are built from the same macros.
  * A device argument being accepted without changing the output.
  * The --help usage line advertising no <device> operand.
  * JSON output wrapping the same string in a "result" object.

Usage: python3 micron_plugin_version_test.py <path-to-nvme-binary>
"""

import re
import subprocess
import sys
import unittest

from tests.nvme_test import TestNVMeBase

_NVME_BIN = sys.argv[1] \
    if len(sys.argv) > 1 and not sys.argv[1].startswith('-') \
    else 'nvme'

_PLUGIN_VERSION = "plugin-version"
_CLOUD_VERSION = "cloud-SSD-plugin-version"

_PLUGIN_VERSION_RE = re.compile(
    r"^nvme-cli Micron plugin version: (\d+)\.(\d+)\.(\d+)$")
_CLOUD_VERSION_RE = re.compile(
    r"^nvme-cli Micron cloud SSD plugin version: (\d+)\.(\d+)$")


class TestMicronPluginVersion(TestNVMeBase):
    """The micron version commands, which touch no device."""

    def setUp(self):
        super().setUp()
        self.nvme_bin = _NVME_BIN

    def run_version(self, command, device=None, args=()):
        argv = [self.nvme_bin, 'micron', command]
        if device:
            argv.append(device)
        argv.extend(args)
        return subprocess.run(argv, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, check=False)

    def run_version_check(self, command, device=None, args=()):
        result = self.run_version(command, device=device, args=args)
        self.assertEqual(result.returncode, 0,
                         f"micron {command} failed: rc={result.returncode}, "
                         f"stderr={result.stderr!r}")
        return result

    def check_device_argument_ignored(self, command):
        """A device argument must not change the output."""
        without = self.run_version_check(command).stdout
        with_device = self.run_version_check(command,
                                             device="/dev/nvme0").stdout

        self.assertEqual(with_device, without,
                         f"micron {command} output changed when a device was "
                         f"supplied")

    def check_help_omits_device(self, command):
        """--help must advertise no <device> operand."""
        result = self.run_version(command, args=("--help",))
        output = result.stdout + result.stderr

        self.assertRegex(output, rf"Usage: nvme micron {command} \[OPTIONS\]")
        self.assertNotIn("<device>", output,
                         f"micron {command} usage should not take a device")

    def check_json_wraps_text(self, command):
        """JSON output reports the text output under a result key."""
        text = self.run_version_check(command).stdout.strip()
        result = self.run_version_check(command,
                                        args=("--output-format=json",))
        data = self.parse_json_output(
            result.stdout, f"micron {command} --output-format=json")

        self.assertEqual(data, {"result": text})

    def test_plugin_version_string(self):
        """plugin-version prints its three-part version."""
        result = self.run_version_check(_PLUGIN_VERSION)

        self.assertRegex(result.stdout.strip(), _PLUGIN_VERSION_RE)

    def test_cloud_plugin_version_string(self):
        """cloud-SSD-plugin-version prints its two-part version."""
        result = self.run_version_check(_CLOUD_VERSION)

        self.assertRegex(result.stdout.strip(), _CLOUD_VERSION_RE)

    def test_cloud_version_matches_the_plugin_version_prefix(self):
        """Both are built from the same version macros."""
        plugin = _PLUGIN_VERSION_RE.match(
            self.run_version_check(_PLUGIN_VERSION).stdout.strip())
        cloud = _CLOUD_VERSION_RE.match(
            self.run_version_check(_CLOUD_VERSION).stdout.strip())
        self.assertIsNotNone(plugin)
        self.assertIsNotNone(cloud)

        self.assertEqual(cloud.group(1, 2), plugin.group(1, 2))

    def test_plugin_version_ignores_a_device_argument(self):
        self.check_device_argument_ignored(_PLUGIN_VERSION)

    def test_cloud_plugin_version_ignores_a_device_argument(self):
        self.check_device_argument_ignored(_CLOUD_VERSION)

    def test_plugin_version_help_omits_the_device_operand(self):
        self.check_help_omits_device(_PLUGIN_VERSION)

    def test_cloud_plugin_version_help_omits_the_device_operand(self):
        self.check_help_omits_device(_CLOUD_VERSION)

    def test_plugin_version_json_output(self):
        self.check_json_wraps_text(_PLUGIN_VERSION)

    def test_cloud_plugin_version_json_output(self):
        self.check_json_wraps_text(_CLOUD_VERSION)


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]], verbosity=2)
