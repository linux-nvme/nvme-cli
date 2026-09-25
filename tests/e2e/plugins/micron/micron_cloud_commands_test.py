# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron cloud SSD commands.

vs-cloud-log, vs-device-waf and cloud-boot-SSD-version all report data from
the vendor cloud health log, and all three are reachable only on a drive
whose customer ID in the vendor-specific identify data marks it as a cloud
SSD; otherwise they print "<command> option is not supported for specified
drive".  vs-cloud-log is additionally gated on the drive model derived from
the PCI device ID, and prints "Unsupported drive model for <command>" when
that gate rejects the drive.

vs-cloud-log renders the log as a field table in normal or JSON form.
vs-device-waf and cloud-boot-SSD-version each derive a single value from it
and print one line of text, declaring no output formats at all, so a format
flag changes nothing rather than being rejected.

On unsupported drives, the gating contract is the primary thing under test.

Both sides of every gate, the derived values and the output formats are
covered without hardware in micron_cloud_commands_mock_test.py.  The tests
here check that a real cloud SSD's log decodes into plausible output.

Tests in this module verify:
  * The field table of vs-cloud-log in both text and JSON form.
  * The single-line output of vs-device-waf and cloud-boot-SSD-version.
"""

import re

from .micron_test import TestMicron

_CLOUD_LOG = "vs-cloud-log"
_DEVICE_WAF = "vs-device-waf"
_BOOT_VERSION = "cloud-boot-SSD-version"

# The top-level JSON key vs-cloud-log emits.
_JSON_KEYS = ("OCP Hyperscale Cloud Health Log: 0xC0",)

_WAF_RE = re.compile(r"^Write Amplification Factor \d+$")
_BOOT_VERSION_RE = re.compile(r"^HyperScale Boot Version Spec\.[0-9a-f]+\.[0-9a-f]+$")


class TestMicronCloudCommands(TestMicron):
    """Test suite for the micron cloud SSD commands."""

    def test_cloud_log_text_field_table(self):
        """vs-cloud-log prints a well-formed '<label> : 0x<hex>' table."""
        self.check_hex_fields_table(_CLOUD_LOG)

    def test_cloud_log_json_field_object(self):
        """vs-cloud-log reports the cloud health log as one JSON key."""
        self.check_hex_fields_json(_CLOUD_LOG, _JSON_KEYS)

    def test_device_waf_prints_factor(self):
        """vs-device-waf prints a single 'Write Amplification Factor <N>' line."""
        result = self.run_supported_cmd(_DEVICE_WAF)

        self.assertRegex(
            result.stdout.strip(), _WAF_RE,
            f"Unexpected vs-device-waf output: {result.stdout!r}",
        )

    def test_cloud_boot_ssd_version_prints_spec(self):
        """cloud-boot-SSD-version prints 'HyperScale Boot Version Spec.<x>.<y>'."""
        result = self.run_supported_cmd(_BOOT_VERSION)

        self.assertRegex(
            result.stdout.strip(), _BOOT_VERSION_RE,
            f"Unexpected cloud-boot-SSD-version output: {result.stdout!r}",
        )
