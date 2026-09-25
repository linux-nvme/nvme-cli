# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron log-page-directory command.

The log-page-directory command lists the log pages the drive supports.  It
does not read a directory from the device: it walks a fixed table of known
log page IDs, issues a small Get Log Page for each one, and prints the ID
and description of every page the drive accepts.  Output is a plain text
table only.

The row format, the known-page table and the exit status are covered without
hardware in micron_log_page_directory_mock_test.py.  The tests here check the
listing a real drive produces.

Tests in this module verify:
  * The mandatory SMART / Health Information page (02h) is always listed.
  * --output-format=normal matches the default output.
  * The controller and namespace device paths list the same log pages.
"""

import re

from .micron_test import TestMicron

_COMMAND = "log-page-directory"

_HEADER_TITLE = "Supported log page list"
_HEADER_COLUMNS = "Log ID : Description"

# printf("%02Xh    : %s\n", log_id, desc) -- exactly four spaces before the
# separator, and upper-case hex.
_ROW_RE = re.compile(r"^([0-9A-F]{2})h {4}: (.+)$")

# The fixed table micron_logpage_dir() probes, mirrored from the plugin.
_KNOWN_LOG_PAGES = {
    0x00: "Supported Log Pages",
    0x01: "Error Information",
    0x02: "SMART / Health Information",
    0x03: "Firmware Slot Information",
    0x04: "Changed Namespace List",
    0x05: "Commands Supported and Effects",
    0x06: "Device Self Test",
    0x07: "Telemetry Host-Initiated",
    0x08: "Telemetry Controller-Initiated",
    0x09: "Endurance Group Information",
    0x0A: "Predictable Latency Per NVM Set",
    0x0B: "Predictable Latency Event Aggregate",
    0x0C: "Asymmetric Namespace Access",
    0x0D: "Persistent Event Log",
    0x0E: "LBA Status Information",
    0x0F: "Endurance Group Event Aggregate",
    0x10: "Media Unit Status",
    0x11: "Supported Capacity Configuration List",
    0x12: "Feature Identifiers Supported and Effects",
    0x13: "NVMe-MI Commands Supported and Effects",
    0x14: "Command and Feature lockdown",
    0x15: "Boot Partition",
    0x16: "Rotational Media Information",
    0x70: "Discovery",
    0x80: "Reservation Notification",
    0x81: "Sanitize Status",
    0xC0: "SMART Cloud Health Log",
    0xC2: "Firmware Activation History",
    0xC3: "Latency Monitor Log",
}

# Mandatory for every NVMe controller, so it must appear on any drive.
_SMART_HEALTH_ID = 0x02
_SMART_HEALTH_DESC = _KNOWN_LOG_PAGES[_SMART_HEALTH_ID]


class TestMicronLogPageDirectory(TestMicron):
    """Test suite for the micron log-page-directory plugin command."""

    def _run_dir(self, device=None, args=""):
        """Run log-page-directory and return the CompletedProcess result."""
        return self.run_plugin_cmd(_COMMAND, device=device, args=args)

    def _listed_pages(self, stdout, context=""):
        """Return {log_id: description} parsed from the listing rows.

        Every non-header line must be a well-formed row; anything else is a
        formatting regression.
        """
        where = f" ({context})" if context else ""
        pages = {}
        for line in stdout.splitlines():
            if not line.strip() or line in (_HEADER_TITLE, _HEADER_COLUMNS):
                continue
            match = _ROW_RE.match(line)
            self.assertIsNotNone(
                match,
                f"Line does not match '<ID>h    : <description>'{where}: "
                f"{line!r}",
            )
            log_id = int(match.group(1), 16)
            self.assertNotIn(
                log_id, pages,
                f"Log page {match.group(1)}h listed more than once{where}: "
                f"{stdout!r}",
            )
            pages[log_id] = match.group(2)
        self.assertGreater(
            len(pages), 0,
            f"Expected at least one supported log page row{where}, "
            f"got: {stdout!r}",
        )
        return pages

    def test_smart_health_log_page_is_listed(self):
        """log-page-directory always lists 02h SMART / Health Information.

        The SMART / Health Information log is mandatory for every NVMe
        controller, so its probe must succeed on any drive.
        """
        result = self._run_dir()
        pages = self._listed_pages(result.stdout)

        self.assertIn(
            _SMART_HEALTH_ID, pages,
            f"Expected mandatory log page {_SMART_HEALTH_ID:02X}h in the "
            f"listing, got: {sorted(f'{i:02X}h' for i in pages)}",
        )
        self.assertEqual(
            pages[_SMART_HEALTH_ID], _SMART_HEALTH_DESC,
            f"Expected {_SMART_HEALTH_DESC!r} for "
            f"{_SMART_HEALTH_ID:02X}h, got: {pages[_SMART_HEALTH_ID]!r}",
        )

    def test_explicit_normal_format_matches_default(self):
        """--output-format=normal produces the same listing as no format flag."""
        default = self._run_dir()
        normal = self._run_dir(args="--output-format=normal")

        self.assertEqual(
            self._listed_pages(normal.stdout, "--output-format=normal"),
            self._listed_pages(default.stdout, "default"),
            f"--output-format=normal listing differs from the default:\n"
            f"  default: {default.stdout!r}\n"
            f"  normal:  {normal.stdout!r}",
        )

    def test_namespace_lists_same_log_pages_as_controller(self):
        """The namespace path lists the same log pages as the controller path.

        A namespace path resolves to its parent controller, so both must probe
        the same set of log pages.
        """
        result_ctrl = self._run_dir(device=self.ctrl)
        result_ns = self._run_dir(device=self.ns1)

        pages_ctrl = self._listed_pages(result_ctrl.stdout, self.ctrl)
        pages_ns = self._listed_pages(result_ns.stdout, self.ns1)

        self.assertEqual(
            pages_ctrl, pages_ns,
            f"Controller and namespace paths listed different log pages:\n"
            f"  ctrl ({self.ctrl}): "
            f"{sorted(f'{i:02X}h' for i in pages_ctrl)}\n"
            f"  ns1  ({self.ns1}):  "
            f"{sorted(f'{i:02X}h' for i in pages_ns)}",
        )
