#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron log-page-directory command, hardware-free.

log-page-directory does not read a directory from the drive.  It walks a
fixed table of known log page IDs, issues a small Get Log Page for each, and
lists the ones the drive accepted.

On real hardware the listing is whatever that drive supports, so a test can
only check a subset of it.  Here the mock decides exactly which pages
succeed, so the printed list is asserted to be exactly the accepted set --
including the cases that matter most: no pages at all, and every page.

Tests in this module verify:
  * The two header lines and the row format.
  * The listing is exactly the set of pages the drive accepted, for several
    arbitrary sets including none and all.
  * Every table entry is probed, exactly once, in table order.
  * The exit status is 0 even when the last probed page is rejected, which is
    the case a "return the last error" bug would break.
  * The command runs on an unrecognised drive model.
  * Error handling for a non-existent device.

Usage: python3 micron_log_page_directory_mock_test.py <nvme-binary> <mock-lib>
"""

import re

from micron_mock_test import TestMicronMock, main

_COMMAND = "log-page-directory"

_HEADER_TITLE = "Supported log page list"
_HEADER_COLUMNS = "Log ID : Description"

# printf("%02Xh    : %s\n", ...) -- four spaces before the separator, and
# upper-case hex.
_ROW_RE = re.compile(r"^([0-9A-F]{2})h {4}: (.+)$")

# The fixed table micron_logpage_dir() probes, in the order it probes it.
_KNOWN_LOG_PAGES = (
    (0x00, "Supported Log Pages"),
    (0x01, "Error Information"),
    (0x02, "SMART / Health Information"),
    (0x03, "Firmware Slot Information"),
    (0x04, "Changed Namespace List"),
    (0x05, "Commands Supported and Effects"),
    (0x06, "Device Self Test"),
    (0x07, "Telemetry Host-Initiated"),
    (0x08, "Telemetry Controller-Initiated"),
    (0x09, "Endurance Group Information"),
    (0x0A, "Predictable Latency Per NVM Set"),
    (0x0B, "Predictable Latency Event Aggregate"),
    (0x0C, "Asymmetric Namespace Access"),
    (0x0D, "Persistent Event Log"),
    (0x0E, "LBA Status Information"),
    (0x0F, "Endurance Group Event Aggregate"),
    (0x10, "Media Unit Status"),
    (0x11, "Supported Capacity Configuration List"),
    (0x12, "Feature Identifiers Supported and Effects"),
    (0x13, "NVMe-MI Commands Supported and Effects"),
    (0x14, "Command and Feature lockdown"),
    (0x15, "Boot Partition"),
    (0x16, "Rotational Media Information"),
    (0x70, "Discovery"),
    (0x80, "Reservation Notification"),
    (0x81, "Sanitize Status"),
    (0xC0, "SMART Cloud Health Log"),
    (0xC2, "Firmware Activation History"),
    (0xC3, "Latency Monitor Log"),
)

_DESCRIPTIONS = dict(_KNOWN_LOG_PAGES)
_ALL_LIDS = tuple(lid for lid, _ in _KNOWN_LOG_PAGES)

# The probe reads MIN_LOG_SIZE bytes of each page.
_PROBE_SIZE = 512


class TestMicronLogPageDirectory(TestMicronMock):
    """log-page-directory against a drive with a chosen set of log pages."""

    def support(self, lids):
        """Make exactly @lids readable; every other page is rejected."""
        self.server.logs = {lid: bytes(_PROBE_SIZE) for lid in lids}
        # The SMART log has a default payload of its own, so drop it unless
        # this test wants 0x02 listed.
        wants_smart = self.server.logs.get(0x02) is not None
        self.server.smart = bytes(_PROBE_SIZE) if wants_smart else None

    def listed(self, stdout):
        """Return {lid: description} from the printed rows."""
        rows = {}
        for line in stdout.splitlines():
            m = _ROW_RE.match(line)
            if m:
                rows[int(m.group(1), 16)] = m.group(2)
        return rows

    # ---------------------------------------------------------------- #
    # Output shape                                                     #
    # ---------------------------------------------------------------- #

    def test_prints_both_header_lines(self):
        """The listing is introduced by a title and a column header."""
        self.support([0x02])
        result = self.run_plugin_cmd_check(_COMMAND)
        lines = result.stdout.splitlines()

        self.assertIn(_HEADER_TITLE, lines)
        self.assertIn(_HEADER_COLUMNS, lines)
        self.assertLess(lines.index(_HEADER_TITLE),
                        lines.index(_HEADER_COLUMNS),
                        "the title must come before the column header")

    def test_row_format_and_descriptions(self):
        """Each row pairs an upper-case hex ID with the table description."""
        self.support([0x00, 0x02, 0xC3])
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertEqual(self.listed(result.stdout), {
            0x00: _DESCRIPTIONS[0x00],
            0x02: _DESCRIPTIONS[0x02],
            0xC3: _DESCRIPTIONS[0xC3],
        })

    def test_two_digit_ids_are_zero_padded(self):
        """A single-digit ID is padded, so the column stays aligned."""
        self.support([0x01])
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertIn(f"01h    : {_DESCRIPTIONS[0x01]}", result.stdout)

    # ---------------------------------------------------------------- #
    # The listing is exactly what the drive accepted                   #
    # ---------------------------------------------------------------- #

    def test_lists_exactly_the_accepted_pages(self):
        """Only pages the drive accepted are listed, and all of them are."""
        cases = {
            'mandatory only': (0x02,),
            'the first entry': (0x00,),
            'the last entry': (0xC3,),
            'vendor pages': (0xC0, 0xC2, 0xC3),
            'a scattered mix': (0x01, 0x05, 0x0E, 0x16, 0x70, 0x81),
            'every page': _ALL_LIDS,
        }
        for name, lids in cases.items():
            with self.subTest(supported=name):
                self.support(lids)
                result = self.run_plugin_cmd_check(_COMMAND)

                self.assertEqual(
                    sorted(self.listed(result.stdout)), sorted(lids),
                    f"the listing does not match the accepted pages "
                    f"({name})",
                )

    def test_no_rows_when_the_drive_accepts_nothing(self):
        """A drive rejecting every page still prints the headers, no rows."""
        self.support([])
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertIn(_HEADER_TITLE, result.stdout)
        self.assertEqual(self.listed(result.stdout), {})

    def test_unknown_page_ids_are_never_listed(self):
        """A page outside the table is not reported even if it is readable.

        The command walks its own table rather than asking the drive, so an
        accepted page it does not know about must not appear.
        """
        self.support([0x02, 0xE1, 0xFB])
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertEqual(sorted(self.listed(result.stdout)), [0x02])

    # ---------------------------------------------------------------- #
    # Probing behaviour                                                #
    # ---------------------------------------------------------------- #

    def test_probes_every_table_entry_once_in_order(self):
        """The whole table is walked in order, one read per entry."""
        self.support([0x02])
        self.server.commands.clear()
        self.run_plugin_cmd_check(_COMMAND)
        probed = [c['lid'] for c in self.server.log_reads()]

        self.assertEqual(probed, list(_ALL_LIDS),
                         "the table was not walked exactly once, in order")

    def test_probe_reads_a_small_fixed_size(self):
        """Each probe asks for one small buffer, not the whole page."""
        self.support([0x02])
        self.server.commands.clear()
        self.run_plugin_cmd_check(_COMMAND)

        for command in self.server.log_reads():
            self.assertEqual(
                command['len'], _PROBE_SIZE,
                f"page {command['lid']:#04x} was probed with "
                f"{command['len']} bytes",
            )

    # ---------------------------------------------------------------- #
    # Exit status                                                      #
    # ---------------------------------------------------------------- #

    def test_exits_zero_when_the_last_page_is_rejected(self):
        """The listing succeeding does not depend on the last page probed.

        The final table entry is 0xC3; returning the loop's last error would
        make a drive without it look like a failure.
        """
        self.support([lid for lid in _ALL_LIDS if lid != 0xC3])
        result = self.run_plugin_cmd(_COMMAND)

        self.assertEqual(
            result.returncode, 0,
            f"exit {result.returncode} although the listing printed: "
            f"{result.stdout!r}",
        )
        self.assertNotIn(0xC3, self.listed(result.stdout))

    def test_exits_zero_when_no_page_is_accepted(self):
        """Even an empty listing is a successful run, not an error."""
        self.support([])
        result = self.run_plugin_cmd(_COMMAND)

        self.assertEqual(result.returncode, 0,
                         f"exit {result.returncode} for an empty listing")

    def test_exits_zero_when_every_page_is_accepted(self):
        self.support(_ALL_LIDS)
        result = self.run_plugin_cmd(_COMMAND)

        self.assertEqual(result.returncode, 0)

    # ---------------------------------------------------------------- #
    # Drive independence                                               #
    # ---------------------------------------------------------------- #

    def test_runs_on_an_unrecognised_drive_model(self):
        """The command reads no model, so it is not gated on one."""
        self.select_model(None)
        self.support([0x02, 0xC0])
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertEqual(sorted(self.listed(result.stdout)), [0x02, 0xC0])

    def test_namespace_path_matches_the_controller_path(self):
        """A namespace path resolves to its parent controller."""
        self.support([0x02, 0x07, 0xC2])
        ctrl = self.run_plugin_cmd_check(_COMMAND, device=self.ctrl)
        ns = self.run_plugin_cmd_check(_COMMAND, device=self.ns1)

        self.assertEqual(self.listed(ctrl.stdout), self.listed(ns.stdout))

    def test_bad_device_returns_error(self):
        """A non-existent device fails with the device path in the message."""
        self.check_bad_device_name(_COMMAND)


if __name__ == '__main__':
    main()
