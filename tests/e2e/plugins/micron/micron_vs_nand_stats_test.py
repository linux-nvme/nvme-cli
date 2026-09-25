# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron vs-nand-stats command.

vs-nand-stats reports NAND wear and failure counters.  Three log pages can
back it depending on the drive: 0xC0 on a Hyperscale boot SSD, 0xFB where the
vendor-specific health log exists, and 0xD0 otherwise.  Each renders as a
"<label> : 0x<hex>" text table or as a single top-level JSON key holding a
one-element array of field objects.

The 0xFB variant reports the vendor health log fields followed by the seven
0xD0 derived counters, so its field set is a superset of the 0xD0 one.

The option surface and log page selection per model and customer ID are covered
without hardware in micron_vs_smart_logs_mock_test.py.  The tests here decode
a real drive's log.

Tests in this module verify:
  * The text field table and the JSON field object are both well formed.
  * The JSON top-level key names one of the three supported log pages.
  * The text and JSON field sets and values are identical.
  * The field labels defined for the reported log page are present.
  * The controller and namespace paths report the same fields.
"""

from .micron_test import TestMicron

_COMMAND = "vs-nand-stats"

# One key per log page vs-nand-stats can report.
_JSON_KEYS = (
    "Extended Smart Log Page : 0xC0",
    "Extended Smart Log Page : 0xFB",
    "Extended Smart Log Page : 0xD0",
)

# The seven derived counters the 0xD0 path reports, which the 0xFB path
# appends to the vendor health log fields.
_D0_LABELS = (
    "NAND Writes (Bytes Written)",
    "Program Failure Count",
    "Erase Failures",
    "Bad Block Count",
    "NAND XOR/RAID Recovery Trigger Events",
    "NSZE Change Supported",
    "Number of NSZE Modifications",
)

_REQUIRED_LABELS = {
    "Extended Smart Log Page : 0xD0": _D0_LABELS,
    "Extended Smart Log Page : 0xFB": _D0_LABELS + (
        "Physical Media Units Written - TLC",
        "Physical Media Units Written - SLC",
        "Raw Bad User NAND Block Count",
        "Log Page GUID",
    ),
    "Extended Smart Log Page : 0xC0": (
        "Physical Media Units Written - TLC",
        "Physical Media Units Written - SLC",
        "Bad User NAND Block Count (Raw)",
        "Endurance Estimate",
        "Boot SSD Spec Version",
    ),
}


class TestMicronVsNandStats(TestMicron):
    """Test suite for the micron vs-nand-stats plugin command."""

    def test_text_field_table(self):
        """Text output is a well-formed '<label> : 0x<hex>' field table."""
        self.check_hex_fields_table(_COMMAND)

    def test_json_field_object(self):
        """JSON output holds one known log-page key with a field object."""
        self.check_hex_fields_json(_COMMAND, _JSON_KEYS)

    def test_text_and_json_fields_match(self):
        """The text and JSON forms report identical fields and values."""
        self.check_text_and_json_hex_fields_match(_COMMAND, _JSON_KEYS)

    def test_required_labels_present(self):
        """Every field label defined for the reported log page is present."""
        self.check_required_hex_fields_present(_COMMAND, _JSON_KEYS, _REQUIRED_LABELS)

    def test_namespace_path_matches_controller(self):
        """The namespace path reports the same fields as the controller path."""
        self.check_ns_hex_fields_match_ctrl(_COMMAND, _JSON_KEYS)
