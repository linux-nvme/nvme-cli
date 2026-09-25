# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron vs-smart-ext-log and vs-smart-add-log commands.

Both commands read a vendor SMART log page and render it through the shared
field-table path (generic_structure_parser): one "<label> : 0x<hex>" line per
field in text mode, or a single top-level key holding a one-element array of
field objects in JSON mode.  Which log page is read depends on the drive
model, so the top-level JSON key varies between drives.

vs-smart-ext-log prints a header line naming the log page in text mode;
vs-smart-add-log prints none.

The log page selection per model, the field layouts, and the option surface
are covered without hardware in micron_vs_smart_logs_mock_test.py.  The tests
here decode a real drive's logs.

Tests in this module verify:
  * The text field table and the JSON field object are both well formed.
  * The JSON top-level key is one the plugin can emit for that command.
  * The text and JSON field sets and values are identical.
  * The log-page specific field labels are present.
  * vs-smart-ext-log's text header equals its JSON top-level key, and
    vs-smart-add-log emits no header.
  * The controller and namespace paths report the same fields.
"""

from .micron_test import TestMicron

_EXT_LOG = "vs-smart-ext-log"
_ADD_LOG = "vs-smart-add-log"

# Top-level JSON keys each command can emit, one per supported log page.
_JSON_KEYS = {
    _EXT_LOG: (
        "SMART Extended Log:0xE1",
        "SMART Extended Log:0xD0",
    ),
    _ADD_LOG: (
        "OCP DataCenter SMART Health Log: 0xC0",
        "OCP SMART Cloud Health Log: 0xC0",
        "Extended Smart Log Page : 0xFB",
    ),
}

# Labels that must appear for a given log page, taken from its field table in
# micron-nvme.c.  Log pages absent from this map are not asserted against.
_REQUIRED_LABELS = {
    "SMART Extended Log:0xE1": (
        "Grown Bad Block Count",
        "Per Block Max Erase Count",
        "Power On Minutes",
        "Total Erase Count",
        "User Block Max Erase Count",
    ),
    "SMART Extended Log:0xD0": (
        "Version",
        "Grown Bad Block Count",
        "Total Erase Count",
        "Erase Fail Count",
    ),
    "OCP DataCenter SMART Health Log: 0xC0": (
        "Physical Media Units Written",
        "Physical Media Units Read",
        "Raw Bad User NAND Block Count",
        "Log Page Version",
        "Log Page GUID",
    ),
    "OCP SMART Cloud Health Log: 0xC0": (
        "Physical Media Units Written",
        "Physical Media Units Read",
        "Raw Bad User NAND Block Count",
        "NUSE",
        "Log Page Version",
        "Log Page GUID",
    ),
    "Extended Smart Log Page : 0xFB": (
        "Physical Media Units Written - TLC",
        "Physical Media Units Written - SLC",
        "Raw Bad User NAND Block Count",
        "Log Page Version",
    ),
}


class TestMicronVsSmartLogs(TestMicron):
    """Test suite for the micron vendor SMART log commands."""

    def test_ext_log_text_field_table(self):
        """vs-smart-ext-log prints a well-formed '<label> : 0x<hex>' table."""
        self.check_hex_fields_table(_EXT_LOG)

    def test_add_log_text_field_table(self):
        """vs-smart-add-log prints a well-formed '<label> : 0x<hex>' table."""
        self.check_hex_fields_table(_ADD_LOG)

    def test_ext_log_json_field_object(self):
        """vs-smart-ext-log JSON holds one known log-page key and its fields."""
        self.check_hex_fields_json(_EXT_LOG, _JSON_KEYS[_EXT_LOG])

    def test_add_log_json_field_object(self):
        """vs-smart-add-log JSON holds one known log-page key and its fields."""
        self.check_hex_fields_json(_ADD_LOG, _JSON_KEYS[_ADD_LOG])

    def test_ext_log_text_and_json_fields_match(self):
        """vs-smart-ext-log reports identical fields in text and JSON."""
        self.check_text_and_json_hex_fields_match(_EXT_LOG, _JSON_KEYS[_EXT_LOG])

    def test_add_log_text_and_json_fields_match(self):
        """vs-smart-add-log reports identical fields in text and JSON."""
        self.check_text_and_json_hex_fields_match(_ADD_LOG, _JSON_KEYS[_ADD_LOG])

    def test_ext_log_required_labels_present(self):
        """vs-smart-ext-log reports every label its log page defines."""
        self.check_required_hex_fields_present(_EXT_LOG, _JSON_KEYS[_EXT_LOG],
                                   _REQUIRED_LABELS)

    def test_add_log_required_labels_present(self):
        """vs-smart-add-log reports every label its log page defines."""
        self.check_required_hex_fields_present(_ADD_LOG, _JSON_KEYS[_ADD_LOG],
                                   _REQUIRED_LABELS)

    def test_ext_log_text_header_matches_json_key(self):
        """vs-smart-ext-log's first line names the log page it read."""
        stdout = self.run_supported_cmd(_EXT_LOG).stdout
        key = next(iter(self.run_supported_cmd_json(_EXT_LOG)))

        self.assertEqual(
            stdout.splitlines()[0].strip(), key,
            f"Expected {key!r} as the first line of vs-smart-ext-log output, "
            f"got: {stdout!r}",
        )

    def test_add_log_text_has_no_header(self):
        """vs-smart-add-log output starts with a field line, not a header."""
        stdout = self.run_supported_cmd(_ADD_LOG).stdout
        first = next(line for line in stdout.splitlines() if line.strip())

        self.assertIn(
            " : ", first,
            f"Expected vs-smart-add-log to start with a field line, "
            f"got: {first!r}",
        )

    def test_ext_log_namespace_path_matches_controller(self):
        """vs-smart-ext-log reports the same fields for both device paths."""
        self.check_ns_hex_fields_match_ctrl(_EXT_LOG, _JSON_KEYS[_EXT_LOG])

    def test_add_log_namespace_path_matches_controller(self):
        """vs-smart-add-log reports the same fields for both device paths."""
        self.check_ns_hex_fields_match_ctrl(_ADD_LOG, _JSON_KEYS[_ADD_LOG])
