# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron vs-work-load-log command.

vs-work-load-log reports the drive's workload log.  The command is gated on
the drive model derived from the PCI device ID and prints "Unsupported drive
model for vs-work-load-log command" on any other drive, so the gating
contract is tested alongside the output and the output assertions skip on a
drive that cannot reach them.

The log renders through the shared field-table path: one
"<label> : 0x<hex>" line per field in text mode, or a single top-level key
holding a one-element array of field objects in JSON mode.  The command
declares normal|json and rejects any other format.

The model gate and the option surface are covered without hardware in
micron_vs_smart_logs_mock_test.py.  The tests here decode a real drive's
log.

Tests in this module verify:
  * The text field table and the JSON field object are both well formed.
"""

from .micron_test import TestMicron

_COMMAND = "vs-work-load-log"

# The top-level JSON key the command emits.
_JSON_KEYS = ("Micron Workload Log:0xC5",)


class TestMicronVsWorkLoadLog(TestMicron):
    """Test suite for the micron vs-work-load-log command."""

    def test_text_field_table(self):
        """Text output is a well-formed '<label> : 0x<hex>' field table."""
        self.check_hex_fields_table(_COMMAND)

    def test_json_field_object(self):
        """JSON output reports the workload log as one top-level key."""
        self.check_hex_fields_json(_COMMAND, _JSON_KEYS)
