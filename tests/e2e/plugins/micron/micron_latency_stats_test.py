# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron latency-stats command.

The command reports data gathered by the drive's latency-monitoring feature,
read from a vendor-specific log page.  Not all drives implement the log.

latency-stats prints a histogram of command completion times: a header
naming the command class it covers (All|Read|Write|Trim, selected with -c),
the log's major and minor revision, and one row per latency bucket
with the bucket's range and the number of commands that fell into it.
The bucket ranges are fixed by the plugin, not reported by the drive.

The command ignores --output-format, always generating text output.

The bucket decoding, the fixed bucket ranges and the argument surface are
covered without hardware in micron_latency_mock_test.py.  The tests here
check that a real drive's log produces a usable table.

Tests in this module verify:
  * The header naming for each -c value and for the default.
  * The revision lines.
  * Equivalent output for the controller and namespace device paths.
"""

import re

from .micron_test import TestMicron

_COMMAND = "latency-stats"

# "Micron IO %s Command Latency Statistics" with cmd_str per -c value.
_HEADER = "Micron IO {} Command Latency Statistics"
_COMMAND_CLASSES = (("all", "All"), ("read", "Read"), ("write", "Write"),
                    ("trim", "Trim"))
_DEFAULT_COMMAND_CLASS = "All"

_MAJOR_REVISION = "Major Revision"
_MINOR_REVISION = "Minor Revision"


class TestMicronLatencyStats(TestMicron):
    """Test suite for the micron latency-stats command."""

    def _stats_stdout(self, args=""):
        """Return latency-stats stdout, skipping if the log is not supported."""
        return self.run_supported_cmd(_COMMAND, args=args).stdout

    def test_header_names_selected_command_class(self):
        """latency-stats names the command class selected by -c in its header."""
        for option, name in _COMMAND_CLASSES:
            stdout = self._stats_stdout(args=f"-c {option}")
            expected = _HEADER.format(name)
            self.assertIn(
                expected, stdout,
                f"Expected header {expected!r} for '-c {option}', "
                f"got: {stdout!r}",
            )

    def test_default_command_class_is_all(self):
        """latency-stats reports the All command class when -c is omitted."""
        stdout = self._stats_stdout()
        expected = _HEADER.format(_DEFAULT_COMMAND_CLASS)

        self.assertIn(
            expected, stdout,
            f"Expected header {expected!r} with no -c option, got: {stdout!r}",
        )

    def test_reports_log_revision(self):
        """latency-stats reports the log's major and minor revision numbers."""
        stdout = self._stats_stdout()

        for label in (_MAJOR_REVISION, _MINOR_REVISION):
            self.assertRegex(
                stdout, re.compile(rf"^{label}\s*:\s*-?\d+$", re.MULTILINE),
                f"Expected '{label} : <N>' line, got: {stdout!r}",
            )

    def test_namespace_device_produces_same_header(self):
        """latency-stats accepts a namespace path and reports the same header.

        A namespace path resolves to its parent controller, so the log page
        read and its output are identical.
        """
        result = self.run_supported_cmd(_COMMAND, device=self.ns1)

        expected = _HEADER.format(_DEFAULT_COMMAND_CLASS)
        self.assertIn(
            expected, result.stdout,
            f"Expected header {expected!r} for {self.ns1}, "
            f"got: {result.stdout!r}",
        )
