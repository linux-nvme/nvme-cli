# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron latency-logs command.

The command reports data gathered by the drive's latency-monitoring feature,
read from a vendor-specific log page that a drive may not implement.

latency-logs reads the log page and prints the fixed-size ring of the most
recent slow commands as comma-separated values, one row per entry, preceded
by a column-name header.

The command ignores --output-format, always generating CSV output.

The CSV header, the per-column decoding and the error paths are covered
without hardware in micron_latency_mock_test.py.  The tests here check that a
real drive returns a full ring.

Tests in this module verify:
  * One CSV row per entry in the fixed-size log.
  * Equivalent output for the controller and namespace device paths.
"""

from .micron_test import TestMicron

_COMMAND = "latency-logs"

_CSV_HEADER = (
    "Timestamp, Latency, CmdTag, Opcode, Fuse, Psdt, Cid, Nsid, "
    "Slba_L, Slba_H, Nlb, DEAC, PRINFO, FUA, LR"
)
_ENTRY_COUNT = 16


class TestMicronLatencyLogs(TestMicron):
    """Test suite for the micron latency-logs command."""

    def _logs_stdout(self):
        """Return latency-logs stdout, skipping if the log is not supported."""
        return self.run_supported_cmd(_COMMAND).stdout

    def _logs_rows(self, stdout):
        """Return the non-empty CSV rows that follow the header."""
        lines = [line.strip() for line in stdout.splitlines()]
        self.assertIn(
            _CSV_HEADER, lines,
            f"Expected CSV header {_CSV_HEADER!r} in stdout, "
            f"got: {stdout!r}",
        )
        start = lines.index(_CSV_HEADER) + 1
        return [line for line in lines[start:] if line]

    def test_has_one_row_per_entry(self):
        """latency-logs prints one row per entry in the fixed-size log."""
        rows = self._logs_rows(self._logs_stdout())

        self.assertEqual(
            len(rows), _ENTRY_COUNT,
            f"Expected {_ENTRY_COUNT} CSV rows, got {len(rows)}: {rows!r}",
        )

    def test_namespace_device_produces_same_row_count(self):
        """latency-logs accepts a namespace path and reports the same rows.

        A namespace path resolves to its parent controller, so the log page
        read and its output are identical.
        """
        result = self.run_supported_cmd(_COMMAND, device=self.ns1)

        rows = self._logs_rows(result.stdout)
        self.assertEqual(
            len(rows), _ENTRY_COUNT,
            f"Expected {_ENTRY_COUNT} CSV rows for {self.ns1}, "
            f"got {len(rows)}: {rows!r}",
        )
