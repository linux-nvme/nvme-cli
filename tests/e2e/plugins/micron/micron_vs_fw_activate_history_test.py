# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron vs-fw-activate-history command.

The vs-fw-activate-history command reads a vendor specific log page
and reports one entry per firmware activation the drive has recorded.

Output is a fixed-width text table by default, or JSON when a JSON format
flag is supplied.  The structure is nested: a single "vs-fw-activation-history"
object holding an entry count and an array of entry objects.

The log is available only on certain drive models and is empty on a drive
that has never had its firmware activated.

The per-entry decoding, the log validation and the option surface are
covered without hardware in micron_vs_fw_activate_history_mock_test.py.  The
tests here check a real drive's recorded activations, if it has any.

Tests in this module verify:
  * Valid JSON shape: a "vs-fw-activation-history" object with an integer
    "Total Entry Num", which may be zero, and an "Entry" array of that
    length.
  * Entry numbers running sequentially from the first entry.
  * One table row per entry, and agreement between the text rows and the
    JSON entries.
  * Equivalent results for the controller and namespace device paths.

The two tests that compare values entry by entry have nothing to work with
on a drive that reported no entries, and skip in that case.
"""

import re

from .micron_test import TestMicron

_COMMAND = "vs-fw-activate-history"

_ROOT_KEY = "vs-fw-activation-history"
_TOTAL_ENTRY_NUM = "Total Entry Num"
_ENTRY = "Entry"

# The on-disk table has a fixed 20-entry array.
_MAX_ENTRIES = 20

_ENTRY_NUMBER = "Entry Number"
_POWER_ON_HOUR = "Power On Hour"
_POWER_CYCLE_COUNT = "Power cycle count"
_PREVIOUS_FIRMWARE = "Previous firmware"
_NEW_FW_ACTIVATED = "New FW activated"
_SLOT_NUMBER = "Slot number"
_COMMIT_ACTION_TYPE = "Commit Action Type"
_RESULT = "Result"

# A drive can carry a log page whose ID or version this build does not decode,
# which leaves no table to check and is a limitation of the pairing rather than
# a fault.  It is detected by message; the model and missing-log-page cases are
# handled by the shared TestMicron helpers.
_BAD_PAGE_MSG = "Unsupported fw activation history page"

# A table row is the only line that starts with a digit; every other line
# of the table starts with a space, an underscore, or a header word.  The
# firmware revision columns are matched loosely because they carry
# whatever 8 bytes the drive reported, including all spaces.
_ROW_RE = re.compile(
    r"^(?P<number>\d+)\s+"
    r"\|(?P<power_on_hour>\d+:\d+:\d+)\s*"
    r"\|\s*(?P<power_cycle_count>\d+)\s*"
    r"\|(?P<previous_fw>[^|]*)"
    r"\|(?P<new_fw>[^|]*)"
    r"\|\s*(?P<slot>\d+)\s*"
    r"\|\s*(?P<commit_action>\S+)\s*"
    r"\|\s*(?P<result>pass|Fail #\d+)\s*$"
)


class TestMicronVsFwActivateHistory(TestMicron):
    """Test suite for the micron vs-fw-activate-history plugin command."""

    def _run_fw_history(self, device=None, args=""):
        """Run vs-fw-activate-history and return the CompletedProcess result."""
        return self.run_plugin_cmd(_COMMAND, device=device, args=args)

    def _skip_if_log_unusable(self, result):
        """Skip when result shows no history table could be produced.

        Both streams are searched: the message goes to stderr in normal mode
        and is reported as a JSON object on stdout in JSON mode.
        """
        self.skip_if_result_unsupported(_COMMAND, result)
        if _BAD_PAGE_MSG in result.stdout + result.stderr:
            self.skipTest(
                f"micron {_COMMAND} log page is not one this build can "
                f"decode on this drive: {_BAD_PAGE_MSG!r}"
            )

    def _history_text(self, device=None, args=""):
        """Run in normal mode and return the result, or skip if unusable."""
        self.skip_unless_command_supported(_COMMAND)
        result = self._run_fw_history(device=device, args=args)
        self._skip_if_log_unusable(result)
        self.assertEqual(
            result.returncode, 0,
            f"micron {_COMMAND} failed unexpectedly: rc={result.returncode}, "
            f"stderr={result.stderr!r}",
        )
        return result

    def _history_json(self, device=None, args="--output-format=json"):
        """Run in JSON mode and return the parsed top-level dict.

        In JSON mode the failure paths report themselves as JSON on stdout
        rather than as a message on stderr, so availability is established
        from a normal-mode run first.
        """
        self._history_text(device=device)
        result = self.run_plugin_cmd_check(_COMMAND, device=device, args=args)
        return self.parse_json_output(result.stdout, f"micron {_COMMAND} {args}")

    def _history_object(self, device=None, args="--output-format=json"):
        """Return the "vs-fw-activation-history" object from the JSON output."""
        data = self._history_json(device=device, args=args)
        self.assertIn(
            _ROOT_KEY, data,
            f"Expected top-level '{_ROOT_KEY}' key, got: {list(data.keys())}",
        )
        history = data[_ROOT_KEY]
        self.assertIsInstance(
            history, dict,
            f"'{_ROOT_KEY}' value must be a JSON object, got: {history!r}",
        )
        return history

    def _history_entries(self, device=None, args="--output-format=json"):
        """Return the "Entry" array from the JSON output."""
        history = self._history_object(device=device, args=args)
        self.assertIn(
            _ENTRY, history,
            f"Expected '{_ENTRY}' key under '{_ROOT_KEY}', "
            f"got: {list(history.keys())}",
        )
        entries = history[_ENTRY]
        self.assertIsInstance(
            entries, list, f"'{_ENTRY}' value must be a JSON array"
        )
        return entries

    def _entries_or_skip(self, device=None, args="--output-format=json"):
        """Return the "Entry" array, or skip when the drive reported none.

        A drive with no activation history, or one whose entries were all
        dropped as unparseable, leaves nothing to compare entry by entry.
        """
        entries = self._history_entries(device=device, args=args)
        if not entries:
            self.skipTest(
                f"micron {_COMMAND} reported no history entries on this drive"
            )
        return entries

    def _text_rows(self, stdout):
        """Return the parsed table rows from text output.

        Every line starting with a digit must be a well-formed row; a
        mismatch means the fixed-width layout has drifted.
        """
        rows = []
        for line in stdout.splitlines():
            if not line[:1].isdigit():
                continue
            match = _ROW_RE.match(line)
            self.assertIsNotNone(
                match,
                f"Table row does not match the expected column layout: "
                f"{line!r}",
            )
            rows.append(match)
        return rows

    def test_json_total_entry_num_is_int(self):
        """'Total Entry Num' is an integer within the table's capacity.

        A drive that has never had its firmware activated reports zero, which
        is a valid count; the upper bound is the fixed entry array.
        """
        history = self._history_object()

        self.assertIn(
            _TOTAL_ENTRY_NUM, history,
            f"Expected '{_TOTAL_ENTRY_NUM}' key under '{_ROOT_KEY}', "
            f"got: {list(history.keys())}",
        )
        total = history[_TOTAL_ENTRY_NUM]
        self.assertIsInstance(
            total, int,
            f"'{_TOTAL_ENTRY_NUM}' must be a JSON number, got: {total!r}",
        )
        self.assertGreaterEqual(
            total, 0, f"Expected a non-negative entry count, got {total}",
        )
        self.assertLessEqual(
            total, _MAX_ENTRIES,
            f"'{_TOTAL_ENTRY_NUM}' exceeds the {_MAX_ENTRIES}-entry log "
            f"table capacity: {total}",
        )

    def test_json_entry_count_matches_total_entry_num(self):
        """The 'Entry' array holds exactly 'Total Entry Num' entries.

        Entries whose version or length is unrecognised are silently
        dropped from the array, so a shortfall means a malformed entry.
        """
        history = self._history_object()
        total = history[_TOTAL_ENTRY_NUM]
        entries = history[_ENTRY]

        self.assertEqual(
            len(entries), total,
            f"'{_ENTRY}' holds {len(entries)} entries but "
            f"'{_TOTAL_ENTRY_NUM}' is {total}",
        )

    def test_json_entry_numbers_are_sequential(self):
        """'Entry Number' counts the entries from zero, in order."""
        entries = self._entries_or_skip()

        numbers = [entry[_ENTRY_NUMBER] for entry in entries]
        self.assertEqual(
            numbers, list(range(len(entries))),
            f"Expected entry numbers 0..{len(entries) - 1}, got: {numbers}",
        )

    def test_text_row_count_matches_total_entry_num(self):
        """The text table prints one row per reported entry."""
        history = self._history_object()
        total = history[_TOTAL_ENTRY_NUM]

        result = self._history_text()
        rows = self._text_rows(result.stdout)

        self.assertEqual(
            len(rows), total,
            f"Expected {total} table rows, got {len(rows)}: {result.stdout!r}",
        )

    def test_text_rows_match_json_entries(self):
        """Text rows and JSON entries report the same values.

        Both formats are rendered from the same entry buffer, so they must
        agree field by field.
        """
        entries = self._entries_or_skip()
        rows = self._text_rows(self._history_text().stdout)

        self.assertEqual(
            len(rows), len(entries),
            f"Text table has {len(rows)} rows but JSON has "
            f"{len(entries)} entries",
        )

        for row, entry in zip(rows, entries):
            self.assertEqual(
                int(row.group("number")), entry[_ENTRY_NUMBER],
                f"{_ENTRY_NUMBER} differs between text ({row.group('number')!r}) "
                f"and JSON ({entry[_ENTRY_NUMBER]!r})",
            )
            self.assertEqual(
                row.group("power_on_hour"), entry[_POWER_ON_HOUR],
                f"{_POWER_ON_HOUR} differs between text "
                f"({row.group('power_on_hour')!r}) and JSON "
                f"({entry[_POWER_ON_HOUR]!r})",
            )
            # The JSON field narrows the 64-bit counter to 32 bits.
            self.assertEqual(
                int(row.group("power_cycle_count")) & 0xFFFFFFFF,
                entry[_POWER_CYCLE_COUNT],
                f"{_POWER_CYCLE_COUNT} differs between text "
                f"({row.group('power_cycle_count')!r}) and JSON "
                f"({entry[_POWER_CYCLE_COUNT]!r})",
            )
            self.assertEqual(
                row.group("previous_fw").strip(),
                entry[_PREVIOUS_FIRMWARE].strip(),
                f"{_PREVIOUS_FIRMWARE} differs between text "
                f"({row.group('previous_fw')!r}) and JSON "
                f"({entry[_PREVIOUS_FIRMWARE]!r})",
            )
            self.assertEqual(
                row.group("new_fw").strip(), entry[_NEW_FW_ACTIVATED].strip(),
                f"{_NEW_FW_ACTIVATED} differs between text "
                f"({row.group('new_fw')!r}) and JSON "
                f"({entry[_NEW_FW_ACTIVATED]!r})",
            )
            self.assertEqual(
                int(row.group("slot")), entry[_SLOT_NUMBER],
                f"{_SLOT_NUMBER} differs between text ({row.group('slot')!r}) "
                f"and JSON ({entry[_SLOT_NUMBER]!r})",
            )
            self.assertEqual(
                row.group("commit_action"), entry[_COMMIT_ACTION_TYPE],
                f"{_COMMIT_ACTION_TYPE} differs between text "
                f"({row.group('commit_action')!r}) and JSON "
                f"({entry[_COMMIT_ACTION_TYPE]!r})",
            )
            self.assertEqual(
                row.group("result"), entry[_RESULT],
                f"{_RESULT} differs between text ({row.group('result')!r}) "
                f"and JSON ({entry[_RESULT]!r})",
            )

    def test_namespace_device_matches_controller(self):
        """The namespace path reports the same history as the controller path.

        A namespace path resolves to its parent controller, so the log and
        every entry must be identical.
        """
        history_ctrl = self._history_object(device=self.ctrl)
        history_ns = self._history_object(device=self.ns1)

        self.assertEqual(
            history_ctrl, history_ns,
            f"Controller and namespace paths reported different history:\n"
            f"  ctrl ({self.ctrl}): {history_ctrl}\n"
            f"  ns1  ({self.ns1}):  {history_ns}",
        )
