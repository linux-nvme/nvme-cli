#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron vs-fw-activate-history command, hardware-free.

vs-fw-activate-history reads the 0xC2 firmware activation history log and
prints one row per recorded activation, in a fixed-width table or as JSON.
Before decoding it validates the log's own page ID and version, and clamps a
device-supplied entry count to the fixed table.

Tests in this module verify:
  * Every column of a decoded entry, in text and JSON.
  * The commit action names, the pass and fail results, and the entry count.
  * Rejection of a log with the wrong page ID or an unsupported version, and
    acceptance of both supported versions.
  * The empty log being reported as a result in text mode and as a table with
    no entries in JSON mode, and the entry count being clamped to the table so
    a drive cannot walk the command past it.
  * The model gate, --output-format handling and a non-existent device.

Usage: python3 micron_vs_fw_activate_history_mock_test.py <nvme-binary>
       <mock-lib>
"""

import re
import struct

from micron_mock_test import SC_INVALID_LOG_PAGE, TestMicronMock, main

_COMMAND = "vs-fw-activate-history"

_LID = 0xC2
_LOG_SIZE = 4096

_JSON_KEY = "vs-fw-activation-history"

# struct micron_fw_activation_history_table, packed.
_OFF_LOG_PAGE = 0
_OFF_NUM_ENTRIES = 4
_OFF_ENTRIES = 8
_OFF_VERSION = 4078
_ENTRY_SIZE = 64
_MAX_ENTRIES = 20

# Models the command accepts.
_SUPPORTED_MODEL = 'M51CX'
_UNSUPPORTED_MODEL = 'M51BX'
_UNSUPPORTED_MSG = "Unsupported drive model for vs-fw-activate-history command"
_EMPTY_LOG_MSG = "No entries were found in fw activation history log"

# Commit action names, indexed by the entry's commit action type.
_COMMIT_ACTIONS = ("000b", "001b", "010b", "011b")

# power_on_hour counts milliseconds and is reported as H:M:S.
_MS_1H2M3S = ((1 * 3600) + (2 * 60) + 3) * 1000


def pack_entry(version=1, length=_ENTRY_SIZE, valid=1, power_on_hour=0,
               power_cycle_count=0, previous_fw="", activated_fw="", slot=0,
               commit_action_type=0, result=0):
    """Build one struct fw_activation_history_entry."""
    buf = bytearray(_ENTRY_SIZE)
    buf[0] = version
    buf[1] = length
    struct.pack_into('<H', buf, 4, valid)
    struct.pack_into('<Q', buf, 6, power_on_hour)
    struct.pack_into('<Q', buf, 22, power_cycle_count)
    buf[30:38] = previous_fw.encode().ljust(8, b'\0')[:8]
    buf[38:46] = activated_fw.encode().ljust(8, b'\0')[:8]
    buf[46] = slot
    buf[47] = commit_action_type
    struct.pack_into('<H', buf, 48, result)
    return bytes(buf)


def pack_history_log(entries=(), num_entries=None, log_page=_LID, version=1):
    """Build a 0xC2 firmware activation history log.

    @num_entries defaults to the number of entries supplied, so a test can
    also claim a count that disagrees with them.
    """
    buf = bytearray(_LOG_SIZE)
    buf[_OFF_LOG_PAGE] = log_page
    struct.pack_into('<I', buf, _OFF_NUM_ENTRIES,
                     len(entries) if num_entries is None else num_entries)
    for index, entry in enumerate(entries):
        start = _OFF_ENTRIES + index * _ENTRY_SIZE
        buf[start:start + _ENTRY_SIZE] = entry
    struct.pack_into('<H', buf, _OFF_VERSION, version)
    return bytes(buf)


class TestMicronVsFwActivateHistory(TestMicronMock):
    """vs-fw-activate-history against a mocked activation history log."""

    def setUp(self):
        super().setUp()
        self.select_model(_SUPPORTED_MODEL)

    def set_log(self, log):
        self.server.logs[_LID] = log

    def json_entries(self):
        data = self.run_plugin_cmd_json(_COMMAND)
        self.assertIn(_JSON_KEY, data,
                      f"Expected top-level {_JSON_KEY!r}, got {list(data)}")
        history = data[_JSON_KEY]
        self.assertIn("Entry", history)
        return history

    @staticmethod
    def rows_of(stdout):
        """Return the entry rows of the fixed-width table.

        Header lines are separators or column names, so a data row is one that
        starts with a digit -- the activation counter.
        """
        return [line for line in stdout.splitlines() if re.match(r"^\d", line)]

    def text_rows(self):
        return self.rows_of(self.run_plugin_cmd_check(_COMMAND).stdout)

    # ---------------------------------------------------------------- #
    # Entry decoding                                                   #
    # ---------------------------------------------------------------- #

    def test_entry_fields_are_decoded(self):
        """Each field of an entry reaches its own JSON key."""
        self.set_log(pack_history_log([pack_entry(
            power_on_hour=_MS_1H2M3S, power_cycle_count=56,
            previous_fw="OLDFW1", activated_fw="NEWFW2", slot=3,
            commit_action_type=2, result=0)]))
        entry = self.json_entries()["Entry"][0]

        self.assertEqual(entry["Entry Number"], 0)
        self.assertEqual(entry["Power On Hour"], "1:2:3")
        self.assertEqual(entry["Power cycle count"], 56)
        self.assertEqual(entry["Previous firmware"], "OLDFW1")
        self.assertEqual(entry["New FW activated"], "NEWFW2")
        self.assertEqual(entry["Slot number"], 3)
        self.assertEqual(entry["Commit Action Type"], _COMMIT_ACTIONS[2])
        self.assertEqual(entry["Result"], "pass")

    def test_power_on_hour_is_rendered_as_elapsed_time(self):
        """The field holds milliseconds and is reported as H:M:S."""
        cases = {
            0: "0:0:0",
            1_000: "0:0:1",
            61_000: "0:1:1",
            _MS_1H2M3S: "1:2:3",
            100 * 3_600_000: "100:0:0",
        }
        for milliseconds, expected in cases.items():
            with self.subTest(power_on_hour=milliseconds):
                self.set_log(pack_history_log(
                    [pack_entry(power_on_hour=milliseconds)]))

                self.assertEqual(
                    self.json_entries()["Entry"][0]["Power On Hour"], expected)

    def test_entry_version_and_length_are_validated(self):
        """An entry the plugin cannot parse is skipped, not misread."""
        self.set_log(pack_history_log([
            pack_entry(power_on_hour=1_000),
            pack_entry(version=9, power_on_hour=2_000),
            pack_entry(length=32, power_on_hour=3_000),
        ]))
        entries = self.json_entries()

        self.assertEqual(entries["Total Entry Num"], 3,
                         "the reported total counts what the log claims")
        self.assertEqual([e["Power On Hour"] for e in entries["Entry"]],
                         ["0:0:1"],
                         "an unparseable entry must not be reported")

    def test_every_commit_action_is_named(self):
        """The four defined action types have names; anything else does not."""
        for action, name in enumerate(_COMMIT_ACTIONS):
            with self.subTest(commit_action_type=action):
                self.set_log(pack_history_log(
                    [pack_entry(commit_action_type=action)]))

                self.assertEqual(
                    self.json_entries()["Entry"][0]["Commit Action Type"],
                    name)

    def test_unknown_commit_action_is_marked(self):
        """An action type outside the table is reported as unknown."""
        self.set_log(pack_history_log([pack_entry(commit_action_type=7)]))

        self.assertEqual(
            self.json_entries()["Entry"][0]["Commit Action Type"], "xxxb")

    def test_failing_activation_reports_its_code(self):
        """A non-zero result is a failure, and the code is reported."""
        self.set_log(pack_history_log([pack_entry(result=5)]))

        self.assertEqual(self.json_entries()["Entry"][0]["Result"], "Fail #5")

    def test_successful_activation_reports_pass(self):
        self.set_log(pack_history_log([pack_entry(result=0)]))

        self.assertEqual(self.json_entries()["Entry"][0]["Result"], "pass")

    def test_entry_count_is_reported(self):
        """The reported total matches the number of entries decoded."""
        for count in (1, 2, 5, _MAX_ENTRIES):
            with self.subTest(entries=count):
                self.set_log(pack_history_log(
                    [pack_entry(power_cycle_count=i) for i in range(count)]))
                history = self.json_entries()

                self.assertEqual(history["Total Entry Num"], count)
                self.assertEqual(len(history["Entry"]), count)

    def test_entries_are_decoded_in_log_order(self):
        self.set_log(pack_history_log(
            [pack_entry(power_cycle_count=i * 10) for i in range(1, 6)]))
        counts = [e["Power cycle count"]
                  for e in self.json_entries()["Entry"]]

        self.assertEqual(counts, [10, 20, 30, 40, 50])

    # ---------------------------------------------------------------- #
    # Text table                                                       #
    # ---------------------------------------------------------------- #

    def test_text_table_has_one_row_per_entry(self):
        self.set_log(pack_history_log(
            [pack_entry(power_cycle_count=i) for i in range(3)]))

        self.assertEqual(len(self.text_rows()), 3)

    def test_text_table_reports_the_entry_contents(self):
        """A row carries the same values the JSON entry does."""
        self.set_log(pack_history_log([pack_entry(
            power_on_hour=_MS_1H2M3S, power_cycle_count=77,
            previous_fw="PREVFW", activated_fw="NEXTFW", slot=2,
            commit_action_type=1, result=0)]))
        row = self.text_rows()[0]

        for value in ("1:2:3", "77", "PREVFW", "NEXTFW", "2",
                      _COMMIT_ACTIONS[1], "pass"):
            self.assertIn(value, row, f"{value!r} missing from row {row!r}")

    def test_text_table_prints_the_column_header(self):
        self.set_log(pack_history_log([pack_entry()]))
        result = self.run_plugin_cmd_check(_COMMAND)

        for column in ("Firmware", "Power On", "Previous", "New FW", "Slot",
                       "Commit", "Result"):
            self.assertIn(column, result.stdout)

    # ---------------------------------------------------------------- #
    # Log validation                                                   #
    # ---------------------------------------------------------------- #

    def test_wrong_log_page_id_is_rejected(self):
        """The log identifies itself, and a mismatch is not decoded."""
        self.set_log(pack_history_log([pack_entry()], log_page=0xC3))
        result = self.run_plugin_cmd(_COMMAND)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported fw activation history page", result.stderr)

    def test_both_supported_versions_are_accepted(self):
        for version in (1, 2):
            with self.subTest(version=version):
                self.set_log(pack_history_log([pack_entry()],
                                              version=version))

                self.assertEqual(self.json_entries()["Total Entry Num"], 1)

    def test_unsupported_version_is_rejected(self):
        for version in (0, 3, 0xFFFF):
            with self.subTest(version=version):
                self.set_log(pack_history_log([pack_entry()],
                                              version=version))
                result = self.run_plugin_cmd(_COMMAND)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Unsupported fw activation history page",
                              result.stderr)

    def test_empty_log_is_reported_as_a_result(self):
        """Having no recorded activations is a result, not a failure.

        The note goes to stdout and the command succeeds, so a drive that has
        never had its firmware activated is not mistaken for a broken one.
        """
        self.set_log(pack_history_log([]))
        result = self.run_plugin_cmd(_COMMAND)

        self.assertEqual(
            result.returncode, 0,
            f"An empty log is not a failure: rc={result.returncode}, "
            f"stderr={result.stderr!r}")
        self.assertIn(_EMPTY_LOG_MSG, result.stdout)
        self.assertNotIn(_EMPTY_LOG_MSG, result.stderr)

    def test_empty_log_prints_no_table(self):
        """Text mode reports the empty log instead of an empty table."""
        self.set_log(pack_history_log([]))
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertNotIn("Power On", result.stdout,
                         "the column header belongs to a table with rows")
        self.assertEqual(self.rows_of(result.stdout), [])

    def test_empty_log_json_is_a_zero_entry_table(self):
        """JSON mode describes an empty log as a table with no entries.

        A consumer parses one shape whether or not the drive has any history,
        and nothing reports the empty log as an error.
        """
        args = "--output-format=json"
        self.set_log(pack_history_log([]))
        result = self.run_plugin_cmd(_COMMAND, args=args)

        self.assertEqual(
            result.returncode, 0,
            f"An empty log is not a failure: rc={result.returncode}, "
            f"stderr={result.stderr!r}")
        data = self.parse_json_output(result.stdout,
                                      f"micron {_COMMAND} {args}")
        self.assertNotIn("error", data)
        self.assertIn(_JSON_KEY, data,
                      f"Expected top-level {_JSON_KEY!r}, got {list(data)}")
        history = data[_JSON_KEY]
        self.assertEqual(history.get("Total Entry Num"), 0)
        self.assertEqual(history.get("Entry"), [])

    def test_entry_count_is_clamped_to_the_table(self):
        """A count larger than the table must not walk past its end."""
        self.set_log(pack_history_log(
            [pack_entry(power_cycle_count=i) for i in range(_MAX_ENTRIES)],
            num_entries=1000))
        history = self.json_entries()

        self.assertEqual(history["Total Entry Num"], _MAX_ENTRIES)
        self.assertEqual(len(history["Entry"]), _MAX_ENTRIES)

    def test_missing_log_is_reported(self):
        self.server.logs[_LID] = SC_INVALID_LOG_PAGE
        result = self.run_plugin_cmd(_COMMAND)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid Log Page", result.stderr)

    # ---------------------------------------------------------------- #
    # Gating and options                                               #
    # ---------------------------------------------------------------- #

    def test_model_gate(self):
        """A model without the log is refused before it is read."""
        self.select_model(_UNSUPPORTED_MODEL)
        self.set_log(pack_history_log([pack_entry()]))
        self.server.commands.clear()
        result = self.run_plugin_cmd(_COMMAND)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(_UNSUPPORTED_MSG, result.stderr)
        self.assertEqual(self.server.log_reads(_LID), [])

    def test_supported_models(self):
        """Every model the plugin lists reaches the log."""
        for model in ('M51CX', 'M51BY', 'M51CY', 'M6003', 'M6004'):
            with self.subTest(model=model):
                self.select_model(model)
                self.set_log(pack_history_log([pack_entry()]))

                self.assertEqual(self.json_entries()["Total Entry Num"], 1)

    def test_binary_output_format_rejected(self):
        self.check_output_format_rejected(_COMMAND, "binary")

    def test_invalid_output_format_returns_error(self):
        self.check_output_format_rejected(_COMMAND, "notaformat")

    def test_namespace_path_matches_the_controller_path(self):
        self.set_log(pack_history_log([pack_entry(power_on_hour=99)]))
        ctrl = self.run_plugin_cmd_check(_COMMAND, device=self.ctrl)
        ns = self.run_plugin_cmd_check(_COMMAND, device=self.ns1)

        self.assertEqual(ctrl.stdout, ns.stdout)

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_COMMAND)


if __name__ == '__main__':
    main()
