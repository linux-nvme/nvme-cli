# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron vs-pcie-stats command.

The command retrieves PCIe error statistics and prints them in JSON or text
format.  The full code-path map is:

  1.  parse_and_open fails
        → rc=-1, "Device not found" in stderr

  2.  validate_output_format fails
        → rc<0, "Invalid output format" in stderr

  3.  GetDriveModel returns UNKNOWN_MODEL
        → "Unsupported drive model for vs-pcie-stats command" in stderr,
          err=-ENOTSUP, goto out (returns a non-zero error)

  4.  eModel == M5407: libnvme_exec_admin_passthru succeeds
        → counters=true, goto print_stats with counter values from hardware

  5.  eModel == M5407: libnvme_exec_admin_passthru fails
        → falls through to micron_get_pcie_aer_errors

  6.  micron_get_pcie_aer_errors fails
        → goto out with error

  6a. On Windows, micron_get_pcie_aer_errors always returns -ENOTSUP with
      "register reads not supported on the current platform" in stderr.
      For non-M5407 drives (which don't take the 0xD6 passthru path), this
      means the command exits with an error and print_stats is never reached.
      M5407 drives are unaffected because they reach print_stats via the
      passthru path before micron_get_pcie_aer_errors is called.

  7.  print_stats, is_json=true (default cfg.fmt="json")
        → JSON output with top-level "PCIE Stats" array containing one
          object with all 16 named error fields

  8.  print_stats, is_json=true, --format=json explicit
        → same JSON output as path 7

  9.  print_stats, is_json=true, --output-format=json
        → same JSON output as path 7

  10. print_stats, is_json=false (--format=normal or --output-format=normal),
      counters=true (M5407 passthru succeeded)
        → per-field text with %hu format

  11. print_stats, is_json=false, counters=false, eModel==M5407 or M5410
        → per-field text with bit values (AER registers)

  12. print_stats, is_json=false, counters=false, other models
        → "PCIE Stats:" header line, hex correctable/uncorrectable counts

Testable paths on real hardware:  1, 2, 7, 8, 9, 10-or-11-or-12
  (which of 10/11/12 is exercised depends on the drive model present)

On Windows with a non-M5407 drive: only paths 1 and 2 are reachable;
paths 7-12 are all skipped because micron_get_pcie_aer_errors returns
-ENOTSUP before print_stats can be reached.  The tests detect this at
runtime via _pcie_stats_available() and skip gracefully.

Untestable paths:
  - Path 3 (UNKNOWN_MODEL): live test hardware is always a supported Micron
    drive; there is no way to inject an unknown device ID.
  - Path 6 (micron_get_pcie_aer_errors error on Linux): requires sysfs to
    be unavailable; not injectable in a live hardware test.
  - Distinguishing paths 10 vs 11 on M5407 hardware: which branch the
    0xD6 admin passthru takes (success → counters=true vs failure →
    AER read) depends on firmware; both yield the same named-field text
    output layout so the difference is transparent to the test.
"""

import json

from tests.plugins.micron.micron_test import TestMicron

_WINDOWS_AER_UNSUPPORTED_MSG = "register reads not supported on the current platform"


# ---------------------------------------------------------------------------
# Expected field names (same order as the C arrays)
# ---------------------------------------------------------------------------

CORRECTABLE_FIELDS = [
    "Unsupported Request Error Status (URES)",
    "ECRC Error Status (ECRCES)",
    "Malformed TLP Status (MTS)",
    "Receiver Overflow Status (ROS)",
    "Unexpected Completion Status (UCS)",
    "Completer Abort Status (CAS)",
    "Completion Timeout Status (CTS)",
    "Flow Control Protocol Error Status (FCPES)",
    "Poisoned TLP Status (PTS)",
    "Data Link Protocol Error Status (DLPES)",
]

UNCORRECTABLE_FIELDS = [
    "Advisory Non-Fatal Error Status (ANFES)",
    "Replay Timer Timeout Status (RTS)",
    "REPLAY_NUM Rollover Status (RRS)",
    "Bad DLLP Status (BDS)",
    "Bad TLP Status (BTS)",
    "Receiver Error Status (RES)",
]

ALL_FIELDS = CORRECTABLE_FIELDS + UNCORRECTABLE_FIELDS


class TestMicronVsPcieStats(TestMicron):
    """Test suite for the micron vs-pcie-stats plugin command."""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _run_pcie_stats(self, device=None, args=""):
        """Run vs-pcie-stats and return the CompletedProcess result."""
        return self.run_plugin_cmd("vs-pcie-stats", device=device, args=args)

    def _pcie_stats_available(self):
        """Return True if vs-pcie-stats can reach the print_stats branch.

        On Windows, micron_get_pcie_aer_errors() always returns -ENOTSUP for
        non-M5407 drives, printing "register reads not supported on the current
        platform" and exiting before print_stats is reached.  M5407 drives are
        unaffected because they take the 0xD6 passthru path first.

        On Linux, the AER path always succeeds on supported hardware, so no
        probe is needed.
        """
        if not self.is_windows():
            return True
        result = self._run_pcie_stats()
        return not (
            result.returncode != 0 and _WINDOWS_AER_UNSUPPORTED_MSG in result.stderr
        )

    def _skip_if_pcie_stats_unavailable(self):
        """Skip the calling test if print_stats is unreachable on this platform."""
        if not self._pcie_stats_available():
            self.skipTest(
                "vs-pcie-stats is not supported on this platform "
                f"(stderr: {_WINDOWS_AER_UNSUPPORTED_MSG!r})"
            )

    def _run_pcie_stats_json(self, args=""):
        """Run vs-pcie-stats in JSON mode and return the parsed top-level dict.

        Skips the test if PCIe stats are unavailable on this platform.
        """
        self._skip_if_pcie_stats_unavailable()
        result = self.run_plugin_cmd_check("vs-pcie-stats", args=args)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(
                f"stdout is not valid JSON: {exc}\nstdout={result.stdout!r}"
            )

    def _pcie_stats_object(self, args=""):
        """Return the first stats object from the 'PCIE Stats' JSON array."""
        data = self._run_pcie_stats_json(args=args)
        self.assertIn(
            "PCIE Stats", data,
            f"Expected top-level 'PCIE Stats' key, got: {list(data.keys())}",
        )
        array = data["PCIE Stats"]
        self.assertIsInstance(array, list, "'PCIE Stats' value must be a list")
        self.assertEqual(len(array), 1,
                         f"Expected exactly one stats object, got {len(array)}")
        return array[0]

    # ------------------------------------------------------------------
    # Error paths (paths 1 & 2)
    # ------------------------------------------------------------------

    def test_bad_device_returns_error(self):
        """vs-pcie-stats fails with a message when the device does not exist.

        Exercises the parse_and_open failure branch (path 1).
        """
        result = self._run_pcie_stats(device="/dev/nvme-nonexistent-test-device")

        self.assertNotEqual(
            result.returncode, 0,
            "Expected non-zero exit code for a non-existent device",
        )
        self.assertIn(
            "Device not found", result.stderr,
            f"Expected 'Device not found' in stderr, got: {result.stderr!r}",
        )

    def test_invalid_output_format_returns_error(self):
        """vs-pcie-stats fails with a message for an unrecognised --output-format.

        Exercises the validate_output_format failure branch (path 2).
        """
        result = self._run_pcie_stats(args="--output-format=notaformat")

        self.assertNotEqual(
            result.returncode, 0,
            "Expected non-zero exit code for an invalid --output-format value",
        )
        self.assertIn(
            "Invalid output format", result.stderr,
            f"Expected 'Invalid output format' in stderr, got: {result.stderr!r}",
        )

    # ------------------------------------------------------------------
    # JSON output (paths 7, 8, 9)
    # ------------------------------------------------------------------

    def test_default_output_is_json(self):
        """vs-pcie-stats produces JSON output by default.

        The default cfg.fmt is "json", so is_json starts true and is never
        cleared by the normal/NORMAL check (path 7).
        """
        self._skip_if_pcie_stats_unavailable()
        result = self.run_plugin_cmd_check("vs-pcie-stats")

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(
                f"Default output is not valid JSON: {exc}\n"
                f"stdout={result.stdout!r}"
            )

        self.assertIn(
            "PCIE Stats", data,
            f"Expected 'PCIE Stats' key in default JSON output, "
            f"got keys: {list(data.keys())}",
        )

    def test_explicit_format_json_produces_valid_json(self):
        """vs-pcie-stats produces valid JSON when --format=json is passed.

        Exercises is_json=true via cfg.fmt == "json" (path 8).
        """
        self._skip_if_pcie_stats_unavailable()
        result = self.run_plugin_cmd_check("vs-pcie-stats", args="--format=json")

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(
                f"stdout is not valid JSON (--format=json): {exc}\n"
                f"stdout={result.stdout!r}"
            )

        self.assertIn(
            "PCIE Stats", data,
            f"Expected 'PCIE Stats' key with --format=json, "
            f"got keys: {list(data.keys())}",
        )

    def test_output_format_json_produces_valid_json(self):
        """vs-pcie-stats produces valid JSON when --output-format=json is passed.

        Exercises is_json=true via flags & JSON (path 9).  The flags path is
        independent from the cfg.fmt path; both must result in JSON output.
        """
        self._skip_if_pcie_stats_unavailable()
        result = self.run_plugin_cmd_check(
            "vs-pcie-stats", args="--output-format=json"
        )

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(
                f"stdout is not valid JSON (--output-format=json): {exc}\n"
                f"stdout={result.stdout!r}"
            )

        self.assertIn(
            "PCIE Stats", data,
            f"Expected 'PCIE Stats' key with --output-format=json, "
            f"got keys: {list(data.keys())}",
        )

    def test_json_pcie_stats_is_single_element_array(self):
        """vs-pcie-stats JSON output wraps the stats object in a one-element array.

        The implementation calls json_object_add_value_array(), appends a
        single stats object, then json_print_object().  Verify the shape.
        """
        data = self._run_pcie_stats_json()
        array = data["PCIE Stats"]

        self.assertIsInstance(array, list,
                              "'PCIE Stats' must be a JSON array")
        self.assertEqual(len(array), 1,
                         f"Expected exactly one element in 'PCIE Stats' array, "
                         f"got {len(array)}")

    def test_json_output_contains_all_correctable_error_fields(self):
        """vs-pcie-stats JSON output contains all 10 correctable error fields.

        Each entry in pcie_correctable_errors[] is emitted via
        json_object_add_value_int(stats, field.err, val).  All 10 fields
        must appear as keys in the stats object.
        """
        stats = self._pcie_stats_object()

        for field in CORRECTABLE_FIELDS:
            self.assertIn(
                field, stats,
                f"Expected correctable error field '{field}' in JSON stats, "
                f"got keys: {list(stats.keys())}",
            )

    def test_json_output_contains_all_uncorrectable_error_fields(self):
        """vs-pcie-stats JSON output contains all 6 uncorrectable error fields.

        Each entry in pcie_uncorrectable_errors[] is emitted similarly.
        All 6 fields must appear as keys in the stats object.
        """
        stats = self._pcie_stats_object()

        for field in UNCORRECTABLE_FIELDS:
            self.assertIn(
                field, stats,
                f"Expected uncorrectable error field '{field}' in JSON stats, "
                f"got keys: {list(stats.keys())}",
            )

    def test_json_error_values_are_non_negative_integers(self):
        """vs-pcie-stats JSON error values are non-negative integers.

        Each value is either a __u16 counter (0–65535) from the M5407
        passthru counters path or a single bit (0 or 1) from the AER path.
        Both representations must be non-negative integers.
        """
        stats = self._pcie_stats_object()

        for field in ALL_FIELDS:
            val = stats[field]
            self.assertIsInstance(
                val, int,
                f"Expected integer value for '{field}', got {type(val).__name__}: {val!r}",
            )
            self.assertGreaterEqual(
                val, 0,
                f"Expected non-negative value for '{field}', got {val}",
            )

    def test_json_has_exactly_16_error_fields(self):
        """vs-pcie-stats JSON stats object contains exactly 16 error fields.

        10 correctable + 6 uncorrectable = 16 total.  Extra keys would
        indicate a regression where new fields were added without updating
        the test.
        """
        stats = self._pcie_stats_object()

        extra = set(stats.keys()) - set(ALL_FIELDS)
        self.assertFalse(
            extra,
            f"Unexpected extra keys in JSON stats object: {extra}",
        )

        missing = set(ALL_FIELDS) - set(stats.keys())
        self.assertFalse(
            missing,
            f"Missing keys in JSON stats object: {missing}",
        )

    def test_format_json_and_output_format_json_produce_identical_fields(self):
        """Both JSON flag paths yield the same set of field keys.

        --format=json sets cfg.fmt and goes through the strcmp path.
        --output-format=json sets flags & JSON and goes through the flags path.
        The resulting field sets must be identical.
        """
        stats_fmt = self._pcie_stats_object(args="--format=json")
        stats_ofmt = self._pcie_stats_object(args="--output-format=json")

        self.assertEqual(
            set(stats_fmt.keys()), set(stats_ofmt.keys()),
            f"--format=json and --output-format=json produced different field sets:\n"
            f"  --format=json:        {sorted(stats_fmt.keys())}\n"
            f"  --output-format=json: {sorted(stats_ofmt.keys())}",
        )

    # ------------------------------------------------------------------
    # Text output (paths 10, 11, 12)
    # ------------------------------------------------------------------

    def test_format_normal_flag_succeeds(self):
        """vs-pcie-stats exits 0 and produces non-empty output with --format=normal.

        Sets is_json=false via cfg.fmt == "normal" (shared entry point for
        paths 10, 11, and 12).
        """
        self._skip_if_pcie_stats_unavailable()
        result = self.run_plugin_cmd_check("vs-pcie-stats", args="--format=normal")

        self.assertTrue(
            result.stdout.strip(),
            "Expected non-empty stdout with --format=normal, got empty output",
        )

    def test_output_format_normal_flag_succeeds(self):
        """vs-pcie-stats exits 0 and produces non-empty output with --output-format=normal.

        Sets is_json=false via flags & NORMAL (the global nvme-cli flag path).
        """
        self._skip_if_pcie_stats_unavailable()
        result = self.run_plugin_cmd_check(
            "vs-pcie-stats", args="--output-format=normal"
        )

        self.assertTrue(
            result.stdout.strip(),
            "Expected non-empty stdout with --output-format=normal, got empty output",
        )

    def test_normal_output_is_not_json(self):
        """vs-pcie-stats text output is not valid JSON when --format=normal is used.

        The text branches (paths 10, 11, 12) all produce plain printf() output,
        never a JSON document.  Parsing must fail.
        """
        self._skip_if_pcie_stats_unavailable()
        result = self.run_plugin_cmd_check("vs-pcie-stats", args="--format=normal")

        try:
            json.loads(result.stdout)
            self.fail(
                f"--format=normal output parsed as JSON unexpectedly; "
                f"stdout={result.stdout!r}"
            )
        except (json.JSONDecodeError, ValueError):
            pass  # expected: text output is not JSON

    def test_normal_format_text_content(self):
        """vs-pcie-stats text output contains the expected fields for this hardware.

        The text branch taken depends on the drive model:

          M5407 (passthru counters=true, path 10) or
          M5407/M5410 (AER bit-values, path 11):
            16 named-field lines in "Field : value" format.

          Other models (path 12):
            A "PCIE Stats:" header followed by two hex-value lines for
            correctable and uncorrectable error counts.

        The test detects which branch was taken by looking for "PCIE Stats:"
        (present only in path 12) and asserts the appropriate content.
        """
        self._skip_if_pcie_stats_unavailable()
        result = self.run_plugin_cmd_check("vs-pcie-stats", args="--format=normal")
        stdout = result.stdout

        if "PCIE Stats:" in stdout:
            # Path 12: generic text branch for non-M5407/M5410 models.
            self.assertIn(
                "Device correctable errors detected:", stdout,
                f"Expected correctable error line in 'PCIE Stats:' branch, "
                f"got: {stdout!r}",
            )
            self.assertIn(
                "Device uncorrectable errors detected:", stdout,
                f"Expected uncorrectable error line in 'PCIE Stats:' branch, "
                f"got: {stdout!r}",
            )
            # The hex values must match 0x<digits>.
            import re
            self.assertRegex(
                stdout,
                r"Device correctable errors detected:\s+0x[0-9a-fA-F]+",
                f"Expected hex value after correctable error label, got: {stdout!r}",
            )
            self.assertRegex(
                stdout,
                r"Device uncorrectable errors detected:\s+0x[0-9a-fA-F]+",
                f"Expected hex value after uncorrectable error label, got: {stdout!r}",
            )
        else:
            # Paths 10/11: named-field text branch for M5407/M5410 models.
            for field in ALL_FIELDS:
                self.assertIn(
                    field, stdout,
                    f"Expected named field '{field}' in M5407/M5410 text output, "
                    f"got: {stdout!r}",
                )
            # Each line must match "Field : integer".
            import re
            for field in ALL_FIELDS:
                self.assertRegex(
                    stdout,
                    re.escape(field) + r"\s*:\s*\d+",
                    f"Expected '{field} : <integer>' in text output, got: {stdout!r}",
                )

    def test_output_format_normal_text_content(self):
        """vs-pcie-stats --output-format=normal produces the same content as --format=normal.

        The two flags converge on the same is_json=false branch.  Verify
        that the output structure matches expectations using the same
        branch-detection logic.
        """
        self._skip_if_pcie_stats_unavailable()
        result = self.run_plugin_cmd_check(
            "vs-pcie-stats", args="--output-format=normal"
        )
        stdout = result.stdout

        if "PCIE Stats:" in stdout:
            self.assertIn("Device correctable errors detected:", stdout)
            self.assertIn("Device uncorrectable errors detected:", stdout)
        else:
            for field in ALL_FIELDS:
                self.assertIn(
                    field, stdout,
                    f"Expected named field '{field}' in --output-format=normal output",
                )

    # ------------------------------------------------------------------
    # Cross-format consistency
    # ------------------------------------------------------------------

    def test_json_and_normal_report_same_error_count_parity(self):
        """JSON and text output agree on whether any errors are non-zero.

        The JSON path sums all field values; the text path prints the same
        underlying data.  If JSON shows all zeros, the text output must not
        report any non-zero values (and vice versa), ensuring both paths read
        the same hardware registers.

        This test only applies to the named-field text branch (paths 10/11);
        it is skipped when the drive uses the generic "PCIE Stats:" branch
        because that branch exposes a different level of aggregation.
        """
        stats = self._pcie_stats_object()
        json_any_nonzero = any(stats[f] != 0 for f in ALL_FIELDS)

        result = self.run_plugin_cmd_check("vs-pcie-stats", args="--format=normal")
        stdout = result.stdout

        if "PCIE Stats:" in stdout:
            self.skipTest(
                "Drive uses generic text branch; cross-format parity check skipped"
            )

        import re
        text_values = []
        for field in ALL_FIELDS:
            m = re.search(re.escape(field) + r"\s*:\s*(\d+)", stdout)
            self.assertIsNotNone(m,
                f"Could not parse '{field}' value from text output: {stdout!r}")
            text_values.append(int(m.group(1)))

        text_any_nonzero = any(v != 0 for v in text_values)

        self.assertEqual(
            json_any_nonzero, text_any_nonzero,
            f"JSON and text output disagree on whether errors are present:\n"
            f"  JSON non-zero: {json_any_nonzero}\n"
            f"  Text non-zero: {text_any_nonzero}\n"
            f"  JSON stats: {stats}\n"
            f"  Text stdout: {stdout!r}",
        )

    # ------------------------------------------------------------------
    # Namespace device path
    # ------------------------------------------------------------------

    def test_namespace_device_produces_same_output_as_ctrl(self):
        """vs-pcie-stats produces identical JSON when given a namespace path.

        Both controller and namespace paths must resolve to the same controller
        and therefore produce the same set of PCIe error field keys.
        """
        # Probe availability using the namespace path specifically, since
        # micron_get_pcie_aer_errors is the function under test here.
        if self.is_windows():
            ns_probe = self.run_plugin_cmd("vs-pcie-stats", device=self.ns1)
            if ns_probe.returncode != 0 and _WINDOWS_AER_UNSUPPORTED_MSG in ns_probe.stderr:
                self.skipTest(
                    "vs-pcie-stats is not supported on this platform "
                    f"(stderr: {_WINDOWS_AER_UNSUPPORTED_MSG!r})"
                )

        result_ctrl = self.run_plugin_cmd_check("vs-pcie-stats", device=self.ctrl)
        result_ns = self.run_plugin_cmd_check("vs-pcie-stats", device=self.ns1)

        try:
            data_ctrl = json.loads(result_ctrl.stdout)
            data_ns = json.loads(result_ns.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"Output is not valid JSON: {exc}")

        stats_ctrl = data_ctrl["PCIE Stats"][0]
        stats_ns = data_ns["PCIE Stats"][0]

        self.assertEqual(
            set(stats_ctrl.keys()), set(stats_ns.keys()),
            f"Controller and namespace device paths produced different field sets:\n"
            f"  ctrl ({self.ctrl}): {sorted(stats_ctrl.keys())}\n"
            f"  ns1  ({self.ns1}):  {sorted(stats_ns.keys())}",
        )
