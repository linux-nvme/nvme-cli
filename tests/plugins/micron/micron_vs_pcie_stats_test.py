# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron vs-pcie-stats command.

The vs-pcie-stats command retrieves PCIe error statistics and prints them in
either JSON (the default) or plain-text format.  The statistics are gathered
in a model-dependent way: some drives report per-field error counters, while
others expose the AER error-status bits read from the PCIe registers.  On
Windows, drives that rely on register reads are unsupported, so the command
fails with -ENOTSUP; the tests probe for this at runtime and skip gracefully.

Tests in this module verify:
  * Error detection for a non-existent device and an invalid output format.
  * JSON output: the top-level "PCIE Stats" single-element array and its
    full set of named correctable and uncorrectable error fields.
  * Text output for whichever model-specific branch the drive exercises.
  * Consistency between the JSON and text representations, and between the
    controller and namespace device paths.
"""

import json
import re

from tests.plugins.micron.micron_test import TestMicron

_WINDOWS_AER_UNSUPPORTED_MSG = "register reads not supported on the current platform"

# Expected PCIe error field names, in the order the command emits them.

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

    def _run_pcie_stats(self, device=None, args=""):
        """Run vs-pcie-stats and return the CompletedProcess result."""
        return self.run_plugin_cmd("vs-pcie-stats", device=device, args=args)

    def _pcie_stats_available(self):
        """Return True if vs-pcie-stats can produce statistics on this platform.

        On Windows, drives that rely on PCIe register reads are unsupported and
        the command fails with -ENOTSUP and a "register reads not supported"
        message.  On other platforms the command is always supported, so no
        probe is needed.
        """
        if not self.is_windows():
            return True
        result = self._run_pcie_stats()
        return not (
            result.returncode != 0 and _WINDOWS_AER_UNSUPPORTED_MSG in result.stderr
        )

    def _skip_if_pcie_stats_unavailable(self):
        """Skip the calling test if vs-pcie-stats is unsupported on this platform."""
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
        if "json" not in args:
            # Explicitly specify JSON output. Don't rely on default behavior.
            # Allow the caller to use a different json format flag if desired.
            args += " --output-format=json"
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

    def test_bad_device_returns_error(self):
        """vs-pcie-stats fails with a message when the device does not exist."""
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
        """vs-pcie-stats fails with a message for an unrecognised --output-format."""
        result = self._run_pcie_stats(args="--output-format=notaformat")

        self.assertNotEqual(
            result.returncode, 0,
            "Expected non-zero exit code for an invalid --output-format value",
        )
        self.assertIn(
            "Invalid output format", result.stderr,
            f"Expected 'Invalid output format' in stderr, got: {result.stderr!r}",
        )

    def test_default_output_is_json(self):
        """vs-pcie-stats produces JSON output by default."""
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
        """vs-pcie-stats produces valid JSON when --format=json is passed."""
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
        """vs-pcie-stats produces valid JSON when --output-format=json is passed."""
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
        """vs-pcie-stats JSON output wraps the stats object in a one-element array."""
        data = self._run_pcie_stats_json()
        array = data["PCIE Stats"]

        self.assertIsInstance(array, list,
                              "'PCIE Stats' must be a JSON array")
        self.assertEqual(len(array), 1,
                         f"Expected exactly one element in 'PCIE Stats' array, "
                         f"got {len(array)}")

    def test_json_output_contains_all_correctable_error_fields(self):
        """vs-pcie-stats JSON output contains all 10 correctable error fields."""
        stats = self._pcie_stats_object()

        for field in CORRECTABLE_FIELDS:
            self.assertIn(
                field, stats,
                f"Expected correctable error field '{field}' in JSON stats, "
                f"got keys: {list(stats.keys())}",
            )

    def test_json_output_contains_all_uncorrectable_error_fields(self):
        """vs-pcie-stats JSON output contains all 6 uncorrectable error fields."""
        stats = self._pcie_stats_object()

        for field in UNCORRECTABLE_FIELDS:
            self.assertIn(
                field, stats,
                f"Expected uncorrectable error field '{field}' in JSON stats, "
                f"got keys: {list(stats.keys())}",
            )

    def test_json_error_values_are_non_negative_integers(self):
        """vs-pcie-stats JSON error values are non-negative integers.

        Each value is either a per-field counter or a single AER status bit,
        depending on the drive model; both are non-negative integers.
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

        10 correctable + 6 uncorrectable, with no extra or missing keys.
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
        """--format=json and --output-format=json yield the same set of field keys."""
        stats_fmt = self._pcie_stats_object(args="--format=json")
        stats_ofmt = self._pcie_stats_object(args="--output-format=json")

        self.assertEqual(
            set(stats_fmt.keys()), set(stats_ofmt.keys()),
            f"--format=json and --output-format=json produced different field sets:\n"
            f"  --format=json:        {sorted(stats_fmt.keys())}\n"
            f"  --output-format=json: {sorted(stats_ofmt.keys())}",
        )

    def test_format_normal_flag_succeeds(self):
        """vs-pcie-stats produces non-empty output with --format=normal."""
        self._skip_if_pcie_stats_unavailable()
        result = self.run_plugin_cmd_check("vs-pcie-stats", args="--format=normal")

        self.assertTrue(
            result.stdout.strip(),
            "Expected non-empty stdout with --format=normal, got empty output",
        )

    def test_output_format_normal_flag_succeeds(self):
        """vs-pcie-stats produces non-empty output with --output-format=normal."""
        self._skip_if_pcie_stats_unavailable()
        result = self.run_plugin_cmd_check(
            "vs-pcie-stats", args="--output-format=normal"
        )

        self.assertTrue(
            result.stdout.strip(),
            "Expected non-empty stdout with --output-format=normal, got empty output",
        )

    def test_normal_output_is_not_json(self):
        """vs-pcie-stats text output is not valid JSON for the normal format.

        Checked for both the plugin's --format flag and the global nvme-cli
        --output-format flag.
        """
        self._skip_if_pcie_stats_unavailable()

        for flag in ("--format=normal", "--output-format=normal"):
            with self.subTest(flag=flag):
                result = self.run_plugin_cmd_check("vs-pcie-stats", args=flag)

                try:
                    json.loads(result.stdout)
                    self.fail(
                        f"{flag} output parsed as JSON unexpectedly; "
                        f"stdout={result.stdout!r}"
                    )
                except (json.JSONDecodeError, ValueError):
                    pass  # expected: text output is not JSON

    def test_normal_format_text_content(self):
        """vs-pcie-stats text output contains the expected fields for this hardware.

        The text layout depends on the drive model: some drives print 16
        named-field lines ("Field : value"), while others print a "PCIE Stats:"
        header followed by hex correctable/uncorrectable error counts.  The test
        detects which layout was produced and asserts the matching content, for
        both the plugin's --format flag and the global --output-format flag.
        """
        self._skip_if_pcie_stats_unavailable()

        for flag in ("--format=normal", "--output-format=normal"):
            with self.subTest(flag=flag):
                result = self.run_plugin_cmd_check("vs-pcie-stats", args=flag)
                stdout = result.stdout

                if "PCIE Stats:" in stdout:
                    # Header-plus-hex-counts layout.
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
                    # Named-field layout.
                    for field in ALL_FIELDS:
                        self.assertIn(
                            field, stdout,
                            f"Expected named field '{field}' in text output, "
                            f"got: {stdout!r}",
                        )
                    # Each line must match "Field : integer".
                    for field in ALL_FIELDS:
                        self.assertRegex(
                            stdout,
                            re.escape(field) + r"\s*:\s*\d+",
                            f"Expected '{field} : <integer>' in text output, got: {stdout!r}",
                        )

    def test_json_and_normal_report_same_error_count_parity(self):
        """JSON and text output agree on whether any errors are non-zero.

        Both representations read the same underlying data, so if one reports
        all zeros the other must too.  Applies only to the named-field text
        layout; it is skipped for the generic "PCIE Stats:" layout, which
        exposes a different level of aggregation.
        """
        stats = self._pcie_stats_object()
        json_any_nonzero = any(stats[f] != 0 for f in ALL_FIELDS)

        result = self.run_plugin_cmd_check("vs-pcie-stats", args="--format=normal")
        stdout = result.stdout

        if "PCIE Stats:" in stdout:
            self.skipTest(
                "Drive uses generic text branch; cross-format parity check skipped"
            )

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

    def test_namespace_device_produces_same_output_as_ctrl(self):
        """vs-pcie-stats produces identical JSON when given a namespace path.

        Both controller and namespace paths resolve to the same controller and
        therefore produce the same set of PCIe error field keys.
        """
        # Probe availability using the namespace path specifically.
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
