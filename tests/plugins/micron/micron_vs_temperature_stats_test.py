# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron vs-temperature-stats command.

The vs-temperature-stats command reads the NVMe SMART log page and prints
the current composite temperature along with any active per-sensor
temperatures.  Output is human-readable text by default, or JSON when a
JSON format flag is supplied.

Temperature sensors are reported sparsely: only sensors with a non-zero
reading appear, so gaps between sensor indices are possible.

Tests in this module verify:
  * Text output (default and explicit normal format flags).
  * JSON output for both the --format=json and --output-format=json flags,
    including that temperatures are formatted with a Celsius suffix.
  * One sensor entry per active sensor and none for inactive sensors, in
    both text and JSON output.
  * Error detection for a non-existent device and an invalid output format.
"""

import json

from tests.plugins.micron.micron_test import TestMicron


class TestMicronVsTemperatureStats(TestMicron):
    """Test suite for the micron vs-temperature-stats plugin command."""

    def _run_temp(self, device=None, args=""):
        """Run vs-temperature-stats and return the CompletedProcess result."""
        return self.run_plugin_cmd("vs-temperature-stats", device=device, args=args)

    def _active_sensor_indices(self):
        """Return the 1-based indices of active temperature sensors from nvme smart-log.

        Sensors are reported sparsely, so the returned indices may have gaps.
        """
        result = self.run_cmd(
            f"{self.nvme_bin} smart-log {self.ctrl} --output-format=json"
        )
        self.assertEqual(result.returncode, 0,
                         f"nvme smart-log failed: {result.stderr}")
        data = json.loads(result.stdout)
        return [i for i in range(1, 9) if f"temperature_sensor_{i}" in data]

    def test_bad_device_returns_error(self):
        """vs-temperature-stats fails with a message when the device does not exist."""
        result = self._run_temp(device="/dev/nvme-nonexistent-test-device")

        self.assertNotEqual(
            result.returncode, 0,
            "Expected non-zero exit code for a non-existent device",
        )
        self.assertIn(
            "Device not found", result.stderr,
            f"Expected 'Device not found' in stderr, got: {result.stderr!r}",
        )

    def test_invalid_output_format_returns_error(self):
        """vs-temperature-stats fails with a message for an unrecognised --output-format."""
        result = self._run_temp(args="--output-format=notaformat")

        self.assertNotEqual(
            result.returncode, 0,
            "Expected non-zero exit code for an invalid --output-format value",
        )
        self.assertIn(
            "Invalid output format", result.stderr,
            f"Expected 'Invalid output format' in stderr, got: {result.stderr!r}",
        )

    def test_default_output_is_text(self):
        """vs-temperature-stats produces human-readable text output by default."""
        result = self.run_plugin_cmd_check("vs-temperature-stats")

        self.assertIn(
            "Micron temperature information", result.stdout,
            f"Expected header line in stdout, got: {result.stdout!r}",
        )
        self.assertIn(
            "Current Composite Temperature", result.stdout,
            f"Expected composite temperature label in stdout, got: {result.stdout!r}",
        )

    def test_explicit_normal_format_flag(self):
        """vs-temperature-stats produces text output when --format=normal is passed."""
        result = self.run_plugin_cmd_check("vs-temperature-stats", args="--format=normal")

        self.assertIn(
            "Micron temperature information", result.stdout,
            f"Expected header line in stdout, got: {result.stdout!r}",
        )
        self.assertIn(
            "Current Composite Temperature", result.stdout,
            f"Expected composite temperature label in stdout, got: {result.stdout!r}",
        )

    def test_output_format_normal_flag(self):
        """vs-temperature-stats produces text output when --output-format=normal is passed."""
        result = self.run_plugin_cmd_check(
            "vs-temperature-stats", args="--output-format=normal"
        )

        self.assertIn(
            "Micron temperature information", result.stdout,
            f"Expected header line in stdout, got: {result.stdout!r}",
        )
        self.assertIn(
            "Current Composite Temperature", result.stdout,
            f"Expected composite temperature label in stdout, got: {result.stdout!r}",
        )

    def test_json_format_flag_produces_valid_json(self):
        """vs-temperature-stats produces valid JSON when --format=json is passed."""
        result = self.run_plugin_cmd_check("vs-temperature-stats", args="--format=json")

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(
                f"stdout is not valid JSON (--format=json): {exc}\n"
                f"stdout={result.stdout!r}"
            )

        self.assertIn(
            "Micron temperature information", data,
            f"Expected top-level key 'Micron temperature information' in JSON, "
            f"got keys: {list(data.keys())}",
        )
        log_pages = data["Micron temperature information"]
        self.assertIsInstance(log_pages, list, "Expected 'Micron temperature information' to be a list")
        self.assertGreater(len(log_pages), 0, "Expected at least one stats object in the JSON array")

        stats = log_pages[0]
        self.assertIn(
            "Current Composite Temperature", stats,
            f"Expected 'Current Composite Temperature' in stats object, got keys: {list(stats.keys())}",
        )

    def test_output_format_json_flag_produces_valid_json(self):
        """vs-temperature-stats produces valid JSON when --output-format=json is passed."""
        result = self.run_plugin_cmd_check(
            "vs-temperature-stats", args="--output-format=json"
        )

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(
                f"stdout is not valid JSON (--output-format=json): {exc}\n"
                f"stdout={result.stdout!r}"
            )

        self.assertIn(
            "Micron temperature information", data,
            f"Expected top-level key 'Micron temperature information' in JSON, "
            f"got keys: {list(data.keys())}",
        )
        log_pages = data["Micron temperature information"]
        self.assertIsInstance(log_pages, list)
        self.assertGreater(len(log_pages), 0)

        stats = log_pages[0]
        self.assertIn(
            "Current Composite Temperature", stats,
            f"Expected 'Current Composite Temperature' in stats object, got keys: {list(stats.keys())}",
        )

    def test_json_temperature_value_has_celsius_suffix(self):
        """vs-temperature-stats JSON output formats temperatures as '<N> C'."""
        result = self.run_plugin_cmd_check("vs-temperature-stats", args="--format=json")
        data = json.loads(result.stdout)
        temp_str = data["Micron temperature information"][0]["Current Composite Temperature"]

        self.assertRegex(
            temp_str, r"^\d+ C$",
            f"Expected temperature formatted as '<N> C', got: {temp_str!r}",
        )

    def test_text_temperature_value_has_celsius_suffix(self):
        """vs-temperature-stats text output formats temperatures as '<N> C'."""
        result = self.run_plugin_cmd_check("vs-temperature-stats")

        self.assertRegex(
            result.stdout, r"Current Composite Temperature\s*:\s*\d+ C",
            f"Expected 'Current Composite Temperature : <N> C' in stdout, "
            f"got: {result.stdout!r}",
        )

    def test_json_sensor_entries_match_smart_log_count(self):
        """vs-temperature-stats JSON output contains exactly one entry per active sensor.

        Cross-checks the reported sensors against nvme smart-log: a
        "Temperature Sensor #N" key must appear for each active sensor and for
        no inactive one.
        """
        active = self._active_sensor_indices()

        result = self.run_plugin_cmd_check("vs-temperature-stats", args="--format=json")
        data = json.loads(result.stdout)
        stats = data["Micron temperature information"][0]

        for i in active:
            key = f"Temperature Sensor #{i}"
            self.assertIn(
                key, stats,
                f"Expected '{key}' in vs-temperature-stats JSON output, "
                f"got keys: {list(stats.keys())}",
            )
            self.assertRegex(
                stats[key], r"^\d+ C$",
                f"Expected '{key}' formatted as '<N> C', got: {stats[key]!r}",
            )

        # No inactive sensor should appear.
        for i in range(1, 9):
            if i in active:
                continue
            self.assertNotIn(
                f"Temperature Sensor #{i}", stats,
                f"Unexpected sensor key for inactive sensor #{i} in JSON output: "
                f"{list(stats.keys())}",
            )

    def test_text_sensor_entries_match_smart_log_count(self):
        """vs-temperature-stats text output contains exactly one line per active sensor.

        Cross-checks the reported sensors against nvme smart-log: a
        "Temperature Sensor #N" line must appear for each active sensor and for
        no inactive one.
        """
        active = self._active_sensor_indices()

        result = self.run_plugin_cmd_check("vs-temperature-stats")

        for i in active:
            self.assertRegex(
                result.stdout, rf"Temperature Sensor #{i}\s*:\s*\d+ C",
                f"Expected 'Temperature Sensor #{i} : <N> C' in stdout, "
                f"got: {result.stdout!r}",
            )

        # No inactive sensor should appear.
        for i in range(1, 9):
            if i in active:
                continue
            self.assertNotRegex(
                result.stdout, rf"Temperature Sensor #{i}\s*:",
                f"Unexpected sensor line for inactive sensor #{i} in stdout: "
                f"{result.stdout!r}",
            )
