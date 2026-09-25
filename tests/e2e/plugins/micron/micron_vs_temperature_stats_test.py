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

The output formats, the Kelvin conversion, and the sensor sparsity are
covered without hardware in micron_temperature_stats_mock_test.py.  The tests
here cross-check a real drive's readings against its own SMART log.

Tests in this module verify:
  * One sensor entry per active sensor and none for inactive sensors, in
    both text and JSON output.
"""

from .micron_test import TestMicron

_COMMAND = "vs-temperature-stats"


class TestMicronVsTemperatureStats(TestMicron):
    """Test suite for the micron vs-temperature-stats plugin command."""

    def _active_sensor_indices(self):
        """Return the 1-based indices of active temperature sensors from nvme log smart.

        Sensors are reported sparsely, so the returned indices may have gaps.
        """
        result = self.run_cmd(
            f"{self.nvme_bin} log smart {self.ctrl} --output-format=json"
        )
        self.assertEqual(result.returncode, 0,
                         f"nvme log smart failed: {result.stderr}")
        data = self.parse_json_output(result.stdout, "nvme log smart")
        return [i for i in range(1, 9) if f"temperature_sensor_{i}" in data]

    def test_json_sensor_entries_match_smart_log_count(self):
        """vs-temperature-stats JSON output contains exactly one entry per active sensor.

        Cross-checks the reported sensors against nvme smart-log: a
        "Temperature Sensor #N" key must appear for each active sensor and for
        no inactive one.
        """
        active = self._active_sensor_indices()

        data = self.run_supported_cmd_json(_COMMAND)
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

        result = self.run_plugin_cmd_check(_COMMAND)

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
