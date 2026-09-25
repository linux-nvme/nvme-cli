#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron vs-temperature-stats command, hardware-free.

vs-temperature-stats reads the SMART log and reports the composite
temperature plus one entry per active sensor, converting each Kelvin reading
to Celsius.  A sensor reading of zero means the sensor is absent, so the
reported set is sparse and can have gaps.

Tests in this module verify:
  * The text header and the composite temperature line, and the JSON shape.
  * Kelvin to Celsius conversion, and that a zero reading reports 0 rather
    than a converted value.
  * One entry per active sensor and none for an inactive one, for a dense
    set, a sparse set, only the first sensor, only the last, and none at all.
  * Text and JSON agree on the reported sensors and values.
  * The namespace path reports what the controller path does.
  * Error handling for a SMART log the drive rejects, a non-existent device
    and a bad --output-format.

Usage: python3 micron_temperature_stats_mock_test.py <nvme-binary> <mock-lib>
"""

import json
import re

from micron_mock_test import (
    LID_SMART,
    SC_INVALID_LOG_PAGE,
    TestMicronMock,
    main,
    pack_smart_log,
)

_COMMAND = "vs-temperature-stats"

_JSON_KEY = "Micron temperature information"
_TEXT_HEADER = "Micron temperature information:"
_COMPOSITE = "Current Composite Temperature"

# Kelvin offset the plugin subtracts from every reading.
_KELVIN_OFFSET = 273

SENSOR_COUNT = 8


class TestMicronTemperatureStats(TestMicronMock):
    """vs-temperature-stats against a mocked SMART log."""

    def set_temperatures(self, composite_kelvin=0, sensors=()):
        self.server.smart = pack_smart_log(temperature_kelvin=composite_kelvin,
                                           sensors=sensors)

    def text_values(self, stdout):
        """Return {label: celsius} parsed from the text output."""
        values = {}
        for line in stdout.splitlines():
            m = re.match(r"^(.*?)\s*:\s*(\d+) C$", line)
            if m:
                values[m.group(1).strip()] = int(m.group(2))
        return values

    def json_values(self, device=None):
        """Return {label: celsius} parsed from the JSON output."""
        data = self.run_plugin_cmd_json(_COMMAND, device=device)
        self.assertIn(_JSON_KEY, data,
                      f"Expected top-level {_JSON_KEY!r}, got {list(data)}")
        array = data[_JSON_KEY]
        self.assertIsInstance(array, list)
        self.assertEqual(len(array), 1,
                         f"Expected one stats object, got {len(array)}")
        values = {}
        for label, value in array[0].items():
            m = re.fullmatch(r"(\d+) C", value)
            self.assertIsNotNone(
                m, f"{label!r} is not formatted as '<N> C': {value!r}")
            values[label] = int(m.group(1))
        return values

    @staticmethod
    def sensor_label(number):
        return f"Temperature Sensor #{number}"

    # ---------------------------------------------------------------- #
    # Output shape                                                     #
    # ---------------------------------------------------------------- #

    def test_text_output_has_the_header_and_composite_temperature(self):
        """Text output leads with the header, then the composite reading."""
        self.set_temperatures(composite_kelvin=_KELVIN_OFFSET + 42)
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertIn(_TEXT_HEADER, result.stdout)
        self.assertEqual(self.text_values(result.stdout)[_COMPOSITE], 42)

    def test_json_output_has_the_composite_temperature(self):
        """JSON output wraps one stats object in the named array."""
        self.set_temperatures(composite_kelvin=_KELVIN_OFFSET + 42)

        self.assertEqual(self.json_values()[_COMPOSITE], 42)

    def test_default_output_is_text(self):
        """With no format flag the output is text, not JSON."""
        self.set_temperatures(composite_kelvin=_KELVIN_OFFSET + 30)
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertIn(_TEXT_HEADER, result.stdout)
        with self.assertRaises(ValueError,
                               msg="default output must not be JSON"):
            json.loads(result.stdout)

    def test_explicit_normal_format_matches_the_default(self):
        """--output-format=normal is the default format, spelled out."""
        self.set_temperatures(composite_kelvin=_KELVIN_OFFSET + 30)
        default = self.run_plugin_cmd_check(_COMMAND)
        normal = self.run_plugin_cmd_check(_COMMAND,
                                           args="--output-format=normal")

        self.assertEqual(default.stdout, normal.stdout)

    # ---------------------------------------------------------------- #
    # Kelvin to Celsius                                                #
    # ---------------------------------------------------------------- #

    def test_composite_temperature_is_converted_from_kelvin(self):
        """The reported value is the raw reading less the Kelvin offset."""
        for celsius in (0, 1, 27, 85, 125):
            with self.subTest(celsius=celsius):
                self.set_temperatures(composite_kelvin=_KELVIN_OFFSET + celsius)
                result = self.run_plugin_cmd_check(_COMMAND)

                self.assertEqual(
                    self.text_values(result.stdout)[_COMPOSITE], celsius)
                self.assertEqual(self.json_values()[_COMPOSITE], celsius)

    def test_zero_composite_reading_reports_zero(self):
        """A drive reporting nothing must not have the offset applied.

        Subtracting the offset from zero would report a nonsensical value, so
        zero is passed through as-is.
        """
        self.set_temperatures(composite_kelvin=0)
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertEqual(self.text_values(result.stdout)[_COMPOSITE], 0)
        self.assertEqual(self.json_values()[_COMPOSITE], 0)

    def test_sensor_readings_are_converted_from_kelvin(self):
        """Each sensor reading is converted the same way as the composite."""
        sensors = {1: _KELVIN_OFFSET + 30, 4: _KELVIN_OFFSET + 45, 8: _KELVIN_OFFSET + 60}
        self.set_temperatures(composite_kelvin=_KELVIN_OFFSET + 40, sensors=sensors)
        text = self.text_values(self.run_plugin_cmd_check(_COMMAND).stdout)

        for number, kelvin in sensors.items():
            self.assertEqual(text[self.sensor_label(number)],
                             kelvin - _KELVIN_OFFSET)

    # ---------------------------------------------------------------- #
    # Which sensors are reported                                       #
    # ---------------------------------------------------------------- #

    def test_only_active_sensors_are_reported(self):
        """A sensor reading of zero means the sensor is not present."""
        cases = {
            'all eight': {n: _KELVIN_OFFSET + 20 + n for n in range(1, 9)},
            'sparse with gaps': {2: _KELVIN_OFFSET + 21, 5: _KELVIN_OFFSET + 22,
                                 7: _KELVIN_OFFSET + 23},
            'first only': {1: _KELVIN_OFFSET + 25},
            'last only': {8: _KELVIN_OFFSET + 25},
            'none': {},
        }
        for name, sensors in cases.items():
            with self.subTest(sensors=name):
                self.set_temperatures(composite_kelvin=_KELVIN_OFFSET + 40,
                                      sensors=sensors)
                text = self.text_values(
                    self.run_plugin_cmd_check(_COMMAND).stdout)
                reported = {n for n in range(1, SENSOR_COUNT + 1)
                            if self.sensor_label(n) in text}

                self.assertEqual(
                    reported, set(sensors),
                    f"reported sensors {sorted(reported)} do not match the "
                    f"active ones {sorted(sensors)}",
                )

    def test_no_sensor_lines_when_none_are_active(self):
        """A drive with no sensors reports only the composite temperature."""
        self.set_temperatures(composite_kelvin=_KELVIN_OFFSET + 40)
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertNotIn("Temperature Sensor", result.stdout)
        self.assertEqual(list(self.json_values()), [_COMPOSITE])

    def test_sensor_numbering_is_one_based(self):
        """The first sensor slot is reported as sensor 1, not 0."""
        self.set_temperatures(sensors={1: _KELVIN_OFFSET + 25})
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertIn("Temperature Sensor #1 :", result.stdout)
        self.assertNotIn("Temperature Sensor #0", result.stdout)

    def test_text_and_json_report_the_same_values(self):
        """Both formats read the same log, so they must agree exactly."""
        self.set_temperatures(composite_kelvin=_KELVIN_OFFSET + 33,
                              sensors={1: _KELVIN_OFFSET + 30, 3: _KELVIN_OFFSET + 35,
                                       8: _KELVIN_OFFSET + 40})
        text = self.text_values(self.run_plugin_cmd_check(_COMMAND).stdout)

        self.assertEqual(text, self.json_values())

    def test_namespace_path_matches_the_controller_path(self):
        """A namespace path resolves to its parent controller."""
        self.set_temperatures(composite_kelvin=_KELVIN_OFFSET + 33,
                              sensors={2: _KELVIN_OFFSET + 31})

        self.assertEqual(self.json_values(device=self.ctrl),
                         self.json_values(device=self.ns1))

    # ---------------------------------------------------------------- #
    # Failure and option handling                                      #
    # ---------------------------------------------------------------- #

    def test_smart_log_failure_exits_non_zero(self):
        """A drive that rejects the SMART log produces no reading."""
        self.server.logs[LID_SMART] = SC_INVALID_LOG_PAGE
        result = self.run_plugin_cmd(_COMMAND)

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(_COMPOSITE, result.stdout)

    def test_unknown_drive_model_is_not_consulted(self):
        """The command reads no model, so an unrecognised drive still works."""
        self.select_model(None)
        self.set_temperatures(composite_kelvin=_KELVIN_OFFSET + 40)
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertEqual(self.text_values(result.stdout)[_COMPOSITE], 40)

    def test_binary_output_format_rejected(self):
        """The command declares normal|json, so binary is refused."""
        self.check_output_format_rejected(_COMMAND, "binary")

    def test_invalid_output_format_returns_error(self):
        """An unrecognised --output-format is refused."""
        self.check_output_format_rejected(_COMMAND, "notaformat")

    def test_bad_device_returns_error(self):
        """A non-existent device fails with the device path in the message."""
        self.check_bad_device_name(_COMMAND)


if __name__ == '__main__':
    main()
