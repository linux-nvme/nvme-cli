#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron smart-log command, hardware-free.

micron smart-log renders the SMART/Health log itself rather than deferring to
the core command: it echoes the device argument, reports the temperature in
both Kelvin and Celsius, adds the operational lifetime energy consumed and
interval power measurement fields, and spells several core counters
differently.

The command warns about an unrecognised drive but proceeds, so it is not
gated on the model.  Because the log is an input here, the Kelvin/Celsius
pair, the sparse sensor set and the renamed counters are checked against
known values, and the core rendering of the same mocked log is available for
comparison.

Tests in this module verify:
  * The Micron-only fields, and that core does not report them.
  * Renamed counters carrying the value core reports under its own name, and
    identically named ones agreeing.
  * temperature_kelvin against the log, temperature_celsius as the offset
    reading, and the zero case.
  * One sensor field per active sensor and none for an inactive one.
  * The normal-mode header echoing the device argument verbatim, and the JSON
    device field matching it.
  * Error handling for a SMART log failure, a non-existent device and a bad
    --output-format.

Usage: python3 micron_smart_log_mock_test.py <nvme-binary> <mock-lib>
"""

import struct

from micron_mock_test import (
    LID_SMART,
    SC_INVALID_LOG_PAGE,
    SMART_LOG_SIZE,
    TestMicronMock,
    main,
    pack_smart_log,
)

_COMMAND = "smart-log"

_HEADER_PREFIX = "SMART/Health Information Log for "

# Kelvin offset the plugin subtracts from every reading.
_KELVIN_OFFSET = 273

# micron smart-log JSON keys that core "log smart" does not emit.
_EXTRA_KEYS = ("device", "temperature_kelvin", "temperature_celsius", "olec",
               "ipm")

# micron smart-log key -> core "log smart" key naming the same counter.
_RENAMED_KEYS = {
    "ctrl_busy_time": "controller_busy_time",
    "host_reads": "host_read_commands",
    "host_writes": "host_write_commands",
    "endurance_grp_crit_warn": "endurance_grp_critical_warning_summary",
    "olec": "op_lifetime_energy_consumed",
    "ipm": "interval_power_measurement",
}

# Fields both renderings spell identically and must agree on.
_SHARED_KEYS = ("critical_warning", "avail_spare", "spare_thresh",
                "percent_used")

# struct nvme_smart_log field offsets, verified with offsetof().
_OFF_CRITICAL_WARNING = 0
_OFF_AVAIL_SPARE = 3
_OFF_SPARE_THRESH = 4
_OFF_PERCENT_USED = 5
_OFF_OLEC = 232
_OFF_IPM = 240

_UNKNOWN_MODEL_WARNING = "WARNING: Unknown drive model"


def to_decimal(value):
    """Read a JSON number that may be rendered as a decimal string."""
    return int(str(value), 0)


class TestMicronSmartLog(TestMicronMock):
    """micron smart-log against a mocked SMART log."""

    def set_smart(self, **kwargs):
        self.server.smart = pack_smart_log(**kwargs)

    def set_smart_bytes(self, patches):
        """Patch raw bytes into the SMART log, for fields pack_smart_log()
        does not model."""
        buf = bytearray(self.server.smart.ljust(SMART_LOG_SIZE, b'\0'))
        for offset, value in patches.items():
            buf[offset] = value
        self.server.smart = bytes(buf)

    def micron_json(self, device=None):
        return self.run_plugin_cmd_json(
            _COMMAND, device=device, args="-o json")

    def core_json(self, device=None):
        return self.run_core_cmd_json("log smart", device=device)

    def header_line(self, device=None):
        result = self.run_plugin_cmd_check(_COMMAND, device=device)
        headers = [line for line in result.stdout.splitlines()
                   if line.startswith(_HEADER_PREFIX)]
        self.assertEqual(len(headers), 1,
                         f"expected one header line, got: {result.stdout!r}")
        return headers[0]

    # ---------------------------------------------------------------- #
    # Relationship to the core rendering                               #
    # ---------------------------------------------------------------- #

    def test_json_adds_the_micron_fields(self):
        """The Micron rendering adds fields core does not report."""
        micron = self.micron_json()
        core = self.core_json()

        for key in _EXTRA_KEYS:
            with self.subTest(key=key):
                self.assertIn(key, micron)
                self.assertNotIn(
                    key, core,
                    f"core log smart now reports {key!r} too, so it is no "
                    f"longer a Micron addition")

    def test_json_shared_fields_agree_with_core(self):
        """Identically named fields carry identical values."""
        self.set_smart_bytes({_OFF_AVAIL_SPARE: 97, _OFF_SPARE_THRESH: 10,
                              _OFF_PERCENT_USED: 3})
        micron = self.micron_json()
        core = self.core_json()

        for key in _SHARED_KEYS:
            with self.subTest(key=key):
                self.assertIn(key, micron)
                self.assertIn(key, core)
                self.assertEqual(to_decimal(micron[key]),
                                 to_decimal(core[key]))

    def test_json_renamed_fields_agree_with_core(self):
        """A differently spelled counter still carries the core value."""
        micron = self.micron_json()
        core = self.core_json()

        for micron_key, core_key in sorted(_RENAMED_KEYS.items()):
            with self.subTest(key=micron_key):
                self.assertIn(micron_key, micron)
                self.assertIn(core_key, core)
                self.assertEqual(to_decimal(micron[micron_key]),
                                 to_decimal(core[core_key]))

    def test_reported_values_follow_the_log(self):
        """A field reports what the log holds, not a constant."""
        self.set_smart_bytes({_OFF_AVAIL_SPARE: 42, _OFF_PERCENT_USED: 7,
                              _OFF_CRITICAL_WARNING: 0})

        micron = self.micron_json()
        self.assertEqual(to_decimal(micron["avail_spare"]), 42)
        self.assertEqual(to_decimal(micron["percent_used"]), 7)

    def test_micron_power_fields_are_read_from_the_log(self):
        """olec and ipm come out of their own fields in the log."""
        buf = bytearray(pack_smart_log())
        struct.pack_into('<Q', buf, _OFF_OLEC, 0x1122334455667788)
        struct.pack_into('<I', buf, _OFF_IPM, 0xDEADBEEF)
        self.server.smart = bytes(buf)
        micron = self.micron_json()

        self.assertEqual(to_decimal(micron["olec"]), 0x1122334455667788)
        self.assertEqual(to_decimal(micron["ipm"]), 0xDEADBEEF)

    # ---------------------------------------------------------------- #
    # Temperature                                                      #
    # ---------------------------------------------------------------- #

    def test_temperature_is_reported_in_both_units(self):
        """The Kelvin reading and its Celsius conversion are both reported."""
        for celsius in (0, 27, 85):
            with self.subTest(celsius=celsius):
                self.set_smart(temperature_kelvin=_KELVIN_OFFSET + celsius)
                micron = self.micron_json()

                self.assertEqual(to_decimal(micron["temperature_kelvin"]),
                                 _KELVIN_OFFSET + celsius)
                self.assertEqual(to_decimal(micron["temperature_celsius"]),
                                 celsius)

    def test_zero_temperature_reports_zero_celsius(self):
        """A drive reporting nothing must not have the offset applied."""
        self.set_smart(temperature_kelvin=0)
        micron = self.micron_json()

        self.assertEqual(to_decimal(micron["temperature_kelvin"]), 0)
        self.assertEqual(to_decimal(micron["temperature_celsius"]), 0)

    def test_temperature_kelvin_matches_core(self):
        """Core reports the raw reading, which is the Kelvin field here."""
        self.set_smart(temperature_kelvin=_KELVIN_OFFSET + 40)
        micron = self.micron_json()
        core = self.core_json()

        self.assertEqual(to_decimal(micron["temperature_kelvin"]),
                         to_decimal(core["temperature"]))

    # ---------------------------------------------------------------- #
    # Sensors                                                          #
    # ---------------------------------------------------------------- #

    def test_only_active_sensors_are_reported(self):
        """A sensor reading of zero means the sensor is not present."""
        cases = {
            'all eight': {n: _KELVIN_OFFSET + 20 + n for n in range(1, 9)},
            'sparse with gaps': {2: _KELVIN_OFFSET + 30, 6: _KELVIN_OFFSET + 35},
            'none': {},
        }
        for name, sensors in cases.items():
            with self.subTest(sensors=name):
                self.set_smart(sensors=sensors)
                micron = self.micron_json()
                reported = {n for n in range(1, 9)
                            if f"temp_sensor_{n}" in micron}

                self.assertEqual(reported, set(sensors))

    def test_sensor_readings_are_converted_to_celsius(self):
        """Each sensor is reported in Celsius, unlike core's Kelvin."""
        sensors = {1: _KELVIN_OFFSET + 31, 8: _KELVIN_OFFSET + 44}
        self.set_smart(sensors=sensors)
        micron = self.micron_json()
        core = self.core_json()

        for number, kelvin in sensors.items():
            with self.subTest(sensor=number):
                self.assertEqual(to_decimal(micron[f"temp_sensor_{number}"]),
                                 kelvin - _KELVIN_OFFSET)
                self.assertEqual(
                    to_decimal(core[f"temperature_sensor_{number}"]), kelvin)

    def test_sensor_presence_matches_core(self):
        """Both renderings report the same sparse set."""
        self.set_smart(sensors={3: _KELVIN_OFFSET + 30, 5: _KELVIN_OFFSET + 32})
        micron = self.micron_json()
        core = self.core_json()

        for number in range(1, 9):
            with self.subTest(sensor=number):
                self.assertEqual(f"temp_sensor_{number}" in micron,
                                 f"temperature_sensor_{number}" in core)

    # ---------------------------------------------------------------- #
    # Device echoing                                                   #
    # ---------------------------------------------------------------- #

    def test_header_echoes_the_device_argument(self):
        """The header prints the argument verbatim, not a canonical path."""
        for device in (self.ctrl, self.ns1):
            with self.subTest(device=device):
                self.assertEqual(self.header_line(device=device),
                                 _HEADER_PREFIX + device)

    def test_json_device_matches_the_header(self):
        """The JSON device field holds the same string as the header."""
        for device in (self.ctrl, self.ns1):
            with self.subTest(device=device):
                echoed = self.header_line(device=device)[len(_HEADER_PREFIX):]

                self.assertEqual(self.micron_json(device=device)["device"],
                                 echoed)

    def test_namespace_path_reports_the_same_log(self):
        """Only the echoed device differs between the two paths."""
        self.set_smart(temperature_kelvin=_KELVIN_OFFSET + 30,
                       sensors={1: _KELVIN_OFFSET + 31})
        from_ctrl = self.micron_json(device=self.ctrl)
        from_ns = self.micron_json(device=self.ns1)

        self.assertNotEqual(from_ctrl.pop("device"), from_ns.pop("device"))
        self.assertEqual(from_ctrl, from_ns)

    # ---------------------------------------------------------------- #
    # Drive independence and failures                                  #
    # ---------------------------------------------------------------- #

    def test_unrecognised_drive_warns_but_succeeds(self):
        """The command is not gated on the model, only noisy about it."""
        self.select_model(None)
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertIn(_UNKNOWN_MODEL_WARNING, result.stderr)
        self.assertIn(_HEADER_PREFIX, result.stdout)

    def test_recognised_drive_does_not_warn(self):
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertNotIn(_UNKNOWN_MODEL_WARNING, result.stderr)

    def test_smart_log_failure_is_reported(self):
        """A drive that rejects the SMART log fails with a message."""
        self.server.logs[LID_SMART] = SC_INVALID_LOG_PAGE
        result = self.run_plugin_cmd(_COMMAND)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Failed to get SMART log", result.stderr)

    def test_binary_output_format_rejected(self):
        """The command declares normal|json, so binary is refused."""
        result = self.check_output_format_rejected(_COMMAND, "binary")

        self.assertEqual(result.stdout, "",
                         f"unexpected stdout: {result.stdout!r}")

    def test_invalid_output_format_returns_error(self):
        self.check_output_format_rejected(_COMMAND, "notaformat")

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_COMMAND)


if __name__ == '__main__':
    main()
