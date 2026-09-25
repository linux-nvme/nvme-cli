# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron smart-log command.

The micron smart-log command reads the SMART/Health log page and
prints its own rendering of it, adding the operational lifetime energy
consumed (olec) and interval power measurement (ipm) fields.  It is
declared NVME_ARGS_OUTPUT_FORMATS(JSON | NORMAL), so binary is rejected.

The added fields, the temperature conversion and the option surface are
covered without hardware in micron_smart_log_mock_test.py.  The tests here
run the comparison against core using a real drive's log.

Tests in this module verify:
  * The JSON output adds device/temperature_kelvin/temperature_celsius/
    olec/ipm, spells several core counters differently, and agrees
    numerically with core "log smart" everywhere the two overlap.
  * The normal-mode "SMART/Health Information Log for <device>" header
    echoes the device argument, for both the controller and namespace
    paths, and matches the JSON "device" field.
"""

from .micron_test import TestMicron
from ....nvme_test import to_decimal

_COMMAND = "smart-log"

_HEADER_PREFIX = "SMART/Health Information Log for "

# micron smart-log JSON keys that core "log smart" does not emit.
_EXTRA_KEYS = (
    "device",
    "temperature_kelvin",
    "temperature_celsius",
    "olec",
    "ipm",
)

# micron smart-log key -> core "log smart" key naming the same counter.
# The micron rendering is independent of the core one, so several fields
# are spelled differently while carrying an identical value.
_RENAMED_KEYS = {
    "ctrl_busy_time": "controller_busy_time",
    "host_reads": "host_read_commands",
    "host_writes": "host_write_commands",
    "endurance_grp_crit_warn": "endurance_grp_critical_warning_summary",
    "olec": "op_lifetime_energy_consumed",
    "ipm": "interval_power_measurement",
}

# Fields both renderings spell identically and must agree on.
_SHARED_KEYS = (
    "critical_warning",
    "avail_spare",
    "spare_thresh",
    "percent_used",
)

_KELVIN_OFFSET = 273


class TestMicronSmartLog(TestMicron):
    """Test suite for the micron smart-log plugin command."""

    def _micron_json(self, device=None):
        """Run micron smart-log in JSON mode and return the parsed object."""
        result = self.run_plugin_cmd_check(_COMMAND, device=device, args="-o json")
        return self.parse_json_output(result.stdout, f"micron {_COMMAND} -o json")

    def _core_json(self, device=None):
        """Run the shadowed core "log smart" in JSON mode and return the object.

        self.command() falls back to the flat legacy name on older nvme
        binaries.
        """
        device = self.ctrl if device is None else device
        name = self.command("log smart")
        result = self.run_cmd(f"{self.nvme_bin} {name} {device} -o json")
        self.assertEqual(
            result.returncode, 0,
            f"Core 'nvme {name}' failed: rc={result.returncode}, "
            f"stderr={result.stderr!r}",
        )
        return self.parse_json_output(result.stdout, f"nvme {name} -o json")

    def _header_line(self, device=None):
        """Return the normal-mode SMART header line for device."""
        result = self.run_plugin_cmd_check(_COMMAND, device=device)
        headers = [
            line for line in result.stdout.splitlines()
            if line.startswith(_HEADER_PREFIX)
        ]
        self.assertEqual(
            len(headers), 1,
            f"Expected exactly one {_HEADER_PREFIX!r} line, "
            f"got: {result.stdout!r}",
        )
        return headers[0]

    def test_json_adds_micron_fields(self):
        """The JSON output adds the device and Micron power fields.

        This rendering is not a superset of the core smart-log command: it
        renames several counters (see _RENAMED_KEYS) and drops core's
        informative_warning and voltage_log_threshold_warning.
        """
        micron = self._micron_json()
        core = self._core_json()

        for key in _EXTRA_KEYS:
            self.assertIn(
                key, micron,
                f"Expected {key!r} in micron {_COMMAND} JSON, "
                f"got keys: {sorted(micron)}",
            )
            self.assertNotIn(
                key, core,
                f"Core log smart now emits {key!r} too, so it is no longer "
                f"a Micron addition; core keys: {sorted(core)}",
            )

    def test_json_shared_fields_agree_with_core(self):
        """Identically named SMART fields agree numerically with core.

        micron renders the 128-bit counters as JSON strings where core
        renders numbers, so the comparison is on decimal values rather than
        on the raw JSON.
        """
        micron = self._micron_json()
        core = self._core_json()

        shared = (set(micron) & set(core)) - {"device"}
        self.assertTrue(
            shared.issuperset(_SHARED_KEYS),
            f"Expected {list(_SHARED_KEYS)} to be shared with core "
            f"log smart, got: {sorted(shared)}",
        )
        for key in sorted(shared):
            self.assertEqual(
                to_decimal(micron[key]), to_decimal(core[key]),
                f"SMART field {key!r} differs: core={core[key]!r}, "
                f"micron={micron[key]!r}",
            )

    def test_json_renamed_fields_agree_with_core(self):
        """Differently named SMART counters still carry the core value."""
        micron = self._micron_json()
        core = self._core_json()

        for micron_key, core_key in sorted(_RENAMED_KEYS.items()):
            self.assertIn(
                micron_key, micron,
                f"Expected {micron_key!r} in micron {_COMMAND} JSON, "
                f"got keys: {sorted(micron)}",
            )
            self.assertIn(
                core_key, core,
                f"Expected {core_key!r} in core log smart JSON, "
                f"got keys: {sorted(core)}",
            )
            self.assertEqual(
                to_decimal(micron[micron_key]), to_decimal(core[core_key]),
                f"micron {micron_key!r} ({micron[micron_key]!r}) does not "
                f"match core {core_key!r} ({core[core_key]!r})",
            )

    def test_json_temperature_matches_core(self):
        """temperature_kelvin equals core 'temperature'; celsius is the offset."""
        micron = self._micron_json()
        core = self._core_json()

        kelvin = to_decimal(
            self.json_get(micron, "temperature_kelvin",
                          context=f"micron {_COMMAND} JSON", required=True)
        )
        celsius = to_decimal(
            self.json_get(micron, "temperature_celsius",
                          context=f"micron {_COMMAND} JSON", required=True)
        )
        core_temp = to_decimal(
            self.json_get(core, "temperature", context="core log smart JSON",
                          required=True)
        )

        self.assertEqual(
            kelvin, core_temp,
            f"temperature_kelvin ({kelvin}) does not match core temperature "
            f"({core_temp})",
        )
        self.assertEqual(
            celsius, kelvin - _KELVIN_OFFSET if kelvin else 0,
            f"temperature_celsius ({celsius}) is not "
            f"temperature_kelvin ({kelvin}) - {_KELVIN_OFFSET}",
        )

    def test_json_temp_sensors_match_core(self):
        """Each temp_sensor_N is core's temperature_sensor_N in Celsius.

        Sensors are reported sparsely: only sensors with a non-zero reading
        appear, in both renderings.
        """
        micron = self._micron_json()
        core = self._core_json()

        for i in range(1, 9):
            micron_key = f"temp_sensor_{i}"
            core_key = f"temperature_sensor_{i}"
            self.assertEqual(
                micron_key in micron, core_key in core,
                f"Sensor #{i} presence differs: micron has "
                f"{micron_key!r}={micron_key in micron}, core has "
                f"{core_key!r}={core_key in core}",
            )
            if micron_key not in micron:
                continue
            self.assertEqual(
                to_decimal(micron[micron_key]),
                to_decimal(core[core_key]) - _KELVIN_OFFSET,
                f"{micron_key} ({micron[micron_key]!r}) is not "
                f"{core_key} ({core[core_key]!r}) - {_KELVIN_OFFSET}",
            )

    def test_normal_header_echoes_device(self):
        """The SMART header echoes the device argument exactly as it was typed.

        The header prints argv[optind] verbatim rather than a canonicalised
        path, so the controller and namespace forms are distinguishable.
        """
        for device in (self.ctrl, self.ns1):
            header = self._header_line(device=device)

            self.assertEqual(
                header, _HEADER_PREFIX + device,
                f"Expected the SMART header to echo {device!r} verbatim, "
                f"got: {header!r}",
            )

    def test_json_device_matches_normal_header(self):
        """The JSON 'device' field holds the same string as the normal header."""
        for device in (self.ctrl, self.ns1):
            header = self._header_line(device=device)
            echoed = header[len(_HEADER_PREFIX):]

            data = self._micron_json(device=device)
            reported = self.json_get(
                data, "device", context=f"micron {_COMMAND} JSON",
                required=True,
            )

            self.assertEqual(
                reported, echoed,
                f"JSON 'device' ({reported!r}) differs from the device in "
                f"the normal-mode header ({echoed!r})",
            )
