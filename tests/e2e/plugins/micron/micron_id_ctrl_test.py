# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron id-ctrl command.

The micron id-ctrl command extends the core id-ctrl command, appending the
vendor specific power measurement support (pms) field to the core rendering.

The pms decoding, the option surface and the comparison against core are
covered without hardware in micron_id_ctrl_mock_test.py.  The tests here run
the same comparison against a real controller's identify data.

Tests in this module verify:
  * The JSON output is a superset of core "id ctrl" JSON -- it adds only
    "pms", and every shared key holds an identical value.
  * The added "pms" key is the CTRATT Power Measurement Support bit.
  * Normal output carries the core Identify header plus the appended
    "pms : <N>" line that core never prints.
  * The controller and namespace paths yield identical JSON.
  * --output-format=binary emits exactly 4096 bytes.
"""

import os

from .micron_test import TestMicron
from ....nvme_test import to_decimal

_COMMAND = "id-ctrl"

_IDENTIFY_HEADER = "NVME Identify Controller:"

# Identify Controller data structure size, per the NVMe specification
_BINARY_SIZE = 4096

# micron id-ctrl JSON keys that core "id ctrl" does not emit
_EXTRA_KEYS = {"pms"}


class TestMicronIdCtrl(TestMicron):
    """Test suite for the micron id-ctrl plugin command."""

    def _micron_json(self, device=None):
        """Run micron id-ctrl in JSON mode and return the parsed object."""
        result = self.run_plugin_cmd_check(_COMMAND, device=device, args="-o json")
        return self.parse_json_output(result.stdout, f"micron {_COMMAND} -o json")

    def _core_json(self, device=None):
        """Run the shadowed core "id ctrl" in JSON mode and return the object.

        self.command() falls back to the flat legacy name on older nvme
        binaries.
        """
        device = self.ctrl if device is None else device
        name = self.command("id ctrl")
        result = self.run_cmd(f"{self.nvme_bin} {name} {device} -o json")
        self.assertEqual(
            result.returncode, 0,
            f"Core 'nvme {name}' failed: rc={result.returncode}, "
            f"stderr={result.stderr!r}",
        )
        return self.parse_json_output(result.stdout, f"nvme {name} -o json")

    def test_json_keys_are_superset_of_core(self):
        """micron id-ctrl JSON emits every core 'id ctrl' key and adds pms."""
        micron = self._micron_json()
        core = self._core_json()

        missing = set(core) - set(micron)
        self.assertFalse(
            missing,
            f"micron {_COMMAND} JSON is missing core id ctrl keys: "
            f"{sorted(missing)}",
        )
        self.assertEqual(
            set(micron) - set(core), _EXTRA_KEYS,
            f"Unexpected difference from core id ctrl keys: "
            f"{sorted(set(micron) - set(core))}",
        )

    def test_json_shared_values_match_core(self):
        """Every key shared with core 'id ctrl' holds an identical value.

        Identify Controller data is static, so the two invocations must agree
        byte for byte -- including the space-padded sn/mn/fr strings.
        """
        micron = self._micron_json()
        core = self._core_json()

        differing = {
            key: (core[key], micron[key])
            for key in set(micron) & set(core)
            if core[key] != micron[key]
        }
        self.assertFalse(
            differing,
            f"micron {_COMMAND} disagrees with core id ctrl on "
            f"{{key: (core, micron)}}: {differing!r}",
        )

    def test_json_pms_is_ctratt_bit(self):
        """The added 'pms' key is the boolean CTRATT Power Measurement Support bit."""
        micron = self._micron_json()
        pms = self.json_get(micron, "pms", context=f"micron {_COMMAND} JSON",
                            required=True)
        ctratt = to_decimal(
            self.json_get(micron, "ctratt", context=f"micron {_COMMAND} JSON",
                          required=True)
        )

        self.assertIn(
            pms, (0, 1), f"Expected 'pms' to be 0 or 1, got: {pms!r}",
        )
        self.assertEqual(
            pms, (ctratt >> 21) & 1,
            f"'pms' ({pms!r}) does not match CTRATT bit 21 of {ctratt:#x}",
        )

    def test_normal_output_adds_pms_line(self):
        """Normal output has the core header plus a 'pms' line."""

        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertIn(
            _IDENTIFY_HEADER, result.stdout,
            f"Expected {_IDENTIFY_HEADER!r} in micron {_COMMAND} output, "
            f"got: {result.stdout!r}",
        )
        self.assertRegex(
            result.stdout, r"(?m)^pms\s+:\s+\d+$",
            f"Expected a 'pms : <N>' line in micron {_COMMAND} output, "
            f"got: {result.stdout!r}",
        )

        core = self.run_cmd(
            f"{self.nvme_bin} {self.command('id ctrl')} {self.ctrl}"
        )
        self.assertEqual(core.returncode, 0,
                         f"Core id ctrl failed: {core.stderr!r}")
        self.assertNotRegex(
            core.stdout, r"(?m)^pms\s+:",
            f"Core id ctrl unexpectedly prints a 'pms' line, so it no longer "
            f"distinguishes the micron rendering: {core.stdout!r}",
        )

    def test_namespace_path_matches_controller(self):
        """A namespace path resolves to its controller and yields identical JSON."""
        from_ctrl = self._micron_json(device=self.ctrl)
        from_ns = self._micron_json(device=self.ns1)

        self.assertEqual(
            from_ctrl, from_ns,
            f"micron {_COMMAND} differs between the controller ({self.ctrl}) "
            f"and namespace ({self.ns1}) paths",
        )

    def test_binary_output_is_accepted(self):
        """--output-format=binary dumps the raw Identify Controller structure.

        micron id-ctrl is declared with plain NVME_ARGS, so unlike the other
        micron commands it honours binary output.  Binary stdout is
        redirected to a file so the byte count is not perturbed by text
        decoding.
        """
        path = os.path.join(self.test_log_dir, "micron_id_ctrl.bin")
        result = self.run_plugin_cmd_check(_COMMAND, args=f'-o binary > "{path}"')

        self.assertEqual(
            os.path.getsize(path), _BINARY_SIZE,
            f"Expected {_BINARY_SIZE} bytes of binary Identify Controller "
            f"data, got {os.path.getsize(path)}; stderr={result.stderr!r}",
        )
