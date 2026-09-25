#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron id-ctrl command, hardware-free.

micron id-ctrl extends the core id-ctrl rendering with one vendor field: pms,
the Power Measurement Support bit of CTRATT.  It is declared with plain
NVME_ARGS, so unlike most micron commands it also honours binary output.

The command warns about an unrecognised drive but proceeds, so it is not
gated on the model.  With the identify buffer as an input, pms can be checked
against a CTRATT value chosen for the purpose -- on hardware it is whatever
the drive reports, which is usually zero.

Tests in this module verify:
  * The JSON output is the core one plus pms, with every shared key equal.
  * pms tracks CTRATT bit 21 for a bit set, a bit clear, and neighbouring
    bits set, and that core does not report pms itself.
  * Normal output carries the core header plus the appended pms line.
  * Identify strings are reported as core reports them.
  * Binary output is exactly the 4096-byte structure the drive returned.
  * The unrecognised-model warning is emitted without failing the command.
  * Error handling for an identify failure, a non-existent device and a bad
    --output-format.

Usage: python3 micron_id_ctrl_mock_test.py <nvme-binary> <mock-lib>
"""

from micron_mock_test import (
    ID_CTRL_SIZE,
    SC_INVALID_FIELD,
    TestMicronMock,
    main,
    pack_id_ctrl,
)

_COMMAND = "id-ctrl"

_IDENTIFY_HEADER = "NVME Identify Controller:"

# micron id-ctrl JSON keys that core "id ctrl" does not emit.
_EXTRA_KEYS = {"pms"}

_CTRATT_PMS_BIT = 21

_UNKNOWN_MODEL_WARNING = "WARNING: Drive not recognized as Micron"


class TestMicronIdCtrl(TestMicronMock):
    """micron id-ctrl against a mocked identify buffer."""

    def micron_json(self, device=None):
        return self.run_plugin_cmd_json(
            _COMMAND, device=device, args="-o json")

    def core_json(self, device=None):
        return self.run_core_cmd_json("id ctrl", device=device)

    # ---------------------------------------------------------------- #
    # Relationship to the core rendering                               #
    # ---------------------------------------------------------------- #

    def test_json_keys_are_the_core_keys_plus_pms(self):
        """The rendering adds one field and drops none."""
        micron = self.micron_json()
        core = self.core_json()

        missing = sorted(set(core) - set(micron))
        self.assertFalse(missing, f"missing core keys: {missing}")
        self.assertEqual(set(micron) - set(core), _EXTRA_KEYS)

    def test_json_shared_values_match_core(self):
        """Identify data is static, so the two renderings must agree."""
        micron = self.micron_json()
        core = self.core_json()

        differing = {key: (core[key], micron[key])
                     for key in set(micron) & set(core)
                     if core[key] != micron[key]}

        self.assertFalse(differing,
                         f"micron and core disagree on {differing!r}")

    def test_core_does_not_report_pms(self):
        """pms is what distinguishes this rendering from the core one."""
        self.assertNotIn("pms", self.core_json())

    # ---------------------------------------------------------------- #
    # The pms field                                                    #
    # ---------------------------------------------------------------- #

    def test_pms_tracks_its_ctratt_bit(self):
        """pms is bit 21 of CTRATT, reported as 0 or 1."""
        cases = (
            (0, 0),
            (1 << _CTRATT_PMS_BIT, 1),
            (0xFFFFFFFF, 1),
            (~(1 << _CTRATT_PMS_BIT) & 0xFFFFFFFF, 0),
        )
        for ctratt, expected in cases:
            with self.subTest(ctratt=hex(ctratt)):
                self.server.identify = pack_id_ctrl(ctratt=ctratt)

                self.assertEqual(self.micron_json()["pms"], expected)

    def test_pms_ignores_neighbouring_bits(self):
        """Only bit 21 matters, not the bits either side of it."""
        neighbours = (1 << (_CTRATT_PMS_BIT - 1)
                      ) | (1 << (_CTRATT_PMS_BIT + 1))
        self.server.identify = pack_id_ctrl(ctratt=neighbours)

        self.assertEqual(self.micron_json()["pms"], 0)

    def test_pms_matches_the_reported_ctratt(self):
        """pms stays consistent with the CTRATT value in the same output."""
        self.server.identify = pack_id_ctrl(
            ctratt=(1 << _CTRATT_PMS_BIT) | 0x55)
        micron = self.micron_json()
        ctratt = int(str(micron["ctratt"]), 0)

        self.assertEqual(micron["pms"], (ctratt >> _CTRATT_PMS_BIT) & 1)

    # ---------------------------------------------------------------- #
    # Normal output                                                    #
    # ---------------------------------------------------------------- #

    def test_normal_output_adds_the_pms_line(self):
        """Normal output is the core listing plus one line."""
        self.server.identify = pack_id_ctrl(ctratt=1 << _CTRATT_PMS_BIT)
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertIn(_IDENTIFY_HEADER, result.stdout)
        self.assertRegex(result.stdout, r"(?m)^pms\s+:\s+1$")

    def test_core_normal_output_has_no_pms_line(self):
        """The added line is not something core prints too."""
        core = self.run_core_cmd("id ctrl")

        self.assertEqual(core.returncode, 0, core.stderr)
        self.assertNotRegex(core.stdout, r"(?m)^pms\s+:")

    def test_identify_strings_are_reported(self):
        """The drive's identity strings reach the output."""
        self.server.identify = pack_id_ctrl(serial="MOCKSERIAL42",
                                            model="MockModel",
                                            fw="MOCKFW1")
        result = self.run_plugin_cmd_check(_COMMAND)

        for value in ("MOCKSERIAL42", "MockModel", "MOCKFW1"):
            self.assertIn(value, result.stdout)

    # ---------------------------------------------------------------- #
    # Binary output                                                    #
    # ---------------------------------------------------------------- #

    def test_binary_output_is_the_identify_structure(self):
        """Binary output is the structure the drive returned, byte for byte."""
        identify = pack_id_ctrl(serial="BINARYSN", ctratt=0x1234)
        self.server.identify = identify
        result = self.run_nvme('micron', _COMMAND, self.ctrl, '-o', 'binary',
                               encoding=None)

        self.assertEqual(result.returncode, 0,
                         result.stderr.decode('utf-8', 'replace'))
        self.assertEqual(len(result.stdout), ID_CTRL_SIZE)
        self.assertEqual(result.stdout, identify)

    # ---------------------------------------------------------------- #
    # Drive independence and failures                                  #
    # ---------------------------------------------------------------- #

    def test_unrecognised_drive_warns_but_succeeds(self):
        """The command is not gated on the model, only noisy about it."""
        self.select_model(None)
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertIn(_UNKNOWN_MODEL_WARNING, result.stderr)
        self.assertIn(_IDENTIFY_HEADER, result.stdout)

    def test_recognised_drive_does_not_warn(self):
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertNotIn(_UNKNOWN_MODEL_WARNING, result.stderr)

    def test_namespace_path_matches_the_controller_path(self):
        """A namespace path resolves to its parent controller."""
        self.assertEqual(self.micron_json(device=self.ctrl),
                         self.micron_json(device=self.ns1))

    def test_identify_failure_is_reported(self):
        """A drive that rejects identify fails with a message."""
        self.server.identify_status = SC_INVALID_FIELD
        result = self.run_plugin_cmd(_COMMAND)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("identify controller failed", result.stderr)

    def test_invalid_output_format_returns_error(self):
        self.check_output_format_rejected(_COMMAND, "notaformat")

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_COMMAND)


if __name__ == '__main__':
    main()
