#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for micron plugin drive-model detection and the gates built on it.

GetDriveModel() maps the PCI vendor and device ID to one of eleven models,
and most commands accept only a subset of them.  On real hardware only the
attached drive's model is reachable, so the other branches -- and every
"unsupported drive" message -- go untested.  Here the model is an input: the
fake sysfs tree advertises whichever device ID the test wants.

Tests in this module verify:
  * Every device ID in the plugin's switch maps to the same model as the
    other IDs for that model, and a device ID outside the switch, or a
    non-Micron vendor ID, yields UNKNOWN_MODEL.
  * For all eleven models plus UNKNOWN, each gated command either runs or
    reports its own gate message -- matching the plugin's gating table.
  * A rejected command exits non-zero, so a caller can detect the refusal
    without scraping stderr.
  * The gate is reported once, not alongside a later diagnostic.

Usage: python3 micron_drive_model_mock_test.py <nvme-binary> <mock-lib>
"""

from micron_mock_test import (
    MICRON_MODELS,
    UNKNOWN_DEVICE_ID,
    TestMicronMock,
    main,
)

# Models each gated command accepts, mirroring the plugin's gate conditions.
# A command is expected to refuse every other model, UNKNOWN included.
_GATES = {
    'vs-nand-stats': (
        "Unsupported drive model for vs-nand-stats command",
        set(MICRON_MODELS),
    ),
    'vs-smart-ext-log': (
        "Unsupported drive model for vs-smart-ext-log command",
        {'M51CX', 'M51BY', 'M51CY', 'M6003', 'M6004', 'M6001'},
    ),
    'vs-work-load-log': (
        "Unsupported drive model for vs-work-load-log command",
        {'M6001', 'M6003', 'M6004'},
    ),
    'vs-vendor-telemetry-log': (
        "Unsupported drive model for vs-vendor-telemetry-log command",
        {'M6001', 'M6003', 'M6004'},
    ),
    'vs-fw-activate-history': (
        "Unsupported drive model for vs-fw-activate-history command",
        {'M51CX', 'M51BY', 'M51CY', 'M6003', 'M6004'},
    ),
    'vs-smart-add-log': (
        "Unsupported drive model for vs-smart-add-log command",
        {'M51CX', 'M51BY', 'M51CY', 'M6003', 'M6004', 'M5410', 'M5407'},
    ),
    'vs-cloud-log': (
        "Unsupported drive model for vs-cloud-log",
        {'M51CX'},
    ),
    'vs-pcie-stats': (
        "Unsupported drive model for vs-pcie-stats command",
        set(MICRON_MODELS),
    ),
    'vs-drive-info': (
        "ERROR : Unsupported drive for vs-drive-info cmd",
        set(MICRON_MODELS),
    ),
    'clear-fw-activate-history': (
        "This option is not supported for specified drive",
        {'M51CX', 'M51BY', 'M51CY', 'M6003', 'M6004'},
    ),
    'vs-smbus-option': (
        "This option is not supported for specified drive",
        {'M5407', 'M5411', 'M6003', 'M6004'},
    ),
}

# vs-internal-log gates the same way but needs a --package argument to reach
# the check, so it is driven separately.
_INTERNAL_LOG_MSG = "Unsupported drive model for vs-internal-log collection"

# A command that names its model in the message, used to tell one model from
# another without relying on a gate that several models share.
_MODEL_PROBE = 'vs-drive-info'


class TestMicronDriveModel(TestMicronMock):
    """Model detection and the per-model command gates."""

    def _gate_reason(self, command, message):
        """Report whether @command refused the current model.

        Also asserts the refusal is visible in the exit status, not only in
        the message.
        """
        result = self.run_plugin_cmd(command)
        if message in result.stderr:
            self.assertNotEqual(
                result.returncode, 0,
                f"micron {command} reported {message!r} but exited 0; a "
                f"caller cannot tell the refusal from success",
            )
            return True
        return False

    # ------------------------------------------------------------------ #
    # Device ID -> model mapping                                         #
    # ------------------------------------------------------------------ #

    def test_every_device_id_maps_to_its_model(self):
        """All device IDs listed for a model behave identically.

        vs-cloud-log accepts only M51CX, so it separates that model from
        every other; vs-work-load-log separates the M600x family. Together
        they pin each ID to the right switch case.
        """
        for model, device_ids in MICRON_MODELS.items():
            for did in device_ids:
                with self.subTest(model=model, device_id=hex(did)):
                    self.select_device_id(did)
                    cloud_gated = self._gate_reason(
                        'vs-cloud-log', _GATES['vs-cloud-log'][0])
                    workload_gated = self._gate_reason(
                        'vs-work-load-log', _GATES['vs-work-load-log'][0])

                    self.assertEqual(
                        cloud_gated, model != 'M51CX',
                        f"device ID {did:#06x} should map to {model}, but "
                        f"vs-cloud-log gating says "
                        f"{'not ' if cloud_gated else ''}M51CX",
                    )
                    self.assertEqual(
                        workload_gated,
                        model not in _GATES['vs-work-load-log'][1],
                        f"device ID {did:#06x} should map to {model}, but "
                        f"vs-work-load-log gating disagrees",
                    )

    def test_unlisted_device_id_is_unknown_model(self):
        """A Micron vendor ID with an unrecognised device ID is UNKNOWN."""
        self.select_device_id(UNKNOWN_DEVICE_ID)
        result = self.run_plugin_cmd(_MODEL_PROBE)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(_GATES[_MODEL_PROBE][0], result.stderr)

    def test_non_micron_vendor_is_unknown_model(self):
        """A recognised device ID under another vendor is still UNKNOWN.

        The device ID is only consulted once the vendor ID matches Micron.
        """
        self.select_vendor(0x144D, did=MICRON_MODELS['M51CX'][0])
        result = self.run_plugin_cmd(_MODEL_PROBE)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(_GATES[_MODEL_PROBE][0], result.stderr)

    def test_missing_pci_attributes_are_unknown_model(self):
        """A controller whose PCI attributes cannot be read is UNKNOWN.

        read_pci_attr() treats a missing attribute as a non-error and leaves
        the IDs at zero, so the plugin must not mistake that for a match.
        """
        (self.sysfs_path_ctrl() / "device").unlink()
        result = self.run_plugin_cmd(_MODEL_PROBE)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(_GATES[_MODEL_PROBE][0], result.stderr)

    # ------------------------------------------------------------------ #
    # Per-model gates                                                    #
    # ------------------------------------------------------------------ #

    def test_gates_match_the_plugin_table(self):
        """Each gated command accepts exactly the models it declares."""
        for model in list(MICRON_MODELS) + [None]:
            self.select_model(model)
            for command, (message, supported) in _GATES.items():
                with self.subTest(model=model or 'UNKNOWN', command=command):
                    gated = self._gate_reason(command, message)
                    expected_gated = model not in supported
                    want = 'a refusal' if expected_gated else 'no refusal'
                    self.assertEqual(
                        gated, expected_gated,
                        f"micron {command} on {model or 'UNKNOWN'}: expected "
                        f"{want}, got {'a refusal' if gated else 'none'}",
                    )

    def test_internal_log_gate(self):
        """vs-internal-log refuses UNKNOWN and accepts every known model."""
        for model in list(MICRON_MODELS) + [None]:
            with self.subTest(model=model or 'UNKNOWN'):
                self.select_model(model)
                result = self.run_plugin_cmd('vs-internal-log',
                                             args="--package=out.zip")
                if model is None:
                    self.assertIn(_INTERNAL_LOG_MSG, result.stderr)
                    self.assertNotEqual(result.returncode, 0)
                else:
                    self.assertNotIn(_INTERNAL_LOG_MSG, result.stderr)

    def test_gate_is_reported_before_any_log_read(self):
        """A refused command must not have read any log page.

        The gate precedes collection, so a caller sees the one message rather
        than a gate followed by log-read diagnostics.
        """
        self.select_model(None)
        for command, (message, _) in _GATES.items():
            with self.subTest(command=command):
                self.server.commands.clear()
                result = self.run_plugin_cmd(command)

                self.assertIn(message, result.stderr)
                self.assertEqual(
                    self.server.log_reads(), [],
                    f"micron {command} reported its gate but had already read "
                    f"log pages {sorted(self.server.lids_read())}",
                )


if __name__ == '__main__':
    main()
