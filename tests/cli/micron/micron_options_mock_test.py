#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron commands that change drive settings, hardware-free.

Three commands write to the drive rather than reading from it:

  vs-smbus-option                 enables, disables or reports the SMBus
                                  feature, on the models that have it.
  vs-telemetry-controller-option  enables, disables or reports controller
                                  telemetry log generation on a drive
                                  that supports telemetry.
  select-download                 downloads a firmware image and commits it
                                  with a slot selection chosen by name.

Against the mock the writes are observable and harmless, and the encoding
each one puts on the wire is asserted directly.

Tests in this module verify:
  * The feature value each option writes, the save bit, and the reported
    state for each value the drive can return.
  * The telemetry support gate, driven by the identify LPA field.
  * select-download's slot selection names, case folding and validation, the
    firmware file and size checks, the download chunking, and the status
    codes that mean "activated, power cycle to apply".
  * Rejection of an unrecognised option, before anything is written.
  * Error handling for a non-existent device.

Usage: python3 micron_options_mock_test.py <nvme-binary> <mock-lib>
"""

import os

from micron_mock_test import (
    LPA_TELEMETRY,
    OPC_FW_COMMIT,
    OPC_FW_DOWNLOAD,
    OPC_GET_FEATURES,
    OPC_SET_FEATURES,
    SC_INVALID_FIELD,
    TestMicronMock,
    main,
    pack_id_ctrl,
)

_SMBUS = "vs-smbus-option"
_TELEMETRY = "vs-telemetry-controller-option"
_DOWNLOAD = "select-download"

_FID_SMBUS = 0xD5
_FID_TELEMETRY = 0xCF

# Models vs-smbus-option accepts.
_SMBUS_MODELS = ('M5407', 'M5411', 'M6003', 'M6004')
_SMBUS_UNSUPPORTED_MODEL = 'M51CX'
_UNSUPPORTED_DRIVE_MSG = "This option is not supported for specified drive"

# Firmware slot selections, and the commit action each one commits with.
_SELECTIONS = {'OOB': 18, 'EEP': 10, 'ALL': 26}

# Commit statuses that mean the image was accepted but needs a power cycle.
_POWER_CYCLE_STATUSES = (0x10B, 0x20B)
_POWER_CYCLE_MSG = "Update successful! Power cycle for changes to take effect"

# nvme_init_fw_download() transfers the image in 4K chunks.
_FW_CHUNK = 4096


class FeatureTestBase(TestMicronMock):
    """Shared assertions for the feature-writing commands."""

    def writes(self, fid):
        return [c for c in self.server.commands
                if c['opcode'] == OPC_SET_FEATURES and c['fid'] == fid]

    def reads(self, fid):
        return [c for c in self.server.commands
                if c['opcode'] == OPC_GET_FEATURES and c['fid'] == fid]

    def one_write(self, fid):
        writes = self.writes(fid)
        self.assertEqual(len(writes), 1,
                         f"expected one Set Features for {fid:#x}, "
                         f"got {len(writes)}")
        return writes[0]


class TestMicronSmbusOption(FeatureTestBase):
    """vs-smbus-option: the SMBus feature on the models that have it."""

    def setUp(self):
        super().setUp()
        self.select_model(_SMBUS_MODELS[0])

    # ---------------------------------------------------------------- #
    # Writing                                                          #
    # ---------------------------------------------------------------- #

    def test_enable_sets_the_enable_bit(self):
        """Enabling sets bit 0 of the feature value."""
        self.run_plugin_cmd_check(_SMBUS, args="-O enable")

        self.assertEqual(self.one_write(_FID_SMBUS)['cdw11'], 1)

    def test_disable_clears_the_enable_bit(self):
        self.run_plugin_cmd_check(_SMBUS, args="-O disable")

        self.assertEqual(self.one_write(_FID_SMBUS)['cdw11'], 0)

    def test_disable_is_the_default_action(self):
        """With no -O the command disables the feature."""
        self.run_plugin_cmd_check(_SMBUS)

        self.assertEqual(self.one_write(_FID_SMBUS)['cdw11'], 0)

    def test_value_selects_the_reported_temperature(self):
        """The temperature selection is bit 1, above the enable bit."""
        cases = (
            ("enable", 0, 0b01),
            ("enable", 1, 0b11),
            ("disable", 0, 0b00),
            ("disable", 1, 0b10),
        )
        for option, value, expected in cases:
            with self.subTest(option=option, value=value):
                self.server.commands.clear()
                self.run_plugin_cmd_check(_SMBUS,
                                          args=f"-O {option} -V {value}")

                self.assertEqual(self.one_write(_FID_SMBUS)['cdw11'], expected)

    def test_save_makes_the_setting_persistent(self):
        """-s 1 sets the save bit, so the setting survives a power cycle."""
        for save, expected in ((0, False), (1, True)):
            with self.subTest(save=save):
                self.server.commands.clear()
                self.run_plugin_cmd_check(_SMBUS,
                                          args=f"-O enable -s {save}")
                saved = bool(self.one_write(_FID_SMBUS)['cdw10'] & (1 << 31))

                self.assertEqual(saved, expected)

    def test_write_failure_is_reported(self):
        """A drive that rejects the write says so and exits non-zero."""
        self.server.feature_status[_FID_SMBUS] = SC_INVALID_FIELD
        result = self.run_plugin_cmd(_SMBUS, args="-O enable")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Failed to enabled SMBus on drive", result.stderr)

    def test_success_is_reported_under_verbose(self):
        result = self.run_plugin_cmd_check(_SMBUS,
                                           args="-O enable --verbose")

        self.assertIn("successfully enabled SMBus on drive",
                      result.stdout + result.stderr)

    # ---------------------------------------------------------------- #
    # Reading                                                          #
    # ---------------------------------------------------------------- #

    def test_status_reports_both_bits(self):
        """The reported state decodes the two bits independently."""
        cases = {
            0b00: ("disabled", "composite"),
            0b01: ("enabled", "composite"),
            0b10: ("disabled", "hottest component"),
            0b11: ("enabled", "hottest component"),
        }
        for value, (state, sensor) in cases.items():
            with self.subTest(value=bin(value)):
                self.server.features[_FID_SMBUS] = value
                result = self.run_plugin_cmd_check(_SMBUS, args="-O status")

                self.assertIn(f"SMBus status on the drive: {state}",
                              result.stdout)
                self.assertIn(f"returns {sensor} temperature", result.stdout)

    def test_status_writes_nothing(self):
        """Reporting the state must not change it."""
        self.run_plugin_cmd_check(_SMBUS, args="-O status")

        self.assertEqual(self.writes(_FID_SMBUS), [])

    def test_status_value_selects_the_feature_selector(self):
        """-V picks current, default or saved for the read."""
        for value in (0, 1, 2):
            with self.subTest(value=value):
                self.server.commands.clear()
                self.run_plugin_cmd_check(_SMBUS,
                                          args=f"-O status -V {value}")
                reads = self.reads(_FID_SMBUS)

                self.assertEqual(len(reads), 1)
                self.assertEqual((reads[0]['cdw10'] >> 8) & 0x7, value)

    def test_status_read_failure_is_reported(self):
        self.server.feature_status[_FID_SMBUS] = SC_INVALID_FIELD
        result = self.run_plugin_cmd(_SMBUS, args="-O status")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Failed to retrieve SMBus status on the drive",
                      result.stderr)

    # ---------------------------------------------------------------- #
    # Validation and gating                                            #
    # ---------------------------------------------------------------- #

    def test_unrecognised_option_is_rejected(self):
        result = self.run_plugin_cmd(_SMBUS, args="-O bogus")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid option bogus", result.stderr)
        self.assertEqual(self.writes(_FID_SMBUS), [],
                         "an unrecognised option must not write the feature")

    def test_model_gate(self):
        """A model without the feature is refused, and nothing written."""
        self.select_model(_SMBUS_UNSUPPORTED_MODEL)
        result = self.run_plugin_cmd(_SMBUS, args="-O enable")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(_UNSUPPORTED_DRIVE_MSG, result.stderr)
        self.assertEqual(self.writes(_FID_SMBUS), [])

    def test_supported_models(self):
        for model in _SMBUS_MODELS:
            with self.subTest(model=model):
                self.select_model(model)
                self.server.commands.clear()
                self.run_plugin_cmd_check(_SMBUS, args="-O enable")

                self.assertEqual(len(self.writes(_FID_SMBUS)), 1)

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_SMBUS)


class TestMicronTelemetryControllerOption(FeatureTestBase):
    """vs-telemetry-controller-option: controller telemetry generation."""

    def setUp(self):
        super().setUp()
        self.server.identify = pack_id_ctrl(lpa=LPA_TELEMETRY)

    def test_enable_sets_the_feature(self):
        self.run_plugin_cmd_check(_TELEMETRY, args="-O enable")

        self.assertEqual(self.one_write(_FID_TELEMETRY)['cdw11'], 1)

    def test_disable_clears_the_feature(self):
        self.run_plugin_cmd_check(_TELEMETRY, args="-O disable")

        self.assertEqual(self.one_write(_FID_TELEMETRY)['cdw11'], 0)

    def test_disable_is_the_default_action(self):
        self.run_plugin_cmd_check(_TELEMETRY)

        self.assertEqual(self.one_write(_FID_TELEMETRY)['cdw11'], 0)

    def test_select_controls_the_save_bit(self):
        """-s 1 makes the setting persistent; only its low bit is used."""
        for select, expected in ((0, False), (1, True), (2, False),
                                 (3, True)):
            with self.subTest(select=select):
                self.server.commands.clear()
                self.run_plugin_cmd_check(_TELEMETRY,
                                          args=f"-O enable -s {select}")
                saved = bool(self.one_write(_FID_TELEMETRY)['cdw10']
                             & (1 << 31))

                self.assertEqual(saved, expected)

    def test_status_reports_the_feature_state(self):
        for value, expected in ((0, "disabled"), (1, "enabled"),
                                (0xFFFF, "enabled")):
            with self.subTest(value=value):
                self.server.features[_FID_TELEMETRY] = value
                result = self.run_plugin_cmd_check(_TELEMETRY,
                                                   args="-O status")

                self.assertIn(f"Controller telemetry option : {expected}",
                              result.stdout)

    def test_status_select_picks_the_feature_selector(self):
        """-s picks current, default or saved for the read."""
        for select in (0, 1, 2):
            with self.subTest(select=select):
                self.server.commands.clear()
                self.run_plugin_cmd_check(_TELEMETRY,
                                          args=f"-O status -s {select}")
                reads = self.reads(_FID_TELEMETRY)

                self.assertEqual(len(reads), 1)
                self.assertEqual((reads[0]['cdw10'] >> 8) & 0x7, select)

    def test_status_writes_nothing(self):
        self.run_plugin_cmd_check(_TELEMETRY, args="-O status")

        self.assertEqual(self.writes(_FID_TELEMETRY), [])

    def test_telemetry_support_gate(self):
        """A drive without telemetry support is told so, nothing written."""
        self.server.identify = pack_id_ctrl(lpa=0)
        result = self.run_plugin_cmd(_TELEMETRY, args="-O enable")

        self.assertIn("drive doesn't support host/controller generated "
                      "telemetry logs", result.stdout)
        self.assertEqual(self.writes(_FID_TELEMETRY), [])

    def test_other_lpa_bits_do_not_grant_support(self):
        """Only the telemetry bit of LPA matters."""
        self.server.identify = pack_id_ctrl(lpa=0xFF & ~LPA_TELEMETRY)
        result = self.run_plugin_cmd(_TELEMETRY, args="-O enable")

        self.assertIn("doesn't support", result.stdout)

    def test_unrecognised_option_is_rejected(self):
        result = self.run_plugin_cmd(_TELEMETRY, args="-O bogus")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid option bogus", result.stderr)
        self.assertEqual(self.writes(_FID_TELEMETRY), [])

    def test_write_failure_is_reported(self):
        self.server.feature_status[_FID_TELEMETRY] = SC_INVALID_FIELD
        result = self.run_plugin_cmd(_TELEMETRY, args="-O enable")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Failed to set controller telemetry option",
                      result.stderr)

    def test_runs_on_an_unrecognised_drive_model(self):
        """The command reads no model, so it is not gated on one."""
        self.select_model(None)
        self.run_plugin_cmd_check(_TELEMETRY, args="-O enable")

        self.assertEqual(len(self.writes(_FID_TELEMETRY)), 1)

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_TELEMETRY)


class TestMicronSelectDownload(TestMicronMock):
    """select-download: a firmware image with a named slot selection."""

    def firmware(self, size=_FW_CHUNK, name="fw.bin"):
        """Write a firmware image of @size bytes and return its path."""
        path = os.path.join(self.out_dir, name)
        with open(path, 'wb') as f:
            f.write(bytes(size))
        return path

    def downloads(self):
        return [c for c in self.server.commands
                if c['opcode'] == OPC_FW_DOWNLOAD]

    def commits(self):
        return [c for c in self.server.commands
                if c['opcode'] == OPC_FW_COMMIT]

    # ---------------------------------------------------------------- #
    # Slot selection                                                   #
    # ---------------------------------------------------------------- #

    def test_each_selection_commits_its_own_action(self):
        """The selection name chooses the commit action written."""
        path = self.firmware()
        for name, action in _SELECTIONS.items():
            with self.subTest(select=name):
                self.server.commands.clear()
                self.run_plugin_cmd_check(_DOWNLOAD,
                                          args=f"-f {path} -s {name}")
                commits = self.commits()

                self.assertEqual(len(commits), 1)
                self.assertEqual(commits[0]['cdw12'], action)

    def test_selection_is_case_insensitive(self):
        """A lower-case selection means the same as an upper-case one."""
        path = self.firmware()
        for name, action in _SELECTIONS.items():
            for spelling in (name.lower(), name.capitalize()):
                with self.subTest(select=spelling):
                    self.server.commands.clear()
                    self.run_plugin_cmd_check(_DOWNLOAD,
                                              args=f"-f {path} -s {spelling}")

                    self.assertEqual(self.commits()[0]['cdw12'], action)

    def test_unrecognised_selection_is_rejected(self):
        """Only the three defined selections are accepted."""
        path = self.firmware()
        result = self.run_plugin_cmd(_DOWNLOAD, args=f"-f {path} -s XYZ")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid select flag", result.stderr)
        self.assertEqual(self.downloads(), [],
                         "an unrecognised selection must not send the image")

    def test_selection_length_is_checked_first(self):
        """A selection of the wrong length is refused before it is matched.

        The long form is used so an empty selection survives argument
        splitting.
        """
        path = self.firmware()
        for value in ("", "OO", "OOBB"):
            with self.subTest(select=value):
                result = self.run_plugin_cmd(
                    _DOWNLOAD, args=f"-f {path} --select={value}")

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Invalid select flag", result.stderr)

    def test_missing_selection_is_rejected(self):
        """The selection has no default, so omitting it is an error."""
        path = self.firmware()
        result = self.run_plugin_cmd(_DOWNLOAD, args=f"-f {path}")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid select flag", result.stderr)

    # ---------------------------------------------------------------- #
    # The firmware image                                               #
    # ---------------------------------------------------------------- #

    def test_missing_firmware_file_is_rejected(self):
        result = self.run_plugin_cmd(
            _DOWNLOAD, args=f"-f {self.out_dir}/absent.bin -s ALL")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no firmware file provided", result.stderr)

    def test_omitted_firmware_file_is_rejected(self):
        result = self.run_plugin_cmd(_DOWNLOAD, args="-s ALL")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no firmware file provided", result.stderr)

    def test_misaligned_image_is_rejected(self):
        """A firmware image is transferred in dwords, so its size must be a
        multiple of four."""
        for size in (1, 2, 3, _FW_CHUNK + 1):
            with self.subTest(size=size):
                path = self.firmware(size=size, name=f"fw{size}.bin")
                result = self.run_plugin_cmd(_DOWNLOAD,
                                             args=f"-f {path} -s ALL")

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"Invalid size:{size} for f/w image",
                              result.stderr)
                self.assertEqual(self.downloads(), [])

    def test_image_is_sent_in_chunks(self):
        """A larger image is split into transfers the drive accepts."""
        cases = {_FW_CHUNK: 1, 2 * _FW_CHUNK: 2, 5 * _FW_CHUNK: 5}
        for size, expected in cases.items():
            with self.subTest(size=size):
                path = self.firmware(size=size, name=f"fw{size}.bin")
                self.server.commands.clear()
                self.run_plugin_cmd_check(_DOWNLOAD,
                                          args=f"-f {path} -s ALL")

                self.assertEqual(len(self.downloads()), expected)

    def test_chunks_cover_the_whole_image(self):
        """Each transfer advances the offset by the amount already sent."""
        path = self.firmware(size=3 * _FW_CHUNK, name="fw3.bin")
        self.run_plugin_cmd_check(_DOWNLOAD, args=f"-f {path} -s ALL")
        downloads = self.downloads()

        # nvme_init_fw_download() puts the dword count in cdw10 and the dword
        # offset in cdw11.
        self.assertEqual([c['cdw11'] for c in downloads],
                         [0, _FW_CHUNK // 4, 2 * _FW_CHUNK // 4])
        for command in downloads:
            self.assertEqual(command['len'], _FW_CHUNK)

    def test_a_short_final_chunk_is_sent(self):
        """An image that is not a whole number of chunks still transfers."""
        size = _FW_CHUNK + 8
        path = self.firmware(size=size, name="fwshort.bin")
        self.run_plugin_cmd_check(_DOWNLOAD, args=f"-f {path} -s ALL")
        downloads = self.downloads()

        self.assertEqual(len(downloads), 2)
        self.assertEqual(downloads[1]['len'], 8)

    def test_commit_follows_the_download(self):
        """The image is committed once, after it has all been sent."""
        path = self.firmware(size=2 * _FW_CHUNK, name="fw2.bin")
        self.run_plugin_cmd_check(_DOWNLOAD, args=f"-f {path} -s OOB")
        opcodes = [c['opcode'] for c in self.server.commands
                   if c['opcode'] in (OPC_FW_DOWNLOAD, OPC_FW_COMMIT)]

        self.assertEqual(opcodes, [OPC_FW_DOWNLOAD, OPC_FW_DOWNLOAD,
                                   OPC_FW_COMMIT])

    # ---------------------------------------------------------------- #
    # Commit results                                                   #
    # ---------------------------------------------------------------- #

    def test_power_cycle_statuses_are_reported_as_success(self):
        """A commit that needs a power cycle is not a failure."""
        path = self.firmware()
        for status in _POWER_CYCLE_STATUSES:
            with self.subTest(status=hex(status)):
                self.server.fw_commit_status = status
                result = self.run_plugin_cmd(_DOWNLOAD,
                                             args=f"-f {path} -s ALL")

                self.assertEqual(
                    result.returncode, 0,
                    f"status {status:#x} means the image was accepted")
                self.assertIn(_POWER_CYCLE_MSG, result.stdout)
                self.assertNotIn(_POWER_CYCLE_MSG, result.stderr)

    def test_other_commit_failures_are_reported(self):
        """A commit the drive rejects outright fails."""
        path = self.firmware()
        self.server.fw_commit_status = SC_INVALID_FIELD
        result = self.run_plugin_cmd(_DOWNLOAD, args=f"-f {path} -s ALL")

        self.assertNotEqual(result.returncode, 0)

    def test_download_failure_stops_the_transfer(self):
        """A rejected transfer is reported and the commit is not attempted."""
        path = self.firmware(size=3 * _FW_CHUNK, name="fwfail.bin")
        self.server.fw_download_status = SC_INVALID_FIELD
        result = self.run_plugin_cmd(_DOWNLOAD, args=f"-f {path} -s ALL")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.downloads()), 1,
                         "the transfer continued past a rejected chunk")
        self.assertEqual(self.commits(), [],
                         "the image was committed despite a failed transfer")

    def test_successful_commit_exits_zero(self):
        path = self.firmware()
        result = self.run_plugin_cmd_check(_DOWNLOAD,
                                           args=f"-f {path} -s ALL")

        self.assertEqual(result.returncode, 0)

    def test_runs_on_an_unrecognised_drive_model(self):
        """The command reads no model, so it is not gated on one."""
        self.select_model(None)
        path = self.firmware()
        self.run_plugin_cmd_check(_DOWNLOAD, args=f"-f {path} -s ALL")

        self.assertEqual(len(self.commits()), 1)

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_DOWNLOAD, args="-s ALL")


if __name__ == '__main__':
    main()
