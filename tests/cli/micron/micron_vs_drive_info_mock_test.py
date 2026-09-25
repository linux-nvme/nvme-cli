#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron vs-drive-info command, hardware-free.

vs-drive-info reports drive hardware information from one of two sources: an
0xDA vendor opcode on M5407, or the vendor-specific identify bytes on every
other model.  Which fields it then reports, and how they are formatted,
depends on the customer ID in the identify data, and on M51CX with a
Hyperscale customer ID it additionally reads boot-spec version and ownership
status out of the 0xC0 log.

Tests in this module verify:
  * The data source per model: the 0xDA opcode on M5407, identify elsewhere.
  * The hardware version, always reported, in text and JSON.
  * FTL unit size in KB for a generic drive and in bytes for a Hyperscale
    one, and that a zero size is omitted entirely.
  * Boot spec version formatting for each source, and its omission when the
    drive reports 0.0.
  * All four ownership states, and that ownership is reported only for a
    Hyperscale customer ID.
  * The 0xC0 log is read only for M51CX with a Hyperscale customer ID.
  * Text and JSON agree on the field set and every value.
  * The namespace path reports what the controller path does.
  * Failure handling: 0xDA rejected, 0xC0 rejected, unsupported model, a
    non-existent device and a bad --output-format.

Usage: python3 micron_vs_drive_info_mock_test.py <nvme-binary> <mock-lib>
"""

import json
import re
import struct

from micron_mock_test import (
    CUST_ID_GENERIC,
    CUST_ID_GG,
    OPC_VENDOR_DA,
    SC_INVALID_FIELD,
    SC_INVALID_LOG_PAGE,
    TestMicronMock,
    main,
    pack_id_ctrl,
)

_COMMAND = "vs-drive-info"

_JSON_KEY = "Micron Drive HW Information"

_HW_VERSION = "Drive Hardware Version"
_FTL_UNIT_SIZE = "FTL_unit_size"
_BOOT_SPEC = "Boot Spec.Version"
_OWNERSHIP = "Drive Ownership Status"
_ALL_LABELS = (_HW_VERSION, _FTL_UNIT_SIZE, _BOOT_SPEC, _OWNERSHIP)

_UNSUPPORTED_MSG = "ERROR : Unsupported drive for vs-drive-info cmd"

# Byte offsets within the 0xC0 log that vs-drive-info reads.
_C0_SIZE = 512
_C0_BS_VER_MAJOR = 300
_C0_BS_VER_MINOR = 302
_C0_OWNERSHIP = 312

_OWNERSHIP_STATES = {0: "N/A", 1: "UNSET", 2: "SET", 3: "BLOCKED"}


def pack_fb_drive_info(hw_major=0, hw_minor=0, ftl_unit_size=0,
                       bs_ver_major=0, bs_ver_minor=0, ownership_status=0):
    """Build the struct fb_drive_info the 0xDA opcode returns.

    The struct is naturally aligned, so the two 16-bit version fields start
    at offset 4 rather than 3.
    """
    return struct.pack('<BBBxHHI', hw_major, hw_minor, ftl_unit_size,
                       bs_ver_major, bs_ver_minor, ownership_status)


def pack_c0_log(bs_ver_major=0, bs_ver_minor=0, ownership_status=0):
    buf = bytearray(_C0_SIZE)
    struct.pack_into('<H', buf, _C0_BS_VER_MAJOR, bs_ver_major)
    struct.pack_into('<H', buf, _C0_BS_VER_MINOR, bs_ver_minor)
    struct.pack_into('<I', buf, _C0_OWNERSHIP, ownership_status)
    return bytes(buf)


class TestMicronVsDriveInfo(TestMicronMock):
    """vs-drive-info against a mocked drive of any model."""

    def setup_drive(self, model='M51CX', cust_id=CUST_ID_GENERIC,
                    hw_ver=(3, 7), ftl_unit_size=0, c0_log=None):
        """Configure the drive the identify path reads from.

        A readable 0xC0 log is provided by default so tests that are not
        about that read do not have to care whether this model consults it.
        """
        self.select_model(model)
        self.server.identify = pack_id_ctrl(cust_id=cust_id, hw_ver=hw_ver,
                                            ftl_unit_size=ftl_unit_size)
        self.server.logs[0xC0] = pack_c0_log() if c0_log is None else c0_log

    def text_fields(self, stdout):
        """Return the {label: value} pairs from the text output."""
        fields = {}
        for label in _ALL_LABELS:
            m = re.search(r"^" + re.escape(label) + r"\s*:\s*(.*)$", stdout,
                          re.MULTILINE)
            if m:
                fields[label] = m.group(1).strip()
        return fields

    def json_fields(self, device=None):
        """Return the single info object from the JSON array."""
        data = self.run_plugin_cmd_json(_COMMAND, device=device)
        self.assertIn(_JSON_KEY, data,
                      f"Expected top-level {_JSON_KEY!r}, got {list(data)}")
        array = data[_JSON_KEY]
        self.assertIsInstance(array, list)
        self.assertEqual(len(array), 1,
                         f"Expected one info object, got {len(array)}")
        return array[0]

    # ---------------------------------------------------------------- #
    # Data source per model                                            #
    # ---------------------------------------------------------------- #

    def test_m5407_reads_the_vendor_opcode(self):
        """On M5407 the hardware data comes from the 0xDA opcode."""
        self.select_model('M5407')
        self.server.vendor[OPC_VENDOR_DA] = pack_fb_drive_info(hw_major=9,
                                                               hw_minor=4)
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertIn(OPC_VENDOR_DA, self.server.opcodes(),
                      "the 0xDA vendor opcode was never issued")
        self.assertEqual(self.text_fields(result.stdout)[_HW_VERSION], "9.4")

    def test_other_models_read_identify(self):
        """Off M5407 the hardware data comes from the identify vs bytes."""
        self.setup_drive(model='M51BX', hw_ver=(2, 11))
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertNotIn(OPC_VENDOR_DA, self.server.opcodes(),
                         "0xDA was issued on a model that reads identify")
        self.assertEqual(self.text_fields(result.stdout)[_HW_VERSION], "2.11")

    def test_vendor_opcode_failure_is_fatal(self):
        """A drive that rejects 0xDA reports the failure and exits non-zero."""
        self.select_model('M5407')
        self.server.vendor[OPC_VENDOR_DA] = SC_INVALID_FIELD
        result = self.run_plugin_cmd(_COMMAND)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("drive-info opcode failed", result.stderr)

    # ---------------------------------------------------------------- #
    # Hardware version                                                 #
    # ---------------------------------------------------------------- #

    def test_hardware_version_is_always_reported(self):
        """The hardware version is emitted whatever else is missing."""
        self.setup_drive(hw_ver=(0, 0))
        text = self.text_fields(self.run_plugin_cmd_check(_COMMAND).stdout)

        self.assertEqual(text[_HW_VERSION], "0.0")
        self.assertEqual(self.json_fields()[_HW_VERSION], "0.0")

    def test_hardware_version_reports_both_bytes(self):
        """Each version byte is reported independently, up to 255."""
        for major, minor in ((1, 2), (255, 0), (0, 255), (16, 32)):
            with self.subTest(hw_ver=(major, minor)):
                self.setup_drive(hw_ver=(major, minor))
                text = self.text_fields(
                    self.run_plugin_cmd_check(_COMMAND).stdout)
                self.assertEqual(text[_HW_VERSION], f"{major}.{minor}")

    # ---------------------------------------------------------------- #
    # FTL unit size                                                    #
    # ---------------------------------------------------------------- #

    def test_ftl_unit_size_is_kb_for_a_generic_drive(self):
        """A generic customer ID reports the raw value in KB."""
        self.setup_drive(cust_id=CUST_ID_GENERIC, ftl_unit_size=32)
        text = self.text_fields(self.run_plugin_cmd_check(_COMMAND).stdout)

        self.assertEqual(text[_FTL_UNIT_SIZE], "32 KB")
        self.assertEqual(self.json_fields()[_FTL_UNIT_SIZE], "32 KB")

    def test_ftl_unit_size_is_bytes_for_a_hyperscale_drive(self):
        """A Hyperscale customer ID reports the value scaled to bytes."""
        self.setup_drive(cust_id=CUST_ID_GG, ftl_unit_size=32)
        text = self.text_fields(self.run_plugin_cmd_check(_COMMAND).stdout)

        self.assertEqual(text[_FTL_UNIT_SIZE], f"{32 * 1024} B")
        self.assertEqual(self.json_fields()[_FTL_UNIT_SIZE], f"{32 * 1024} B")

    def test_zero_ftl_unit_size_is_omitted(self):
        """A drive reporting no FTL unit size gets no field, not a zero."""
        for cust_id in (CUST_ID_GENERIC, CUST_ID_GG):
            with self.subTest(cust_id=hex(cust_id)):
                self.setup_drive(cust_id=cust_id, ftl_unit_size=0)
                text = self.text_fields(
                    self.run_plugin_cmd_check(_COMMAND).stdout)

                self.assertNotIn(_FTL_UNIT_SIZE, text)
                self.assertNotIn(_FTL_UNIT_SIZE, self.json_fields())

    # ---------------------------------------------------------------- #
    # Boot spec version                                                #
    # ---------------------------------------------------------------- #

    def test_boot_spec_from_the_c0_log_on_hyperscale_m51cx(self):
        """M51CX with a Hyperscale customer ID reads the 0xC0 log for it."""
        self.setup_drive(model='M51CX', cust_id=CUST_ID_GG,
                         c0_log=pack_c0_log(bs_ver_major=2, bs_ver_minor=5))
        text = self.text_fields(self.run_plugin_cmd_check(_COMMAND).stdout)

        self.assertEqual(text[_BOOT_SPEC], "HyperScale Boot Version Spec.2.5")
        self.assertIn(0xC0, self.server.lids_read())

    def test_boot_spec_from_the_vendor_opcode_on_m5407(self):
        """M5407 reports the plain version its 0xDA payload carries."""
        self.select_model('M5407')
        self.server.vendor[OPC_VENDOR_DA] = pack_fb_drive_info(
            hw_major=1, hw_minor=0, bs_ver_major=4, bs_ver_minor=1)
        text = self.text_fields(self.run_plugin_cmd_check(_COMMAND).stdout)

        self.assertEqual(text[_BOOT_SPEC], "4.1")

    def test_zero_boot_spec_is_omitted(self):
        """A 0.0 boot spec version means the drive has none to report."""
        self.setup_drive(model='M51CX', cust_id=CUST_ID_GG,
                         c0_log=pack_c0_log(bs_ver_major=0, bs_ver_minor=0))
        text = self.text_fields(self.run_plugin_cmd_check(_COMMAND).stdout)

        self.assertNotIn(_BOOT_SPEC, text)
        self.assertNotIn(_BOOT_SPEC, self.json_fields())

    def test_boot_spec_minor_only_is_still_reported(self):
        """Either half being set is enough for the field to appear."""
        self.setup_drive(model='M51CX', cust_id=CUST_ID_GG,
                         c0_log=pack_c0_log(bs_ver_major=0, bs_ver_minor=3))
        text = self.text_fields(self.run_plugin_cmd_check(_COMMAND).stdout)

        self.assertEqual(text[_BOOT_SPEC], "HyperScale Boot Version Spec.0.3")

    # ---------------------------------------------------------------- #
    # Ownership status                                                 #
    # ---------------------------------------------------------------- #

    def test_every_ownership_state(self):
        """Each ownership value maps to its own name."""
        for value, name in _OWNERSHIP_STATES.items():
            with self.subTest(ownership_status=value):
                self.setup_drive(model='M51CX', cust_id=CUST_ID_GG,
                                 c0_log=pack_c0_log(ownership_status=value))
                text = self.text_fields(
                    self.run_plugin_cmd_check(_COMMAND).stdout)

                self.assertEqual(text[_OWNERSHIP], name)
                self.assertEqual(self.json_fields()[_OWNERSHIP], name)

    def test_ownership_is_hyperscale_only(self):
        """A generic drive reports no ownership status at all."""
        self.setup_drive(model='M51CX', cust_id=CUST_ID_GENERIC)
        text = self.text_fields(self.run_plugin_cmd_check(_COMMAND).stdout)

        self.assertNotIn(_OWNERSHIP, text)
        self.assertNotIn(_OWNERSHIP, self.json_fields())

    def test_hyperscale_always_reports_ownership(self):
        """A Hyperscale drive reports ownership even with no 0xC0 data.

        Off M51CX the log is never read, so the status stays 0 and must still
        be reported rather than dropped like the optional fields.
        """
        self.setup_drive(model='M51CY', cust_id=CUST_ID_GG)
        text = self.text_fields(self.run_plugin_cmd_check(_COMMAND).stdout)

        self.assertEqual(text[_OWNERSHIP], "N/A")
        self.assertNotIn(
            0xC0, self.server.lids_read(),
            "the 0xC0 log was read on a model that does not use it")

    # ---------------------------------------------------------------- #
    # The 0xC0 read is narrowly gated                                  #
    # ---------------------------------------------------------------- #

    def test_c0_log_is_read_only_for_hyperscale_m51cx(self):
        """Both the model and the customer ID have to match."""
        cases = (
            ('M51CX', CUST_ID_GG, True),
            ('M51CX', CUST_ID_GENERIC, False),
            ('M51CY', CUST_ID_GG, False),
            ('M51BX', CUST_ID_GENERIC, False),
        )
        for model, cust_id, expected in cases:
            with self.subTest(model=model, cust_id=hex(cust_id)):
                self.setup_drive(model=model, cust_id=cust_id,
                                 c0_log=pack_c0_log())
                self.server.commands.clear()
                self.run_plugin_cmd_check(_COMMAND)

                self.assertEqual(
                    0xC0 in self.server.lids_read(), expected,
                    f"{model} with customer ID {cust_id:#x} should "
                    f"{'read' if expected else 'not read'} the 0xC0 log",
                )

    def test_c0_log_failure_is_fatal(self):
        """A Hyperscale M51CX that cannot read 0xC0 reports it and fails.

        nvme_show_err() drops the caller's message for a positive NVMe
        status and reports the status itself, so that is what surfaces.
        """
        self.setup_drive(model='M51CX', cust_id=CUST_ID_GG,
                         c0_log=SC_INVALID_LOG_PAGE)
        result = self.run_plugin_cmd(_COMMAND)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid Log Page", result.stderr)

    # ---------------------------------------------------------------- #
    # Format parity and the option surface                             #
    # ---------------------------------------------------------------- #

    def test_text_and_json_report_the_same_fields(self):
        """Both formats are driven by the same data, so they must agree."""
        self.setup_drive(model='M51CX', cust_id=CUST_ID_GG, hw_ver=(5, 6),
                         ftl_unit_size=16,
                         c0_log=pack_c0_log(bs_ver_major=1, bs_ver_minor=2,
                                            ownership_status=2))
        text = self.text_fields(self.run_plugin_cmd_check(_COMMAND).stdout)

        self.assertEqual(text, self.json_fields())
        self.assertEqual(set(text), set(_ALL_LABELS),
                         "expected every field to be present for this drive")

    def test_json_reports_no_undocumented_fields(self):
        """A new field must not appear without this test being updated."""
        self.setup_drive(model='M51CX', cust_id=CUST_ID_GG,
                         c0_log=pack_c0_log(bs_ver_major=1))
        extra = set(self.json_fields()) - set(_ALL_LABELS)

        self.assertFalse(
            extra, f"undocumented keys in the JSON object: {extra}")

    def test_default_output_is_text(self):
        """With no format flag the output is text, not JSON."""
        self.setup_drive()
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertIn(_HW_VERSION, self.text_fields(result.stdout))
        with self.assertRaises(ValueError,
                               msg="default output must not be JSON"):
            json.loads(result.stdout)

    def test_explicit_normal_format_is_text(self):
        """--output-format=normal produces the same text as the default."""
        self.setup_drive(hw_ver=(4, 2))
        default = self.run_plugin_cmd_check(_COMMAND)
        normal = self.run_plugin_cmd_check(_COMMAND,
                                           args="--output-format=normal")

        self.assertEqual(default.stdout, normal.stdout)

    def test_short_json_flag_matches_the_long_one(self):
        """-o json is the same switch as --output-format=json."""
        self.setup_drive(hw_ver=(4, 2), ftl_unit_size=8)
        long_form = self.run_plugin_cmd_check(
            _COMMAND, args="--output-format=json").stdout
        short_form = self.run_plugin_cmd_check(_COMMAND, args="-o json").stdout

        self.assertEqual(long_form, short_form)

    def test_namespace_path_matches_the_controller_path(self):
        """A namespace path resolves to its parent controller."""
        self.setup_drive(model='M51CX', cust_id=CUST_ID_GG, hw_ver=(1, 1),
                         ftl_unit_size=4,
                         c0_log=pack_c0_log(ownership_status=1))

        self.assertEqual(self.json_fields(device=self.ctrl),
                         self.json_fields(device=self.ns1))

    def test_binary_output_format_rejected(self):
        """The command declares normal|json, so binary is refused."""
        self.setup_drive()
        self.check_output_format_rejected(_COMMAND, "binary")

    def test_invalid_output_format_returns_error(self):
        """An unrecognised --output-format is refused."""
        self.setup_drive()
        self.check_output_format_rejected(_COMMAND, "notaformat")

    def test_unsupported_model_is_refused(self):
        """An unrecognised drive is refused before the format check."""
        self.select_model(None)
        result = self.run_plugin_cmd(_COMMAND)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(_UNSUPPORTED_MSG, result.stderr)

    def test_bad_device_returns_error(self):
        """A non-existent device fails with the device path in the message."""
        self.check_bad_device_name(_COMMAND)


if __name__ == '__main__':
    main()
