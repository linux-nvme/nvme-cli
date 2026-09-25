#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron cloud SSD commands, hardware-free.

vs-cloud-log, vs-device-waf and cloud-boot-SSD-version all read the vendor
0xC0 cloud health log, and all three are reachable only on a drive whose
customer ID in the vendor-specific identify data marks it a Hyperscale boot
SSD.  vs-cloud-log is additionally restricted to M51CX.

On hardware, a drive is either a cloud SSD or it is not, so one side of each
gate is unreachable. Here the customer ID is an input, so both sides run.

Tests in this module verify:
  * The customer-ID gate for all three commands, in both directions.
  * The model gate on vs-cloud-log, and that it precedes the customer-ID one.
  * cloud-boot-SSD-version decoding the boot spec version out of the log.
  * vs-device-waf computing written / (TLC + SLC) and rounding it, including
    the case where the ratio is below one.
  * vs-cloud-log rendering the log as a field table in text and JSON.
  * The commands that declare no output format ignoring --output-format,
    and vs-cloud-log rejecting one it does not implement.
  * Error handling for identify and log failures and a non-existent device.

Usage: python3 micron_cloud_commands_mock_test.py <nvme-binary> <mock-lib>
"""

import re
import struct

from micron_mock_test import (
    CUST_ID_GENERIC,
    CUST_ID_GG,
    SC_INVALID_LOG_PAGE,
    TestMicronMock,
    main,
    pack_id_ctrl,
    pack_smart_log,
)

_CLOUD_LOG = "vs-cloud-log"
_DEVICE_WAF = "vs-device-waf"
_BOOT_VERSION = "cloud-boot-SSD-version"

_LID_CLOUD = 0xC0
_C0_SIZE = 512

# The top-level JSON key vs-cloud-log emits.
_CLOUD_JSON_KEYS = ("OCP Hyperscale Cloud Health Log: 0xC0",)

# The model gate message ends in "command", which vs-cloud-log misspells, so
# only the prefix up to the command name is matched.
_UNSUPPORTED_MODEL_MSG = f"Unsupported drive model for {_CLOUD_LOG}"
_UNSUPPORTED_DRIVE_MSG = ("{command} option is not supported for "
                          "specified drive")

# Byte offsets in the 0xC0 log the single-line commands read.
_C0_TLC_WRITTEN = 0
_C0_SLC_WRITTEN = 16
_C0_BS_VER_MAJOR = 300
_C0_BS_VER_MINOR = 302


def pack_cloud_log(tlc_written=0, slc_written=0, bs_ver_major=0,
                   bs_ver_minor=0):
    """Build a 0xC0 cloud health log.

    The two written-units counters are 128-bit; only the low 64 bits are set
    here, which is the range a drive reaches in practice.
    """
    buf = bytearray(_C0_SIZE)
    struct.pack_into('<Q', buf, _C0_TLC_WRITTEN, tlc_written)
    struct.pack_into('<Q', buf, _C0_SLC_WRITTEN, slc_written)
    struct.pack_into('<H', buf, _C0_BS_VER_MAJOR, bs_ver_major)
    struct.pack_into('<H', buf, _C0_BS_VER_MINOR, bs_ver_minor)
    return bytes(buf)


class CloudTestBase(TestMicronMock):
    """Shared drive setup for the cloud commands."""

    def setup_cloud_drive(self, model='M51CX', cust_id=CUST_ID_GG,
                          data_units_written=0, log=None):
        self.select_model(model)
        self.server.identify = pack_id_ctrl(cust_id=cust_id)
        self.server.smart = pack_smart_log(
            data_units_written=data_units_written)
        self.server.logs[_LID_CLOUD] = (pack_cloud_log() if log is None
                                        else log)

    def assert_customer_id_gate(self, command):
        """A non-Hyperscale drive must be refused, by name, with an error."""
        self.setup_cloud_drive(cust_id=CUST_ID_GENERIC)
        result = self.run_plugin_cmd(command)

        self.assertNotEqual(
            result.returncode, 0,
            f"micron {command} accepted a drive with a generic customer ID")
        self.assertIn(_UNSUPPORTED_DRIVE_MSG.format(command=command),
                      result.stderr)

    def assert_output_format_ignored(self, command):
        """A command declaring no output formats must ignore the flag."""
        baseline = self.run_plugin_cmd_check(command)
        for value in ("binary", "notaformat"):
            with self.subTest(value=value):
                result = self.run_plugin_cmd(command,
                                             args=f"--output-format={value}")

                self.assertNotIn(
                    "Invalid output format", result.stderr + result.stdout,
                    f"micron {command} does not validate --output-format but "
                    f"rejected {value!r}")
                self.assertEqual(
                    result.stdout, baseline.stdout,
                    f"micron {command} output changed for "
                    f"--output-format={value}")


class TestMicronCloudBootVersion(CloudTestBase):
    """cloud-boot-SSD-version: the boot spec version from the 0xC0 log."""

    def version(self):
        result = self.run_plugin_cmd_check(_BOOT_VERSION)
        m = re.search(
            r"HyperScale Boot Version Spec\.([0-9a-f]+)\.([0-9a-f]+)",
            result.stdout)
        self.assertIsNotNone(
            m, f"no boot version line in stdout: {result.stdout!r}")
        return m.group(1), m.group(2)

    def test_version_is_read_from_the_log(self):
        """Both halves come out of their own field in the log."""
        for major, minor in ((0, 0), (1, 2), (2, 5), (0x0A, 0x0B)):
            with self.subTest(version=(major, minor)):
                self.setup_cloud_drive(
                    log=pack_cloud_log(bs_ver_major=major,
                                       bs_ver_minor=minor))

                self.assertEqual(self.version(), (f"{major:x}", f"{minor:x}"))

    def test_version_is_printed_in_hex(self):
        """The version halves are rendered as hex, not decimal."""
        self.setup_cloud_drive(log=pack_cloud_log(bs_ver_major=0x1F,
                                                  bs_ver_minor=0x2A))

        self.assertEqual(self.version(), ("1f", "2a"))

    def test_any_model_is_accepted(self):
        """Only the customer ID gates this command, not the model."""
        for model in ('M51CX', 'M51BX', 'M5407', 'M6001'):
            with self.subTest(model=model):
                self.setup_cloud_drive(model=model,
                                       log=pack_cloud_log(bs_ver_major=3))

                self.assertEqual(self.version()[0], "3")

    def test_unknown_model_is_accepted(self):
        """The command reads no model, so an unrecognised drive still works."""
        self.setup_cloud_drive(model=None,
                               log=pack_cloud_log(bs_ver_major=4))

        self.assertEqual(self.version()[0], "4")

    def test_customer_id_gate(self):
        self.assert_customer_id_gate(_BOOT_VERSION)

    def test_log_failure_is_reported(self):
        """A Hyperscale drive that cannot read 0xC0 fails."""
        self.setup_cloud_drive(log=SC_INVALID_LOG_PAGE)
        result = self.run_plugin_cmd(_BOOT_VERSION)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid Log Page", result.stderr)

    def test_output_format_is_ignored(self):
        self.setup_cloud_drive(log=pack_cloud_log(bs_ver_major=1))
        self.assert_output_format_ignored(_BOOT_VERSION)

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_BOOT_VERSION)


class TestMicronDeviceWaf(CloudTestBase):
    """vs-device-waf: host writes divided by the NAND writes behind them."""

    def factor(self):
        result = self.run_plugin_cmd_check(_DEVICE_WAF)
        m = re.search(r"Write Amplification Factor (\S+)", result.stdout)
        self.assertIsNotNone(
            m, f"no write amplification line in stdout: {result.stdout!r}")
        return m.group(1)

    def test_factor_is_written_over_nand_writes(self):
        """The factor is the host writes divided by TLC plus SLC writes."""
        cases = (
            (100, 50, 50, "1"),
            (300, 100, 50, "2"),
            (1000, 100, 100, "5"),
            (7, 1, 0, "7"),
        )
        for written, tlc, slc, expected in cases:
            with self.subTest(written=written, tlc=tlc, slc=slc):
                self.setup_cloud_drive(
                    data_units_written=written,
                    log=pack_cloud_log(tlc_written=tlc, slc_written=slc))

                self.assertEqual(self.factor(), expected)

    def test_both_nand_counters_are_summed(self):
        """SLC and TLC writes both count toward the denominator."""
        self.setup_cloud_drive(
            data_units_written=100,
            log=pack_cloud_log(tlc_written=10, slc_written=10))

        self.assertEqual(self.factor(), "5")

    def test_factor_is_rounded_to_a_whole_number(self):
        """The value prints with no fractional part."""
        self.setup_cloud_drive(
            data_units_written=10,
            log=pack_cloud_log(tlc_written=3, slc_written=0))

        self.assertEqual(self.factor(), "3")

    def test_factor_below_one_rounds_toward_zero(self):
        """A drive writing less than its NAND does reports a small factor."""
        self.setup_cloud_drive(
            data_units_written=1,
            log=pack_cloud_log(tlc_written=100, slc_written=0))

        self.assertEqual(self.factor(), "0")

    def test_zero_nand_writes_has_no_defined_factor(self):
        """A drive reporting no NAND writes leaves the ratio undefined.

        The denominator is unguarded, so the printed value is whatever
        dividing by zero yields rather than a number; the command still
        completes, which is what is asserted here.
        """
        self.setup_cloud_drive(data_units_written=100,
                               log=pack_cloud_log(tlc_written=0,
                                                  slc_written=0))
        result = self.run_plugin_cmd_check(_DEVICE_WAF)

        self.assertIn("Write Amplification Factor", result.stdout)

    def test_any_model_is_accepted(self):
        """Only the customer ID gates this command, not the model."""
        for model in ('M51CX', 'M51BX', 'M5410', None):
            with self.subTest(model=model or 'UNKNOWN'):
                self.setup_cloud_drive(
                    model=model, data_units_written=100,
                    log=pack_cloud_log(tlc_written=25, slc_written=25))

                self.assertEqual(self.factor(), "2")

    def test_customer_id_gate(self):
        self.assert_customer_id_gate(_DEVICE_WAF)

    def test_smart_log_failure_is_reported(self):
        """The host write count comes from the SMART log, which can fail."""
        self.setup_cloud_drive()
        self.server.logs[0x02] = SC_INVALID_LOG_PAGE
        result = self.run_plugin_cmd(_DEVICE_WAF)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nvme_smart_log() failed", result.stderr)

    def test_cloud_log_failure_is_reported(self):
        self.setup_cloud_drive(log=SC_INVALID_LOG_PAGE)
        result = self.run_plugin_cmd(_DEVICE_WAF)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Failed to get extended smart log", result.stderr)

    def test_output_format_is_ignored(self):
        self.setup_cloud_drive(data_units_written=10,
                               log=pack_cloud_log(tlc_written=10))
        self.assert_output_format_ignored(_DEVICE_WAF)

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_DEVICE_WAF)


class TestMicronCloudLog(CloudTestBase):
    """vs-cloud-log: the cloud health log as a field table."""

    def test_model_gate_is_m51cx_only(self):
        """Every other model is refused, whatever its customer ID."""
        for model in ('M51BX', 'M51BY', 'M51CY', 'M5407', 'M6001', None):
            with self.subTest(model=model or 'UNKNOWN'):
                self.setup_cloud_drive(model=model)
                result = self.run_plugin_cmd(_CLOUD_LOG)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(_UNSUPPORTED_MODEL_MSG, result.stderr)

    def test_model_gate_precedes_the_customer_id_gate(self):
        """A non-M51CX cloud SSD reports the model, not the customer ID."""
        self.setup_cloud_drive(model='M51BX', cust_id=CUST_ID_GG)
        result = self.run_plugin_cmd(_CLOUD_LOG)

        self.assertIn(_UNSUPPORTED_MODEL_MSG, result.stderr)
        self.assertNotIn(_UNSUPPORTED_DRIVE_MSG.format(command=_CLOUD_LOG),
                         result.stderr)

    def test_customer_id_gate(self):
        self.assert_customer_id_gate(_CLOUD_LOG)

    def test_text_field_table(self):
        """Text output is a well-formed '<label> : 0x<hex>' table."""
        self.setup_cloud_drive()
        result = self.run_plugin_cmd_check(_CLOUD_LOG)

        self.hex_fields_from_table(result.stdout, _CLOUD_LOG)

    def test_json_field_object(self):
        """JSON output reports the log under one top-level key."""
        self.setup_cloud_drive()
        data = self.run_plugin_cmd_json(_CLOUD_LOG)

        self.hex_fields_from_json(data, _CLOUD_JSON_KEYS, _CLOUD_LOG)

    def test_text_and_json_report_the_same_fields(self):
        """Both formats parse the same log, so they must agree."""
        self.setup_cloud_drive(log=pack_cloud_log(tlc_written=0x1234,
                                                  slc_written=0x5678))
        text = self.hex_fields_from_table(
            self.run_plugin_cmd_check(_CLOUD_LOG).stdout, _CLOUD_LOG)
        json_fields = self.hex_fields_from_json(
            self.run_plugin_cmd_json(_CLOUD_LOG), _CLOUD_JSON_KEYS,
            _CLOUD_LOG)

        self.assertEqual(text, json_fields)

    def test_field_values_follow_the_log_contents(self):
        """A changed log changes the reported fields, not just their names."""
        self.setup_cloud_drive(log=pack_cloud_log(tlc_written=0))
        zeros = self.hex_fields_from_json(
            self.run_plugin_cmd_json(_CLOUD_LOG), _CLOUD_JSON_KEYS)

        self.setup_cloud_drive(log=pack_cloud_log(tlc_written=0xABCD))
        changed = self.hex_fields_from_json(
            self.run_plugin_cmd_json(_CLOUD_LOG), _CLOUD_JSON_KEYS)

        self.assertEqual(set(zeros), set(changed))
        self.assertNotEqual(zeros, changed,
                            "the reported fields ignored the log contents")

    def test_log_failure_is_reported(self):
        self.setup_cloud_drive(log=SC_INVALID_LOG_PAGE)
        result = self.run_plugin_cmd(_CLOUD_LOG)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid Log Page", result.stderr)

    def test_binary_output_format_rejected(self):
        """The command declares normal|json, so binary is refused."""
        self.setup_cloud_drive()
        self.check_output_format_rejected(_CLOUD_LOG, "binary")

    def test_invalid_output_format_returns_error(self):
        self.setup_cloud_drive()
        self.check_output_format_rejected(_CLOUD_LOG, "notaformat")

    def test_output_format_is_checked_before_both_gates(self):
        """The format check runs on any drive, gated or not."""
        self.setup_cloud_drive(model=None, cust_id=CUST_ID_GENERIC)
        result = self.run_plugin_cmd(_CLOUD_LOG,
                                     args="--output-format=notaformat")

        self.assertIn("Invalid output format", result.stderr)
        self.assertNotIn(_UNSUPPORTED_MODEL_MSG, result.stderr)

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_CLOUD_LOG)


if __name__ == '__main__':
    main()
