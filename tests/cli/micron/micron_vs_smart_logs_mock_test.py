#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron vendor log commands that render a field table.

vs-smart-ext-log, vs-work-load-log, vs-vendor-telemetry-log, vs-nand-stats
and vs-smart-add-log all read one vendor log page and render it through the
shared field-table path: a "<label> : 0x<hex>" line per field in text mode, or
one top-level key holding a one-element array of field objects in JSON mode.

Which log page each reads, and which top-level key it reports it under,
depends on the drive model -- and for vs-nand-stats also on the customer ID.

Tests in this module verify:
  * The log page each command reads for each model that accepts it.
  * The top-level JSON key per model, which selects the field layout.
  * Text and JSON reporting identical fields and values.
  * Field values following the log contents rather than being constant.
  * A log the drive rejects being reported rather than printed as zeros.
  * --output-format=binary and an unrecognised format both being refused,
    before the model gate.
  * Error handling for a non-existent device.

Usage: python3 micron_vs_smart_logs_mock_test.py <nvme-binary> <mock-lib>
"""

from micron_mock_test import (
    CUST_ID_GENERIC,
    CUST_ID_GG,
    SC_INVALID_LOG_PAGE,
    TestMicronMock,
    main,
    pack_id_ctrl,
)

_EXT_LOG = "vs-smart-ext-log"
_WORK_LOAD = "vs-work-load-log"
_VENDOR_TELEMETRY = "vs-vendor-telemetry-log"
_NAND_STATS = "vs-nand-stats"
_SMART_ADD = "vs-smart-add-log"

# Log page sizes the commands request, from the plugin's size macros.
_SIZES = {0xC0: 512, 0xC5: 256, 0xC6: 512, 0xD0: 512, 0xE1: 256, 0xFB: 512}


def log_payload(lid, fill=0xA5):
    """Build a log page of the size the plugin reads, with recognisable
    contents so a field value can be told from a zero."""
    return bytes([fill]) * _SIZES[lid]


class SmartLogsTestBase(TestMicronMock):
    """Shared helpers for the field-table log commands."""

    def provide(self, *lids, fill=0xA5):
        for lid in lids:
            self.server.logs[lid] = log_payload(lid, fill)

    def text_fields(self, command, device=None):
        result = self.run_plugin_cmd_check(command, device=device)
        return self.hex_fields_from_table(result.stdout, command)

    def json_fields(self, command, allowed_keys, device=None):
        data = self.run_plugin_cmd_json(command, device=device)
        return self.hex_fields_from_json(data, allowed_keys, command)

    def json_key(self, command):
        """Return the single top-level key the JSON output used."""
        data = self.run_plugin_cmd_json(command)
        self.assertEqual(len(data), 1,
                         f"expected one top-level key, got {list(data)}")
        return next(iter(data))

    def assert_formats_rejected(self, command):
        """The command declares normal|json and refuses anything else.

        The format check precedes the model gate, so it runs on any drive.
        """
        for value in ("binary", "notaformat"):
            with self.subTest(value=value):
                self.check_output_format_rejected(command, value)

    def assert_text_and_json_agree(self, command, allowed_keys):
        text = self.text_fields(command)
        json_fields = self.json_fields(command, allowed_keys)

        self.assertEqual(text, json_fields,
                         f"micron {command} text and JSON output differ")

    def assert_values_follow_the_log(self, command, lid, allowed_keys):
        """A different log must produce different field values."""
        self.provide(lid, fill=0x00)
        zeros = self.json_fields(command, allowed_keys)

        self.provide(lid, fill=0x5A)
        changed = self.json_fields(command, allowed_keys)

        self.assertEqual(set(zeros), set(changed))
        self.assertNotEqual(zeros, changed,
                            f"micron {command} ignored the log contents")


class TestMicronVsSmartExtLog(SmartLogsTestBase):
    """vs-smart-ext-log: 0xE1 on most models, 0xD0 on M6001."""

    _JSON_KEYS = ("SMART Extended Log:0xE1", "SMART Extended Log:0xD0")

    def test_log_page_per_model(self):
        """The model chooses which extended SMART log is read."""
        cases = {
            'M51CX': 0xE1, 'M51BY': 0xE1, 'M51CY': 0xE1,
            'M6003': 0xE1, 'M6004': 0xE1,
            'M6001': 0xD0,
        }
        for model, lid in cases.items():
            with self.subTest(model=model):
                self.select_model(model)
                self.provide(lid)
                self.server.commands.clear()
                self.run_plugin_cmd_check(_EXT_LOG)

                self.assertEqual(self.server.lids_read(), {lid})

    def test_json_key_names_the_log_page_read(self):
        """The top-level key reports which page the values came from."""
        for model, expected in (('M51CX', "SMART Extended Log:0xE1"),
                                ('M6001', "SMART Extended Log:0xD0")):
            with self.subTest(model=model):
                self.select_model(model)
                self.provide(0xE1, 0xD0)

                self.assertEqual(self.json_key(_EXT_LOG), expected)

    def test_text_field_table(self):
        self.select_model('M51CX')
        self.provide(0xE1)

        self.text_fields(_EXT_LOG)

    def test_text_and_json_agree(self):
        self.select_model('M51CX')
        self.provide(0xE1)
        self.assert_text_and_json_agree(_EXT_LOG, self._JSON_KEYS)

    def test_values_follow_the_log(self):
        self.select_model('M51CX')
        self.assert_values_follow_the_log(_EXT_LOG, 0xE1, self._JSON_KEYS)

    def test_missing_log_is_reported(self):
        self.select_model('M51CX')
        self.server.logs[0xE1] = SC_INVALID_LOG_PAGE
        result = self.run_plugin_cmd(_EXT_LOG)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid Log Page", result.stderr)

    def test_namespace_path_matches_the_controller_path(self):
        self.select_model('M51CX')
        self.provide(0xE1)

        self.assertEqual(self.json_fields(_EXT_LOG, self._JSON_KEYS,
                                          device=self.ctrl),
                         self.json_fields(_EXT_LOG, self._JSON_KEYS,
                                          device=self.ns1))

    def test_output_formats_rejected(self):
        self.assert_formats_rejected(_EXT_LOG)

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_EXT_LOG)


class TestMicronVsWorkLoadLog(SmartLogsTestBase):
    """vs-work-load-log: the 0xC5 workload log on the M600x family."""

    _JSON_KEYS = ("Micron Workload Log:0xC5",)
    _MODELS = ('M6001', 'M6003', 'M6004')

    def test_reads_the_workload_log(self):
        for model in self._MODELS:
            with self.subTest(model=model):
                self.select_model(model)
                self.provide(0xC5)
                self.server.commands.clear()
                self.run_plugin_cmd_check(_WORK_LOAD)

                self.assertEqual(self.server.lids_read(), {0xC5})

    def test_text_and_json_agree(self):
        self.select_model('M6001')
        self.provide(0xC5)
        self.assert_text_and_json_agree(_WORK_LOAD, self._JSON_KEYS)

    def test_values_follow_the_log(self):
        self.select_model('M6001')
        self.assert_values_follow_the_log(_WORK_LOAD, 0xC5, self._JSON_KEYS)

    def test_missing_log_is_reported(self):
        self.select_model('M6001')
        self.server.logs[0xC5] = SC_INVALID_LOG_PAGE
        result = self.run_plugin_cmd(_WORK_LOAD)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid Log Page", result.stderr)

    def test_output_formats_rejected(self):
        self.assert_formats_rejected(_WORK_LOAD)

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_WORK_LOAD)


class TestMicronVsVendorTelemetryLog(SmartLogsTestBase):
    """vs-vendor-telemetry-log: the 0xC6 log on the M600x family."""

    _JSON_KEYS = ("Vendor Telemetry Log:0xC6",)
    _MODELS = ('M6001', 'M6003', 'M6004')

    def test_reads_the_vendor_telemetry_log(self):
        for model in self._MODELS:
            with self.subTest(model=model):
                self.select_model(model)
                self.provide(0xC6)
                self.server.commands.clear()
                self.run_plugin_cmd_check(_VENDOR_TELEMETRY)

                self.assertEqual(self.server.lids_read(), {0xC6})

    def test_text_and_json_agree(self):
        self.select_model('M6001')
        self.provide(0xC6)
        self.assert_text_and_json_agree(_VENDOR_TELEMETRY, self._JSON_KEYS)

    def test_values_follow_the_log(self):
        self.select_model('M6001')
        self.assert_values_follow_the_log(_VENDOR_TELEMETRY, 0xC6,
                                          self._JSON_KEYS)

    def test_missing_log_is_reported(self):
        self.select_model('M6001')
        self.server.logs[0xC6] = SC_INVALID_LOG_PAGE
        result = self.run_plugin_cmd(_VENDOR_TELEMETRY)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid Log Page", result.stderr)

    def test_output_formats_rejected(self):
        self.assert_formats_rejected(_VENDOR_TELEMETRY)

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_VENDOR_TELEMETRY)


class TestMicronVsNandStats(SmartLogsTestBase):
    """vs-nand-stats: one of three logs, chosen by model and customer ID."""

    _JSON_KEYS = ("Extended Smart Log Page : 0xC0",
                  "Extended Smart Log Page : 0xFB",
                  "Extended Smart Log Page : 0xD0")

    def setup_drive(self, model='M51CX', cust_id=CUST_ID_GENERIC):
        self.select_model(model)
        self.server.identify = pack_id_ctrl(cust_id=cust_id)

    def test_hyperscale_m51cx_reads_the_cloud_log(self):
        """A Hyperscale M51CX reports the 0xC0 cloud log."""
        self.setup_drive(model='M51CX', cust_id=CUST_ID_GG)
        self.provide(0xC0, 0xD0, 0xFB)

        self.assertEqual(self.json_key(_NAND_STATS),
                         "Extended Smart Log Page : 0xC0")

    def test_vendor_health_log_is_preferred_when_present(self):
        """Off the Hyperscale path the 0xFB log wins over 0xD0."""
        self.setup_drive(model='M51BX')
        self.provide(0xD0, 0xFB)

        self.assertEqual(self.json_key(_NAND_STATS),
                         "Extended Smart Log Page : 0xFB")

    def test_falls_back_to_the_d0_log(self):
        """A drive without 0xFB reports the 0xD0 counters."""
        self.setup_drive(model='M51BX')
        self.provide(0xD0)

        self.assertEqual(self.json_key(_NAND_STATS),
                         "Extended Smart Log Page : 0xD0")

    def test_legacy_models_never_read_the_vendor_health_log(self):
        """M5407 and M5410 are not asked for 0xFB at all."""
        for model in ('M5407', 'M5410'):
            with self.subTest(model=model):
                self.setup_drive(model=model)
                self.provide(0xD0, 0xFB)
                self.server.commands.clear()
                self.run_plugin_cmd_check(_NAND_STATS)

                self.assertNotIn(0xFB, self.server.lids_read())
                self.assertEqual(self.json_key(_NAND_STATS),
                                 "Extended Smart Log Page : 0xD0")

    def test_generic_customer_id_does_not_read_the_cloud_log(self):
        """The 0xC0 path needs the Hyperscale customer ID as well as M51CX."""
        self.setup_drive(model='M51CX', cust_id=CUST_ID_GENERIC)
        self.provide(0xC0, 0xD0)
        self.server.commands.clear()
        self.run_plugin_cmd_check(_NAND_STATS)

        self.assertNotIn(0xC0, self.server.lids_read())

    def test_text_and_json_agree(self):
        self.setup_drive(model='M51BX')
        self.provide(0xD0)
        self.assert_text_and_json_agree(_NAND_STATS, self._JSON_KEYS)

    def test_values_follow_the_log(self):
        self.setup_drive(model='M51BX')
        self.assert_values_follow_the_log(_NAND_STATS, 0xD0, self._JSON_KEYS)

    def test_identify_failure_is_reported(self):
        """The customer ID comes from identify, which can fail."""
        self.setup_drive()
        self.server.identify_status = SC_INVALID_LOG_PAGE
        result = self.run_plugin_cmd(_NAND_STATS)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid Log Page", result.stderr)

    def test_namespace_path_matches_the_controller_path(self):
        self.setup_drive(model='M51BX')
        self.provide(0xD0)

        self.assertEqual(self.json_fields(_NAND_STATS, self._JSON_KEYS,
                                          device=self.ctrl),
                         self.json_fields(_NAND_STATS, self._JSON_KEYS,
                                          device=self.ns1))

    def test_output_formats_rejected(self):
        self.assert_formats_rejected(_NAND_STATS)

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_NAND_STATS)


class TestMicronVsSmartAddLog(SmartLogsTestBase):
    """vs-smart-add-log: the 0xFB legacy log or the 0xC0 cloud log."""

    # The 0xC0 rendering differs per model family, and so does its key.
    _OCP_KEY = "OCP SMART Cloud Health Log: 0xC0"
    _DATACENTER_KEY = "OCP DataCenter SMART Health Log: 0xC0"
    _JSON_KEYS = (_OCP_KEY, _DATACENTER_KEY)

    def test_legacy_models_read_the_vendor_health_log(self):
        """M5410 and M5407 report the 0xFB log instead of 0xC0."""
        for model in ('M5410', 'M5407'):
            with self.subTest(model=model):
                self.select_model(model)
                self.provide(0xFB, 0xC0)
                self.server.commands.clear()
                self.run_plugin_cmd_check(_SMART_ADD)

                self.assertIn(0xFB, self.server.lids_read())
                self.assertNotIn(0xC0, self.server.lids_read())

    def test_cloud_models_read_the_cloud_log(self):
        for model in ('M51CX', 'M51BY', 'M51CY', 'M6003', 'M6004'):
            with self.subTest(model=model):
                self.select_model(model)
                self.provide(0xC0)
                self.server.commands.clear()
                self.run_plugin_cmd_check(_SMART_ADD)

                self.assertEqual(self.server.lids_read(), {0xC0})

    def test_cloud_log_key_depends_on_the_model_family(self):
        """M51CX uses the OCP layout; M51BY and M51CY the datacenter one."""
        for model, expected in (('M51CX', self._OCP_KEY),
                                ('M51BY', self._DATACENTER_KEY),
                                ('M51CY', self._DATACENTER_KEY)):
            with self.subTest(model=model):
                self.select_model(model)
                self.provide(0xC0)

                self.assertEqual(self.json_key(_SMART_ADD), expected)

    def test_field_layouts_differ_between_the_two_families(self):
        """The two layouts describe the same log with different fields."""
        self.select_model('M51CX')
        self.provide(0xC0)
        ocp = self.json_fields(_SMART_ADD, self._JSON_KEYS)

        self.select_model('M51BY')
        self.provide(0xC0)
        datacenter = self.json_fields(_SMART_ADD, self._JSON_KEYS)

        self.assertNotEqual(set(ocp), set(datacenter))

    def test_text_and_json_agree(self):
        self.select_model('M51CX')
        self.provide(0xC0)
        self.assert_text_and_json_agree(_SMART_ADD, self._JSON_KEYS)

    def test_values_follow_the_log(self):
        self.select_model('M51CX')
        self.assert_values_follow_the_log(_SMART_ADD, 0xC0, self._JSON_KEYS)

    def test_missing_cloud_log_is_reported(self):
        self.select_model('M51CX')
        self.server.logs[0xC0] = SC_INVALID_LOG_PAGE
        result = self.run_plugin_cmd(_SMART_ADD)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid Log Page", result.stderr)

    def test_missing_legacy_log_is_reported(self):
        self.select_model('M5410')
        self.server.logs[0xFB] = SC_INVALID_LOG_PAGE
        result = self.run_plugin_cmd(_SMART_ADD)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid Log Page", result.stderr)

    def test_output_formats_rejected(self):
        self.assert_formats_rejected(_SMART_ADD)

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_SMART_ADD)


if __name__ == '__main__':
    main()
