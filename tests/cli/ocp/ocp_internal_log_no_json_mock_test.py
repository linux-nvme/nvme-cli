#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp internal-log" in a build without json-c.

Without json-c there is no JSON printer, so the report is decoded as
normal text by default and -o json is not an accepted format. The other
internal-log suites go through -o json and run only in builds with
json-c; this one runs only in builds without it.

Tests in this module verify:
  * With no -o, the log is decoded to the .txt report and no .json one,
    covering the Data Area 1 statistics and event FIFOs.
  * The default report is the one -o normal writes.
  * -a 2 adds the Data Area 2 statistics and event FIFOs.
  * -o json is rejected without writing a report.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_internal_log_no_json_mock_test.py <nvme-binary> <mock-lib>
"""
import os

from tests.cli.ocp.ocp_internal_log_mock_test import string_log, telemetry_log
from tests.cli.ocp.ocp_mock_test import (MODES, STR_DA_STATS,
                                         OCPInternalLogTestBase, main,
                                         parse_text_report, text_records)


class TestInternalLogWithoutJson(OCPInternalLogTestBase):
    """Output format handling when the JSON printer is not built."""

    def decode_default(self, *args):
        """Decode the fixtures with no -o; return the parsed .txt report
        and the run's stdout."""
        result = self.assertOk(self.run_internal_log(
            *args, telemetry=telemetry_log(), strings=string_log()))
        self.assertFalse(os.path.exists(self.report_path('json')))
        path = self.report_path('text')
        self.assertTrue(os.path.exists(path), f'{path} was not written')
        with open(path, encoding='utf-8') as f:
            return parse_text_report(f.read()), result.stdout

    def assert_data_area(self, report, da, stat_id, fifo):
        stats = text_records(self.section(report, STR_DA_STATS.format(da)))
        self.assertIn(stat_id,
                      [s.get('Statistics Identifier') for s in stats])
        titles = self.fifo_titles(report, da)
        self.assertEqual(len(titles), 1, titles)
        self.assertTrue(titles[0].startswith(f'EVENT FIFO {fifo} - '),
                        titles)

    def test_default_format_is_normal(self):
        report, stdout = self.decode_default()
        self.assertIn('Using default format - normal.', stdout)
        self.section(report, 'Log Page Header')
        self.assert_data_area(report, 1, '0x22', 1)
        self.assertNotIn(STR_DA_STATS.format(2),
                         [name for name, _ in report])

    def test_default_matches_explicit_normal(self):
        default, _ = self.decode_default()
        explicit = self.decode(telemetry_log(), string_log(), mode='text')
        self.assertEqual(default, explicit)

    def test_data_area_2(self):
        report, _ = self.decode_default('-a', '2')
        self.assert_data_area(report, 1, '0x22', 1)
        self.assert_data_area(report, 2, '0x23', 2)

    def test_json_is_rejected(self):
        result = self.run_internal_log('-o', 'json',
                                       telemetry=telemetry_log(),
                                       strings=string_log())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Invalid output format', result.stderr)
        for mode in MODES:
            self.assertFalse(os.path.exists(self.report_path(mode)))


if __name__ == '__main__':
    main()
