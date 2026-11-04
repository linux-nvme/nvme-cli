#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp latency-monitor-log" against a mocked controller.

The mock serves a synthetic C3h Latency Monitor page built by
tests/e2e/plugins/ocp/ocp_c3_layout.py, transcribed from the OCP
specification rather than from nvme-cli's struct.

Tests in this module verify:
  * The page is read as LID C3h, 512 bytes, with the OCP UUID index.
  * --no-uuid reads it with UUID index 0, without looking the OCP UUID up.
  * The Latency Monitor Feature Status (LMDATA-1) is shown raw in text and
    JSON.
  * Every scalar field decodes from its offset with the scaling the
    specification gives it, in text and JSON.
  * The Bucket Counters, Latency Stamps and Measured Latencies of each
    bucket and counter, Active and Static, map as the specification lays
    them out, a stamp of all FFh shows as not valid, and the Timestamp
    attributes in byte 6 of a stamp are not part of its time.
  * The Debug Telemetry Log Size is left out below log page version 4 and
    is shown in hex without its leading zero bytes from version 4.
  * A successful read reports no NVMe status.
  * A failed Get Log Page, a controller without the OCP UUID and a page
    with a different GUID fail, naming the cause in text and reporting
    only the error under -o json, plus the NVMe status for a failed Get
    Log Page; a different GUID is reported with the expected and actual
    GUIDs on one line; without the OCP UUID nothing is read.

A known defect is covered by an expectedFailure test asserting the
behavior the specification defines: a Latency Stamp whose Stamp Units bit
is cleared, which counts from power on, is shown as a date.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_latency_monitor_log_mock_test.py <nvme-binary> <mock-lib>
"""
import json
import re
import struct
import unittest
from datetime import datetime, timezone

from tests.cli.nvme_mock import CNS_UUID_LIST, main
from tests.cli.ocp.ocp_mock_test import OCPMockTestBase
from tests.e2e.plugins.ocp import ocp_c3_layout as layout

UNKNOWN_GUID_MSG = 'Unknown GUID in C3 Log Page data'

FEATURE_STATUS_RE = re.compile(r'^\s*Feature Status\s+0x([0-9a-f]+)$', re.M)


class LatencyMonitorLogTestBase(OCPMockTestBase):

    def serve(self, page):
        self.server.logs = {layout.LID: page}

    def run_c3(self, *args):
        return self.run_ocp('latency-monitor-log', *args)

    def json_log(self, *args):
        result = self.assertOk(self.run_c3('-o', 'json', *args))
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f'-o json output is not valid JSON ({exc}): '
                      f'{result.stdout!r}')


class TestLatencyMonitorLog(LatencyMonitorLogTestBase):

    def test_page_is_read_with_the_ocp_uuid_index(self):
        self.serve(layout.pack())
        self.server.uuid_slot = 1
        self.assertOk(self.run_c3())
        reads = self.server.log_reads(layout.LID)
        self.assertEqual(len(reads), 1, reads)
        self.assertEqual(reads[0].data_len, layout.DEFINED_SIZE)
        self.assertEqual(reads[0].cdw14 & 0x7F, 2)

    def test_no_uuid_reads_with_uuid_index_0(self):
        self.serve(layout.pack())
        self.server.uuid_slot = 1
        self.assertOk(self.run_c3('--no-uuid'))
        reads = self.server.log_reads(layout.LID)
        self.assertEqual(len(reads), 1, reads)
        self.assertEqual(reads[0].data_len, layout.DEFINED_SIZE)
        self.assertEqual(reads[0].cdw14 & 0x7F, 0)
        self.assertEqual(self.server.identifies(CNS_UUID_LIST), [])

    def test_feature_status_is_shown_raw(self):
        for status in (0x00, 0x06, 0x1F, 0xFF):
            with self.subTest(status=f'{status:#04x}'):
                self.serve(layout.pack(feature_status=status))
                text = self.assertOk(self.run_c3()).stdout
                values = FEATURE_STATUS_RE.findall(text)
                self.assertEqual(values, [f'{status:x}'], text)
                log = self.json_log()
                self.assertEqual(log['Feature Status'], status)

    def test_text_output_reports_no_status_line_on_success(self):
        """A successful command has no NVMe status to report."""
        self.serve(layout.pack())
        result = self.assertOk(self.run_c3())
        self.assertNotIn('nvme status', (result.stdout + result.stderr).lower())


GUID_TEXT = layout.GUID_BYTES[::-1].hex().upper()
SETS = {
    'Active': (layout.ACTIVE_BUCKET_COUNTER, layout.ACTIVE_LATENCY_STAMP,
               layout.ACTIVE_MEASURED_LATENCY,
               layout.ACTIVE_LATENCY_STAMP_UNITS),
    'Static': (layout.STATIC_BUCKET_COUNTER, layout.STATIC_LATENCY_STAMP,
               layout.STATIC_MEASURED_LATENCY,
               layout.STATIC_LATENCY_STAMP_UNITS),
}
ALL_STAMP_UNITS = 0x0FFF
# 2023-11-14 22:13:20 UTC
BASE_MS = 1_700_000_000_000
DATE_RE = re.compile(r'\d{4}-\d{2}-\d{2}')
DEBUG_STAMP = 'Debug Log Latency Time Stamp'
DEBUG_LOG_SIZE = 'Debug Telemetry Log Size'


def page_with(fields, **pack_args):
    """layout.pack(**@pack_args) with each (offset, struct format, value)
    of @fields packed in."""
    page = bytearray(layout.pack(**pack_args))
    for offset, fmt, value in fields:
        struct.pack_into(fmt, page, offset, value)
    return bytes(page)


def each_counter():
    for name in SETS:
        for bucket in range(layout.BUCKETS):
            for counter in layout.COUNTERS:
                yield name, bucket, counter


def stamp_text(ms):
    """A valid Latency Stamp of @ms milliseconds as shr_format_ts() shows
    it."""
    when = datetime.fromtimestamp(ms // 1000, tz=timezone.utc)
    return f'{when:%Y-%m-%dD|%H:%M:%S}:{ms % 1000:03d}'


class LatencyMonitorLogDecodeTestBase(LatencyMonitorLogTestBase):

    def reports(self, page):
        """The text and the JSON report of @page."""
        self.serve(page)
        text = self.assertOk(self.run_c3()).stdout
        return text, self.json_log()

    def text_value(self, text, label):
        """The value of the "label   value" line of @label. Two or more
        spaces end the label, so "Active Bucket Timer" leaves "Active
        Bucket Timer Threshold" alone."""
        values = re.findall(rf'^\s*{re.escape(label)}\s{{2,}}(.*?)\s*$',
                            text, re.M)
        self.assertEqual(len(values), 1, f'{label!r} in {text!r}')
        return values[0]

    def text_row(self, text, name):
        """The words after @name on its bucket row."""
        rows = re.findall(rf'^\s*{re.escape(name)}\s+(.*)$', text, re.M)
        self.assertEqual(len(rows), 1, f'{name!r} in {text!r}')
        return rows[0].split()

    def text_stamps(self, text, name, bucket):
        """Read, Write and Trim Latency Stamp of @bucket in @name's set."""
        words = self.text_row(
            text, f'{name} Latency Time Stamp: Bucket {bucket}')
        self.assertEqual(len(words), len(layout.COUNTERS), words)
        return dict(zip(layout.COUNTERS, words))

    def json_stamps(self, log, name, bucket):
        return log[f'{name} Latency Time Stamp: Bucket {bucket}']


class TestLatencyMonitorLogFields(LatencyMonitorLogDecodeTestBase):

    # Label in both reports, offset, struct format, raw value, text, JSON.
    SCALARS = (
        # 5 minute steps
        ('Active Bucket Timer', layout.ACTIVE_BUCKET_TIMER, '<H', 0x0003,
         '15 min', 15),
        ('Active Bucket Timer Threshold',
         layout.ACTIVE_BUCKET_TIMER_THRESHOLD, '<H', 0x07E0,
         '10080 min', 10080),
        # 5 ms steps, 00h being 5 ms and FFh 1.280 s
        ('Active Threshold A', layout.ACTIVE_THRESHOLD_A, 'B', 0x01,
         '10 ms', 10),
        ('Active Threshold B', layout.ACTIVE_THRESHOLD_B, 'B', 0x13,
         '100 ms', 100),
        ('Active Threshold C', layout.ACTIVE_THRESHOLD_C, 'B', 0x1E,
         '155 ms', 155),
        ('Active Threshold D', layout.ACTIVE_THRESHOLD_D, 'B', 0xFF,
         '1280 ms', 1280),
        ('Active Latency Configuration', layout.ACTIVE_LATENCY_CONFIG, '<H',
         0x0A5C, '0xa5c', 0x0A5C),
        # 100 ms steps
        ('Active Latency Minimum Window', layout.ACTIVE_LATENCY_MIN_WINDOW,
         'B', 0x0A, '1000 ms', 1000),
        ('Active Latency Stamp Units', layout.ACTIVE_LATENCY_STAMP_UNITS,
         '<H', 0x0123, '291', 0x0123),
        ('Static Latency Stamp Units', layout.STATIC_LATENCY_STAMP_UNITS,
         '<H', 0x0456, '1110', 0x0456),
        ('Debug Log Trigger Enable', layout.DEBUG_LOG_TRIGGER_ENABLE, '<H',
         0x0789, '1929', 0x0789),
        ('Debug Log Measured Latency', layout.DEBUG_LOG_MEASURED_LATENCY,
         '<H', 0x1234, '4660', 0x1234),
        ('Debug Log Pointer', layout.DEBUG_LOG_POINTER, '<H', 0x00CA,
         '202', 0xCA),
        ('Debug Counter Trigger Source', layout.DEBUG_COUNTER_TRIGGER_SOURCE,
         '<H', 0x0040, '64', 0x40),
        ('Debug Log Stamp Units', layout.DEBUG_LOG_STAMP_UNITS, 'B', 0x01,
         '1', 1),
        ('Log Page Version', layout.LOG_PAGE_VERSION, '<H', 0x0005,
         '5', 5),
    )

    def test_scalar_fields_decode(self):
        text, log = self.reports(page_with(
            (offset, fmt, raw)
            for _, offset, fmt, raw, _, _ in self.SCALARS))
        for label, _, _, _, want_text, want_json in self.SCALARS:
            with self.subTest(label=label):
                self.assertEqual(self.text_value(text, label), want_text)
                self.assertEqual(log[label], want_json)

    def test_guid_is_shown_as_the_specification_writes_it(self):
        text, log = self.reports(layout.pack())
        self.assertEqual(self.text_value(text, 'Log Page GUID'), GUID_TEXT)
        self.assertEqual(log['Log Page GUID'], GUID_TEXT)


class TestLatencyMonitorLogBuckets(LatencyMonitorLogDecodeTestBase):

    @staticmethod
    def _value(name, bucket, counter, width):
        """A value unique to the counter that fits in @width bits, with
        the top bit set."""
        index = list(SETS).index(name) + 1
        shift = width // 4
        return (1 << width - 1 | index << 3 * shift | bucket << 2 * shift |
                layout.COUNTERS.index(counter) + 1)

    def test_bucket_counters_map_per_spec(self):
        fields = []
        for name, bucket, counter in each_counter():
            base = SETS[name][0]
            fields.append((layout.bucket_counter(base, bucket, counter),
                           '<I', self._value(name, bucket, counter, 32)))
            # The reserved dword ahead of the counters.
            fields.append((base + layout.BUCKET_COUNTER_SIZE * bucket, '<I',
                           0xDEADBEEF))
        text, log = self.reports(page_with(fields))
        for name in SETS:
            for bucket in range(layout.BUCKETS):
                key = f'{name} Bucket Counter: Bucket {bucket}'
                want = {c: self._value(name, bucket, c, 32)
                        for c in layout.COUNTERS}
                with self.subTest(key=key):
                    words = self.text_row(text, key)
                    self.assertEqual(
                        dict(zip(layout.COUNTERS, map(int, words))), want)
                    self.assertEqual(log[key], want)

    def test_measured_latencies_map_per_spec(self):
        fields = [(layout.measured_latency(SETS[name][2], bucket, counter),
                   '<H', self._value(name, bucket, counter, 16))
                  for name, bucket, counter in each_counter()]
        text, log = self.reports(page_with(fields))
        for name in SETS:
            for bucket in range(layout.BUCKETS):
                key = f'{name} Measured Latency: Bucket {bucket}'
                want = {c: self._value(name, bucket, c, 16)
                        for c in layout.COUNTERS}
                with self.subTest(key=key):
                    words = self.text_row(text, key)
                    self.assertEqual(words[1::2], ['ms'] * 3, words)
                    self.assertEqual(
                        dict(zip(layout.COUNTERS, map(int, words[::2]))),
                        want)
                    self.assertEqual(log[key], want)

    @staticmethod
    def _stamp_ms(name, bucket, counter):
        index = list(SETS).index(name)
        return (BASE_MS + index * 86_400_000 + bucket * 3_600_000 +
                layout.COUNTERS.index(counter) * 60_000 +
                100 * index + 10 * bucket + layout.COUNTERS.index(counter))

    def test_latency_stamps_map_per_spec(self):
        debug_ms = BASE_MS + 7 * 86_400_000 + 123
        fields = [(layout.latency_stamp(SETS[name][1], bucket, counter),
                   '<Q', layout.stamp(self._stamp_ms(name, bucket, counter)))
                  for name, bucket, counter in each_counter()]
        fields += [(SETS[name][3], '<H', ALL_STAMP_UNITS) for name in SETS]
        fields += [(layout.DEBUG_LOG_LATENCY_STAMP, '<Q',
                    layout.stamp(debug_ms)),
                   (layout.DEBUG_LOG_STAMP_UNITS, 'B', 1)]
        text, log = self.reports(page_with(fields))
        for name in SETS:
            for bucket in range(layout.BUCKETS):
                want = {c: stamp_text(self._stamp_ms(name, bucket, c))
                        for c in layout.COUNTERS}
                with self.subTest(set=name, bucket=bucket):
                    self.assertEqual(self.text_stamps(text, name, bucket),
                                     want)
                    self.assertEqual(self.json_stamps(log, name, bucket),
                                     want)
        self.assertEqual(self.text_value(text, DEBUG_STAMP),
                         stamp_text(debug_ms))
        self.assertEqual(log[DEBUG_STAMP], stamp_text(debug_ms))


class TestLatencyMonitorLogStamps(LatencyMonitorLogDecodeTestBase):

    def _stamped_page(self, active_units, static_units, debug_units,
                      stamp_for, debug_stamp):
        fields = [(layout.latency_stamp(SETS[name][1], bucket, counter),
                   '<Q', stamp_for(name, bucket, counter))
                  for name, bucket, counter in each_counter()]
        fields += [
            (layout.ACTIVE_LATENCY_STAMP_UNITS, '<H', active_units),
            (layout.STATIC_LATENCY_STAMP_UNITS, '<H', static_units),
            (layout.DEBUG_LOG_STAMP_UNITS, 'B', debug_units),
            (layout.DEBUG_LOG_LATENCY_STAMP, '<Q', debug_stamp),
        ]
        return page_with(fields)

    def test_invalid_stamps_show_na(self):
        invalid = {('Active', 1, 'Write'), ('Static', 2, 'Trim')}

        def stamp_for(name, bucket, counter):
            if (name, bucket, counter) in invalid:
                return layout.INVALID_STAMP
            return layout.stamp(BASE_MS)

        text, log = self.reports(self._stamped_page(
            ALL_STAMP_UNITS, ALL_STAMP_UNITS, 1, stamp_for,
            layout.INVALID_STAMP))
        for name, bucket, counter in each_counter():
            not_valid = (name, bucket, counter) in invalid
            with self.subTest(set=name, bucket=bucket, counter=counter):
                self.assertEqual(
                    self.text_stamps(text, name, bucket)[counter],
                    'N/A' if not_valid else stamp_text(BASE_MS))
                self.assertEqual(
                    self.json_stamps(log, name, bucket)[counter],
                    'NA' if not_valid else stamp_text(BASE_MS))
        self.assertEqual(self.text_value(text, DEBUG_STAMP), 'N/A')
        self.assertEqual(log[DEBUG_STAMP], 'NA')

    def test_stamp_attributes_are_not_part_of_the_time(self):
        """Bytes 5:0 of a Latency Stamp are its time; byte 6 holds the
        Synch and Timestamp Origin attributes."""
        # Synch set, Timestamp Origin 001b: set by a Set Features command
        attributes = 0x03
        text, log = self.reports(self._stamped_page(
            ALL_STAMP_UNITS, ALL_STAMP_UNITS, 1,
            lambda *_: layout.stamp(BASE_MS, attributes),
            layout.stamp(BASE_MS, attributes)))
        for name, bucket, counter in each_counter():
            with self.subTest(set=name, bucket=bucket, counter=counter):
                self.assertEqual(
                    self.text_stamps(text, name, bucket)[counter],
                    stamp_text(BASE_MS))
                self.assertEqual(
                    self.json_stamps(log, name, bucket)[counter],
                    stamp_text(BASE_MS))
        self.assertEqual(self.text_value(text, DEBUG_STAMP),
                         stamp_text(BASE_MS))
        self.assertEqual(log[DEBUG_STAMP], stamp_text(BASE_MS))

    @unittest.expectedFailure
    def test_power_on_stamps_are_not_dates(self):
        """Defect: the printers ignore the Stamp Units; a stamp whose bit
        is cleared counts from power on and is shown as a date all the
        same."""
        hour_ms = 3_600_000
        units = layout.stamp_unit_bit(0, 'Read')
        text, log = self.reports(self._stamped_page(
            units, units, 0, lambda *_: layout.stamp(hour_ms),
            layout.stamp(hour_ms)))
        for name, bucket, counter in each_counter():
            is_date = (bucket, counter) == (0, 'Read')
            with self.subTest(set=name, bucket=bucket, counter=counter):
                for shown in (self.text_stamps(text, name, bucket)[counter],
                              self.json_stamps(log, name, bucket)[counter]):
                    self.assertEqual(bool(DATE_RE.search(shown)), is_date,
                                     shown)
        for shown in (self.text_value(text, DEBUG_STAMP), log[DEBUG_STAMP]):
            self.assertIsNone(DATE_RE.search(shown), shown)


class TestLatencyMonitorLogDebugLogSize(LatencyMonitorLogDecodeTestBase):

    def _page(self, version, size):
        return page_with(
            [(layout.DEBUG_TELEMETRY_LOG_SIZE, f'{len(size)}s', size)],
            version=version)

    def test_absent_before_version_4(self):
        version = layout.DEBUG_TELEMETRY_LOG_SIZE_VERSION - 1
        text, log = self.reports(self._page(version, bytes([1] * 12)))
        self.assertNotIn(DEBUG_LOG_SIZE, text)
        self.assertNotIn(DEBUG_LOG_SIZE, log)

    def test_hex_from_version_4(self):
        cases = (
            (bytes(12), '0x00'),
            ((0x1234).to_bytes(12, 'little'), '0x1234'),
            (bytes(11) + b'\xab', '0xab' + '00' * 11),
            (bytes(range(1, 13)), '0x0c0b0a090807060504030201'),
        )
        for version in (layout.DEBUG_TELEMETRY_LOG_SIZE_VERSION,
                        layout.HITFS_VERSION):
            for size, want in cases:
                with self.subTest(version=version, want=want):
                    text, log = self.reports(self._page(version, size))
                    self.assertEqual(self.text_value(text, DEBUG_LOG_SIZE),
                                     want)
                    self.assertEqual(log[DEBUG_LOG_SIZE], want)


class TestLatencyMonitorLogErrors(LatencyMonitorLogTestBase):

    def assertFails(self, cause, status=None):
        """A failed text run naming @cause on stderr, and a failed -o json
        run whose report is the error alone, or the error and the NVMe
        @status the read failed with. Return the text run's stderr and the
        JSON report."""
        result = self.run_c3()
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn(cause, result.stderr)
        stderr = result.stderr
        result = self.run_c3('-o', 'json')
        self.assertNotEqual(result.returncode, 0, result.stdout)
        report = json.loads(result.stdout)
        keys = {'error'}
        if status is not None:
            keys.add(f'status: {status}')
        self.assertEqual(set(report), keys, report)
        self.assertIn('Failure reading the C3 Log Page', report['error'])
        return stderr, report

    def test_get_log_error_fails(self):
        status = 0x0002
        self.server.logs = {layout.LID: status}
        stderr, report = self.assertFails('Unable to read C3 data', status)
        self.assertIn('NVMe status: Invalid Field in Command', stderr)
        self.assertEqual(report[f'status: {status}'][0]['error'].split(':')[0],
                         'Invalid Field in Command')

    def test_no_ocp_uuid_fails_without_reading(self):
        self.serve(layout.pack())
        self.server.uuid_slot = None
        self.assertFails('No OCP UUID index found')
        self.assertEqual(self.server.log_reads(layout.LID), [])

    def test_unknown_guid_reports_only_the_error_in_json(self):
        self.serve(layout.pack(guid=bytes(16)))
        stderr, _ = self.assertFails(UNKNOWN_GUID_MSG)
        self.assertIn(f'{UNKNOWN_GUID_MSG}: '
                      f'expected 0x{layout.GUID_BYTES[::-1].hex()}, '
                      f'actual 0x{bytes(16).hex()}', stderr)


if __name__ == '__main__':
    main()
