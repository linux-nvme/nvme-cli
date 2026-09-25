#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron latency monitoring commands, hardware-free.

Three commands share the drive's latency-monitoring feature:

  latency-tracking  reads and writes the feature itself (0xD0), reporting or
                    changing which command classes are monitored and the
                    threshold above which a command is recorded.
  latency-stats     prints a histogram from the 0xD0 log, one row per fixed
                    latency bucket, for the command class chosen with -c.
  latency-logs      prints the fixed-size ring of recently recorded slow
                    commands from the 0xD1 log as CSV.

None is gated on the drive model.  On real hardware the counters and ring
entries are whatever the drive happened to record, so the e2e tests can only
check shape; here the log contents are inputs, so every decoded value is
asserted against a known one.

Tests in this module verify:
  * latency-tracking status reporting for each combination of enabled state
    and monitored command classes.
  * The command mask and threshold encoding the enable path writes, the
    save bit, and rejection of an out-of-range or non-multiple-of-10
    threshold and of an unrecognised -O or -c value.
  * latency-stats bucket counts decoded per command class, the revision
    split, the fixed bucket ranges, and that -c is validated before the log
    is read.
  * latency-logs decoding of every CSV column, including the packed bitfields
    in the two command dwords.
  * Error handling for logs the drive rejects and for a non-existent device.

Usage: python3 micron_latency_mock_test.py <nvme-binary> <mock-lib>
"""

import re
import struct

from micron_mock_test import (
    OPC_GET_FEATURES,
    OPC_SET_FEATURES,
    SC_INVALID_LOG_PAGE,
    TestMicronMock,
    main,
)

_TRACKING = "latency-tracking"
_STATS = "latency-stats"
_LOGS = "latency-logs"

_FID_LATENCY_MONITOR = 0xD0
_LID_STATS = 0xD0
_LID_LOGS = 0xD1

# struct micron_latency_stats: a u64 version, then four arrays of
# 32 buckets + 32 reserved u64 entries, one array per command class.
_BUCKET_COUNT = 32
_ARRAY_ENTRIES = 64
_STATS_VERSION_OFFSET = 0
_STATS_ARRAY_OFFSET = {
    'all': 8,
    'read': 8 + _ARRAY_ENTRIES * 8,
    'write': 8 + 2 * _ARRAY_ENTRIES * 8,
    'trim': 8 + 3 * _ARRAY_ENTRIES * 8,
}
_STATS_LOG_SIZE = 4096

# struct latency_log_entry, 16 to a log.
_LOG_ENTRY_SIZE = 64
_LOG_ENTRY_COUNT = 16

_HEADER = "Micron IO {} Command Latency Statistics"
_COMMAND_CLASSES = (("all", "All"), ("read", "Read"), ("write", "Write"),
                    ("trim", "Trim"))
_TABLE_HEADER = "Bucket    Start     End        Command Count"

# Bucket boundaries are hard-coded in the plugin's thresholds[] table, so they
# are identical on every drive. The last bucket's end prints as "INF".
_LATENCY_BUCKETS = (
    ("0us", "50us"), ("50us", "100us"), ("100us", "150us"),
    ("150us", "200us"), ("200us", "300us"), ("300us", "400us"),
    ("400us", "500us"), ("500us", "600us"), ("600us", "700us"),
    ("700us", "800us"), ("800us", "900us"), ("900us", "1000us"),
    ("1ms", "5ms"), ("5ms", "10ms"), ("10ms", "20ms"), ("20ms", "50ms"),
    ("50ms", "100ms"), ("100ms", "200ms"), ("200ms", "300ms"),
    ("300ms", "400ms"), ("400ms", "500ms"), ("500ms", "600ms"),
    ("600ms", "700ms"), ("700ms", "800ms"), ("800ms", "900ms"),
    ("900ms", "1000ms"), ("1s", "2s"), ("2s", "3s"), ("3s", "4s"),
    ("4s", "5s"), ("5s", "8s"), ("8s", "INF"),
)

# "%2d   %8s    %8s    %8"PRIu64"" -- bucket, start, end, command count.
_BUCKET_ROW_RE = re.compile(
    r"^\s*(\d+)\s+(\d+(?:us|ms|s))\s+(\d+(?:us|ms|s)|INF)\s+(\d+)$"
)

_CSV_HEADER = (
    "Timestamp, Latency, CmdTag, Opcode, Fuse, Psdt, Cid, Nsid, "
    "Slba_L, Slba_H, Nlb, DEAC, PRINFO, FUA, LR"
)
_CSV_COLUMNS = tuple(name.strip() for name in _CSV_HEADER.split(","))

# Command-class bits in the feature value and in the mask written back.
_MASK_READ = 0x1
_MASK_WRITE = 0x2
_MASK_TRIM = 0x4
_MASK_ALL = 0x7

# Default threshold mask the "all" path writes: read/write/trim at 8 units of
# 10ms each, i.e. 80ms per class.
_DEFAULT_TIMING_MASK = 0x08080800


def pack_stats_log(version_major=0, version_minor=0, counts=None):
    """Build a 0xD0 latency stats log. @counts maps a command class name to a
    sequence of per-bucket counts."""
    buf = bytearray(_STATS_LOG_SIZE)
    struct.pack_into('<Q', buf, _STATS_VERSION_OFFSET,
                     (version_major << 32) | version_minor)
    for name, bucket_counts in (counts or {}).items():
        base = _STATS_ARRAY_OFFSET[name]
        for index, count in enumerate(bucket_counts):
            struct.pack_into('<Q', buf, base + index * 8, count)
    return bytes(buf)


def pack_log_entry(timestamp=0, latency=0, cmdtag=0, opcode=0, fuse=0, psdt=0,
                   cid=0, nsid=0, slba_low=0, slba_high=0, nlb=0, deac=0,
                   prinfo=0, fua=0, lr=0, dsm=0):
    """Build one struct latency_log_entry.

    The command dwords pack several fields as bitfields; on a little-endian
    target the first declared field occupies the least significant bits.
    """
    dw0 = (opcode & 0xFF) | ((fuse & 0x3) << 8) | ((psdt & 0x3) << 14) \
        | ((cid & 0xFFFF) << 16)
    dw12 = (nlb & 0xFFFF) | ((deac & 0x1) << 25) | ((prinfo & 0xF) << 26) \
        | ((fua & 0x1) << 30) | ((lr & 0x1) << 31)
    entry = struct.pack('<QIIIIIIII', timestamp, latency, cmdtag, dw0, nsid,
                        slba_low, slba_high, dw12, dsm)
    return entry.ljust(_LOG_ENTRY_SIZE, b'\0')


def pack_logs_log(entries=()):
    """Build a 0xD1 latency log from up to 16 entries."""
    buf = bytearray(_LOG_ENTRY_SIZE * _LOG_ENTRY_COUNT)
    for index, entry in enumerate(entries):
        buf[index * _LOG_ENTRY_SIZE:(index + 1) * _LOG_ENTRY_SIZE] = entry
    return bytes(buf)


class TestMicronLatencyTracking(TestMicronMock):
    """latency-tracking: reading and writing the monitoring feature."""

    def set_feature_value(self, value):
        self.server.features[_FID_LATENCY_MONITOR] = value

    def written(self):
        """Return the single Set Features command the command issued."""
        writes = [c for c in self.server.commands
                  if c['opcode'] == OPC_SET_FEATURES
                  and c['fid'] == _FID_LATENCY_MONITOR]
        self.assertEqual(len(writes), 1,
                         f"expected one Set Features, got {len(writes)}")
        return writes[0]

    # ---------------------------------------------------------------- #
    # Status reporting                                                 #
    # ---------------------------------------------------------------- #

    def test_status_is_the_default_action(self):
        """With no -O the state is reported and nothing is written."""
        self.set_feature_value(0)
        result = self.run_plugin_cmd_check(_TRACKING)

        self.assertIn("Latency Tracking Statistics is currently disabled",
                      result.stdout)
        self.assertNotIn(OPC_SET_FEATURES, self.server.opcodes(),
                         "a status query must not change the feature")

    def test_status_reports_enabled_from_the_upper_half(self):
        """The threshold half of the value being set means tracking is on."""
        self.set_feature_value(0x08080800 | _MASK_ALL)
        result = self.run_plugin_cmd_check(_TRACKING, args="-O status")

        self.assertIn("Latency Tracking Statistics is currently enabled",
                      result.stdout)

    def test_status_reports_each_command_class(self):
        """The low three bits name the monitored classes."""
        cases = {
            _MASK_ALL: " for All commands",
            _MASK_READ: " for Read commands",
            _MASK_WRITE: " for Write commands",
            _MASK_TRIM: " for Trim commands",
            _MASK_READ | _MASK_WRITE: " for Read Write commands",
            _MASK_WRITE | _MASK_TRIM: " for Write Trim commands",
            _MASK_READ | _MASK_TRIM: " for Read Trim commands",
        }
        for mask, expected in cases.items():
            with self.subTest(mask=hex(mask)):
                self.set_feature_value(0x08080800 | mask)
                result = self.run_plugin_cmd_check(_TRACKING, args="-O status")

                self.assertIn(expected, result.stdout)

    def test_status_reads_the_feature_not_a_log(self):
        """The state comes from Get Features, not from a log page."""
        self.set_feature_value(0)
        self.server.commands.clear()
        self.run_plugin_cmd_check(_TRACKING)

        reads = [c for c in self.server.commands
                 if c['opcode'] == OPC_GET_FEATURES]
        self.assertEqual(len(reads), 1)
        self.assertEqual(reads[0]['fid'], _FID_LATENCY_MONITOR)
        self.assertEqual(self.server.log_reads(), [])

    def test_feature_read_failure_is_reported(self):
        """A drive that rejects the feature read fails with a message."""
        self.server.feature_status[_FID_LATENCY_MONITOR] = SC_INVALID_LOG_PAGE
        result = self.run_plugin_cmd(_TRACKING)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Failed to retrieve latency monitoring feature status",
                      result.stderr)

    # ---------------------------------------------------------------- #
    # Enabling and disabling                                           #
    # ---------------------------------------------------------------- #

    def test_enable_writes_the_enable_flag(self):
        """Enabling sets cdw11 to 1 and saves the setting."""
        self.set_feature_value(0)
        self.run_plugin_cmd_check(_TRACKING, args="-O enable")
        write = self.written()

        self.assertEqual(write['cdw11'], 1)
        self.assertTrue(write['cdw10'] & (1 << 31),
                        "the save bit was not set")

    def test_disable_writes_the_disable_flag(self):
        """Disabling sets cdw11 to 0."""
        self.set_feature_value(0x08080800 | _MASK_ALL)
        self.run_plugin_cmd_check(_TRACKING, args="-O disable")

        self.assertEqual(self.written()['cdw11'], 0)

    def test_command_class_selects_its_mask_and_threshold_slot(self):
        """Each class writes its own bit and its own threshold byte.

        The threshold is carried in units of 10ms, in a per-class byte:
        read in bits 31:24, write in 23:16, trim in 15:8.
        """
        cases = (
            ('read', _MASK_READ, 24),
            ('write', _MASK_WRITE, 16),
            ('trim', _MASK_TRIM, 8),
        )
        for name, mask, shift in cases:
            with self.subTest(command=name):
                self.set_feature_value(0)
                self.server.commands.clear()
                self.run_plugin_cmd_check(
                    _TRACKING, args=f"-O enable -c {name} -t 500")
                write = self.written()

                self.assertEqual(write['cdw12'], mask)
                self.assertEqual(write['cdw13'], (500 // 10) << shift)

    def test_all_commands_uses_the_default_mask_and_threshold(self):
        """Monitoring every class writes the plugin's fixed default mask.

        The -t threshold is only applied to a single named class, so it does
        not reach the mask here.
        """
        self.set_feature_value(0)
        self.run_plugin_cmd_check(_TRACKING, args="-O enable -c all -t 500")
        write = self.written()

        self.assertEqual(write['cdw12'], _MASK_ALL)
        self.assertEqual(write['cdw13'], _DEFAULT_TIMING_MASK)

    def test_default_command_class_is_all(self):
        """Omitting -c monitors every command class."""
        self.set_feature_value(0)
        self.run_plugin_cmd_check(_TRACKING, args="-O enable")

        self.assertEqual(self.written()['cdw12'], _MASK_ALL)

    def test_enable_reports_success(self):
        """A successful write is reported under --verbose."""
        self.set_feature_value(0)
        result = self.run_plugin_cmd_check(
            _TRACKING, args="-O enable -c read -t 100 --verbose")

        self.assertIn("Successfully enabled latency monitoring",
                      result.stdout + result.stderr)
        self.assertIn("100ms threshold", result.stdout + result.stderr)

    def test_threshold_defaults_are_reported_as_the_drive_default(self):
        """With no -t the message names the drive's 800ms default."""
        self.set_feature_value(0)
        result = self.run_plugin_cmd_check(
            _TRACKING, args="-O enable --verbose")

        self.assertIn("800ms threshold", result.stdout + result.stderr)

    # ---------------------------------------------------------------- #
    # Argument validation                                              #
    # ---------------------------------------------------------------- #

    def test_threshold_above_the_maximum_is_rejected(self):
        """The per-class threshold byte counts 10ms units, so 2550ms is the
        largest representable value."""
        self.set_feature_value(0)
        result = self.run_plugin_cmd(_TRACKING,
                                     args="-O enable -c read -t 2560")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("maximum threshold value cannot be more than 2550 ms",
                      result.stderr)
        self.assertNotIn(OPC_SET_FEATURES, self.server.opcodes(),
                         "a rejected threshold must not be written")

    def test_maximum_threshold_is_accepted(self):
        """2550ms is inside the range, so it is written."""
        self.set_feature_value(0)
        self.run_plugin_cmd_check(_TRACKING,
                                  args="-O enable -c read -t 2550")

        self.assertEqual(self.written()['cdw13'], (2550 // 10) << 24)

    def test_threshold_must_be_a_multiple_of_ten(self):
        """A threshold that is not a whole number of 10ms units is refused."""
        self.set_feature_value(0)
        result = self.run_plugin_cmd(_TRACKING,
                                     args="-O enable -c read -t 105")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("threshold value should be multiple of 10 ms",
                      result.stderr)

    def test_threshold_is_only_checked_when_enabling(self):
        """Disabling ignores -t, so an unrepresentable value is harmless."""
        self.set_feature_value(0)
        self.run_plugin_cmd_check(_TRACKING,
                                  args="-O disable -c read -t 9999")

        self.assertEqual(self.written()['cdw11'], 0)

    def test_unrecognised_option_is_rejected(self):
        """-O takes enable, disable or status and nothing else."""
        self.set_feature_value(0)
        result = self.run_plugin_cmd(_TRACKING, args="-O bogus")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid control option bogus specified", result.stderr)

    def test_unrecognised_option_is_checked_before_the_feature_read(self):
        """-O is validated first, so a bad value reports only itself."""
        self.set_feature_value(0)
        self.server.commands.clear()
        self.run_plugin_cmd(_TRACKING, args="-O bogus")

        self.assertEqual(self.server.commands, [],
                         "the drive was touched despite an invalid -O value")

    def test_unrecognised_command_class_is_rejected(self):
        """-c takes all, read, write or trim and nothing else."""
        self.set_feature_value(0)
        result = self.run_plugin_cmd(_TRACKING, args="-O enable -c bogus")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid command bogus specified", result.stderr)

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_TRACKING)


class TestMicronLatencyStats(TestMicronMock):
    """latency-stats: the per-bucket histogram from the 0xD0 log."""

    def set_stats(self, **kwargs):
        self.server.logs[_LID_STATS] = pack_stats_log(**kwargs)

    def bucket_rows(self, stdout):
        """Return the (bucket, start, end, count) tuples from the table."""
        rows = [m.groups() for m in
                (_BUCKET_ROW_RE.match(line) for line in stdout.splitlines())
                if m]
        self.assertTrue(rows, f"no bucket rows in stdout: {stdout!r}")
        return rows

    def counts(self, args=""):
        """Return the per-bucket counts the command printed."""
        result = self.run_plugin_cmd_check(_STATS, args=args)
        return [int(count) for _, _, _, count in
                self.bucket_rows(result.stdout)]

    # ---------------------------------------------------------------- #
    # Decoding                                                         #
    # ---------------------------------------------------------------- #

    def test_counts_are_read_from_the_selected_command_class(self):
        """-c chooses which of the four arrays in the log is reported."""
        per_class = {
            'all': [1] * _BUCKET_COUNT,
            'read': [2] * _BUCKET_COUNT,
            'write': [3] * _BUCKET_COUNT,
            'trim': [4] * _BUCKET_COUNT,
        }
        self.set_stats(counts=per_class)

        for name, expected in per_class.items():
            with self.subTest(command=name):
                self.assertEqual(self.counts(args=f"-c {name}"), expected)

    def test_default_command_class_is_all(self):
        """Omitting -c reports the aggregate array."""
        self.set_stats(counts={'all': [7] * _BUCKET_COUNT,
                               'read': [9] * _BUCKET_COUNT})

        self.assertEqual(self.counts(), [7] * _BUCKET_COUNT)

    def test_each_bucket_is_reported_independently(self):
        """A count lands in the bucket it was stored in."""
        counts = list(range(1, _BUCKET_COUNT + 1))
        self.set_stats(counts={'all': counts})

        self.assertEqual(self.counts(), counts)

    def test_large_counts_are_reported_unsigned(self):
        """A count is a 64-bit unsigned value, so the top of the range must
        not print as negative."""
        biggest = (1 << 64) - 1
        counts = [0] * _BUCKET_COUNT
        counts[0] = biggest
        counts[-1] = (1 << 63)
        self.set_stats(counts={'all': counts})
        reported = self.counts()

        self.assertEqual(reported[0], biggest)
        self.assertEqual(reported[-1], 1 << 63)

    def test_reserved_buckets_are_not_reported(self):
        """Each array has 32 reserved entries after the 32 buckets; those are
        not part of the histogram."""
        counts = [0] * _BUCKET_COUNT + [999] * _BUCKET_COUNT
        self.set_stats(counts={'all': counts})

        self.assertEqual(self.counts(), [0] * _BUCKET_COUNT)

    def test_revision_is_split_from_the_version_field(self):
        """The version word carries the major revision in its upper half."""
        for major, minor in ((0, 0), (1, 2), (3, 40000)):
            with self.subTest(version=(major, minor)):
                self.set_stats(version_major=major, version_minor=minor)
                result = self.run_plugin_cmd_check(_STATS)

                self.assertIn(f"Major Revision : {major}", result.stdout)
                self.assertIn(f"Minor Revision : {minor}", result.stdout)

    # ---------------------------------------------------------------- #
    # Table layout                                                     #
    # ---------------------------------------------------------------- #

    def test_header_names_the_selected_command_class(self):
        self.set_stats()
        for option, name in _COMMAND_CLASSES:
            with self.subTest(command=option):
                result = self.run_plugin_cmd_check(_STATS,
                                                   args=f"-c {option}")
                self.assertIn(_HEADER.format(name), result.stdout)

    def test_prints_the_bucket_table_header(self):
        self.set_stats()
        result = self.run_plugin_cmd_check(_STATS)

        self.assertIn(_TABLE_HEADER, result.stdout)

    def test_bucket_ranges_match_the_plugin_thresholds(self):
        """The fixed bucket ranges print in order, numbered from 1."""
        self.set_stats()
        rows = self.bucket_rows(self.run_plugin_cmd_check(_STATS).stdout)
        ranges = [(int(bucket), start, end) for bucket, start, end, _ in rows]
        expected = [(i + 1, start, end)
                    for i, (start, end) in enumerate(_LATENCY_BUCKETS)]

        self.assertEqual(ranges, expected)

    def test_has_one_row_per_bucket(self):
        self.set_stats()
        rows = self.bucket_rows(self.run_plugin_cmd_check(_STATS).stdout)

        self.assertEqual(len(rows), len(_LATENCY_BUCKETS))

    # ---------------------------------------------------------------- #
    # Validation and failures                                          #
    # ---------------------------------------------------------------- #

    def test_unrecognised_command_class_is_rejected(self):
        self.set_stats()
        result = self.run_plugin_cmd(_STATS, args="-c bogus")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid command option bogus to display latency stats",
                      result.stderr)

    def test_command_class_is_checked_before_the_log_read(self):
        """A bad -c reports only itself, on a drive with or without the log."""
        self.server.commands.clear()
        result = self.run_plugin_cmd(_STATS, args="-c bogus")

        self.assertEqual(self.server.log_reads(_LID_STATS), [],
                         "the log was read despite an invalid -c value")
        self.assertEqual(result.stdout, "",
                         f"unexpected stdout: {result.stdout!r}")

    def test_missing_log_is_reported(self):
        """A drive without the stats log fails rather than printing zeros."""
        result = self.run_plugin_cmd(_STATS)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid Log Page", result.stderr)

    def test_runs_on_an_unrecognised_drive_model(self):
        """The command reads no model, so it is not gated on one."""
        self.select_model(None)
        self.set_stats(counts={'all': [5] * _BUCKET_COUNT})

        self.assertEqual(self.counts(), [5] * _BUCKET_COUNT)

    def test_namespace_path_matches_the_controller_path(self):
        self.set_stats(counts={'all': list(range(_BUCKET_COUNT))})
        ctrl = self.run_plugin_cmd_check(_STATS, device=self.ctrl)
        ns = self.run_plugin_cmd_check(_STATS, device=self.ns1)

        self.assertEqual(ctrl.stdout, ns.stdout)

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_STATS)


class TestMicronLatencyLogs(TestMicronMock):
    """latency-logs: the CSV ring of recorded slow commands."""

    def set_entries(self, entries):
        self.server.logs[_LID_LOGS] = pack_logs_log(entries)

    def rows(self, stdout):
        """Return the CSV data rows that follow the header."""
        lines = [line.strip() for line in stdout.splitlines()]
        self.assertIn(_CSV_HEADER, lines,
                      f"missing CSV header in stdout: {stdout!r}")
        start = lines.index(_CSV_HEADER) + 1
        return [line for line in lines[start:] if line]

    def first_row(self):
        result = self.run_plugin_cmd_check(_LOGS)
        row = self.rows(result.stdout)[0].split(",")
        self.assertEqual(len(row), len(_CSV_COLUMNS))
        return dict(zip(_CSV_COLUMNS, (int(v) for v in row)))

    def test_prints_the_csv_header(self):
        self.set_entries([])
        result = self.run_plugin_cmd_check(_LOGS)

        self.assertIn(_CSV_HEADER, result.stdout)

    def test_has_one_row_per_entry(self):
        """The log is a fixed-size ring, so every slot is printed."""
        self.set_entries([pack_log_entry(timestamp=i) for i in range(4)])
        rows = self.rows(self.run_plugin_cmd_check(_LOGS).stdout)

        self.assertEqual(len(rows), _LOG_ENTRY_COUNT)

    def test_every_column_is_decoded(self):
        """Each field lands in its own column, bitfields included."""
        self.set_entries([pack_log_entry(
            timestamp=0x1122334455667788, latency=4321, cmdtag=7, opcode=0x02,
            fuse=2, psdt=1, cid=0xBEEF, nsid=3, slba_low=0xDEADBEEF,
            slba_high=0x99, nlb=0x1234, deac=1, prinfo=0xB, fua=1, lr=1)])
        row = self.first_row()

        self.assertEqual(row, {
            'Timestamp': 0x1122334455667788,
            'Latency': 4321,
            'CmdTag': 7,
            'Opcode': 0x02,
            'Fuse': 2,
            'Psdt': 1,
            'Cid': 0xBEEF,
            'Nsid': 3,
            'Slba_L': 0xDEADBEEF,
            'Slba_H': 0x99,
            'Nlb': 0x1234,
            'DEAC': 1,
            'PRINFO': 0xB,
            'FUA': 1,
            'LR': 1,
        })

    def test_bitfields_do_not_bleed_into_each_other(self):
        """Setting one packed field leaves its neighbours at zero."""
        for field in ('opcode', 'fuse', 'psdt', 'cid'):
            with self.subTest(field=field):
                self.set_entries([pack_log_entry(**{field: 1})])
                row = self.first_row()
                for column in ('Opcode', 'Fuse', 'Psdt', 'Cid'):
                    expected = 1 if column.lower() == field else 0
                    self.assertEqual(row[column], expected,
                                     f"{column} changed when setting {field}")

    def test_flag_fields_do_not_bleed_into_each_other(self):
        for field in ('nlb', 'deac', 'prinfo', 'fua', 'lr'):
            with self.subTest(field=field):
                self.set_entries([pack_log_entry(**{field: 1})])
                row = self.first_row()
                for column in ('Nlb', 'DEAC', 'PRINFO', 'FUA', 'LR'):
                    expected = 1 if column.lower() == field else 0
                    self.assertEqual(row[column], expected,
                                     f"{column} changed when setting {field}")

    def test_all_rows_hold_unsigned_decimal_values(self):
        self.set_entries([pack_log_entry(timestamp=(1 << 64) - 1,
                                         latency=(1 << 32) - 1)])
        rows = self.rows(self.run_plugin_cmd_check(_LOGS).stdout)

        for row in rows:
            values = row.split(",")
            self.assertEqual(len(values), len(_CSV_COLUMNS))
            for column, value in zip(_CSV_COLUMNS, values):
                self.assertRegex(
                    value, r"^\d+$",
                    f"{column} is not unsigned decimal: {value!r}")

    def test_entries_are_printed_in_log_order(self):
        """Slot order is preserved, so the ring reads as stored."""
        self.set_entries([pack_log_entry(timestamp=i + 1)
                          for i in range(_LOG_ENTRY_COUNT)])
        rows = self.rows(self.run_plugin_cmd_check(_LOGS).stdout)
        timestamps = [int(row.split(",")[0]) for row in rows]

        self.assertEqual(timestamps, list(range(1, _LOG_ENTRY_COUNT + 1)))

    def test_missing_log_is_reported(self):
        result = self.run_plugin_cmd(_LOGS)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid Log Page", result.stderr)

    def test_runs_on_an_unrecognised_drive_model(self):
        self.select_model(None)
        self.set_entries([pack_log_entry(timestamp=42)])

        self.assertEqual(self.first_row()['Timestamp'], 42)

    def test_namespace_path_matches_the_controller_path(self):
        self.set_entries([pack_log_entry(timestamp=42, latency=7)])
        ctrl = self.run_plugin_cmd_check(_LOGS, device=self.ctrl)
        ns = self.run_plugin_cmd_check(_LOGS, device=self.ns1)

        self.assertEqual(ctrl.stdout, ns.stdout)

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_LOGS)


if __name__ == '__main__':
    main()
