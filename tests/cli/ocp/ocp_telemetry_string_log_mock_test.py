#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp telemetry-string-log" against a mocked controller.

The C9 Telemetry String Log is a 432-byte header followed by four tables
whose start and size the header gives in DWORDs, all device-reported.
The text and JSON printers walk those tables straight out of the fetched
buffer, so these tests serve pages whose tables are well formed, very
large, placed past the end of the log, or sized so that scaling to bytes
wraps, and check that each is either decoded exactly or refused.

Tests in this module verify:
  * Every entry of every table, and the ASCII table, decodes to the
    values the page carries, in text and JSON output; NUL bytes inside
    the ASCII table are kept in JSON.
  * A table far larger than the stack decodes in full, so no copy of it
    lives on the stack.
  * A table that starts past the end of the log, or whose size wraps
    when scaled to bytes, is reported and skipped while the other tables
    still decode.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_telemetry_string_log_mock_test.py <nvme-binary> <mock-lib>
"""
import json
import os
import re
import struct

from tests.cli.ocp.ocp_mock_test import OCPMockServer, OCPMockTestBase, main

_OCP_LID_TELSLG = 0xC9

_HEADER_LEN = 432
_ENTRY_LEN = 16
_ENTRY_DWORDS = _ENTRY_LEN // 4
_GUID = bytes.fromhex('b13a83691a8f408b9ea495940057aa44')[::-1]

# struct telemetry_str_log_format: sits at byte 64, then sitsz, ests,
# estsz, vu_eve_sts, vu_eve_st_sz, ascts, asctsz, all __le64.
_TABLE_FIELDS_OFFSET = 64

_STAT_TABLE = 'Statistics Identifier String Table'
_EVENT_TABLE = 'Event String Table'
_VU_EVENT_TABLE = 'VU Event String Table'
_ASCII_TABLE = 'ASCII Table'
_EXCEEDS = 'exceeds the log page'

_JSON_STAT_KEY = 'Statistics Identifier String Table'
_JSON_EVENT_KEY = 'Event Identifier String Table Entry'
_JSON_VU_EVENT_KEY = 'VU Event Identifier String Table Entry'

# Small enough that a stack copy of the large table below cannot fit.
_SMALL_STACK_KB = 512


def stat_id(i):
    return (0x100 + i) & 0xFFFF


def stat_entry(i):
    return struct.pack('<HBBQI', stat_id(i), 0, 4 + (i % 8), 8 * i, 0)


def event_entry(i):
    return struct.pack('<BHBQI', 0x03, 0x200 + i, 5, 4 * i, 0)


def vu_event_entry(i):
    return struct.pack('<BHBQI', 0x80, 0x300 + i, 6, 2 * i, 0)


def pack_page(stats=2, events=3, vu_events=1, ascii_text=b'OCP_STRINGS_LOG!',
              overrides=None):
    """Header plus tables laid out back to back after it. @overrides
    replaces any of the eight table start/size DWORD counts after the
    tables are placed, to describe a page the bytes do not back."""
    tables = [
        b''.join(stat_entry(i) for i in range(stats)),
        b''.join(event_entry(i) for i in range(events)),
        b''.join(vu_event_entry(i) for i in range(vu_events)),
        ascii_text + bytes(-len(ascii_text) % 4),
    ]
    fields = []
    body = b''
    for table in tables:
        fields += [(_HEADER_LEN + len(body)) // 4, len(table) // 4]
        body += table
    names = ('sits', 'sitsz', 'ests', 'estsz',
             'vu_eve_sts', 'vu_eve_st_sz', 'ascts', 'asctsz')
    for name, value in (overrides or {}).items():
        fields[names.index(name)] = value

    header = bytearray(_HEADER_LEN)
    header[0] = 1
    header[16:32] = _GUID
    struct.pack_into('<Q', header, 32, (_HEADER_LEN + len(body)) // 4)
    struct.pack_into('<8Q', header, _TABLE_FIELDS_OFFSET, *fields)
    return bytes(header) + body


class OCPTelemetryStringLogMockServer(OCPMockServer):
    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.logs[_OCP_LID_TELSLG] = pack_page()


class TestOCPTelemetryStringLog(OCPMockTestBase):
    server_class = OCPTelemetryStringLogMockServer

    def setUp(self):
        super().setUp()
        self.out_dir = self._temp_dir('nvme-ocp-c9-')

    def run_c9(self, *args, stack_limit_kb=None):
        return self.run_ocp('telemetry-string-log', '-f',
                            os.path.join(self.out_dir, 'c9'), *args,
                            stack_limit_kb=stack_limit_kb)

    def json_log(self, *args, stack_limit_kb=None):
        result = self.assertOk(self.run_c9('-o', 'json', *args,
                                           stack_limit_kb=stack_limit_kb))
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f'-o json output is not one JSON document ({exc}): '
                      f'{result.stdout!r}')

    def text_values(self, stdout, label):
        return [int(v, 16) for v in
                re.findall(rf'^\s+{re.escape(label)}\s+: 0x([0-9a-f]+)$',
                           stdout, re.MULTILINE)]

    def assert_text_stats(self, stdout, count):
        self.assertEqual(
            self.text_values(stdout, 'Vendor Specific Statistic Identifier'),
            [stat_id(i) for i in range(count)])

    def assert_json_stats(self, log, count):
        table = log[_JSON_STAT_KEY]
        self.assertEqual(len(table), count)
        for i in range(count):
            entry = table[f'{_JSON_STAT_KEY} {i}']
            self.assertEqual(entry['Vendor Specific Statistic Identifier'],
                             stat_id(i))
            self.assertEqual(entry['ASCII ID Length'], 4 + (i % 8))
            self.assertEqual(entry['ASCII ID offset'], 8 * i)

    def test_text_decodes_every_table(self):
        out = self.assertOk(self.run_c9()).stdout
        self.assert_text_stats(out, 2)
        self.assertEqual(self.text_values(out, 'Event Identifier'),
                         [0x200, 0x201, 0x202])
        self.assertEqual(self.text_values(out, 'VU Event Identifier'),
                         [0x300])
        # The FIFO rows above share the ASCII table's row format.
        ascii_rows = out.split('ASCII_Character\n', 1)[1]
        ascii_chars = re.findall(r'^\s+\d+\s+\d+\s+(.)$', ascii_rows,
                                 re.MULTILINE)
        self.assertEqual(''.join(ascii_chars), 'OCP_STRINGS_LOG!')

    def test_json_decodes_every_table(self):
        log = self.json_log()
        self.assert_json_stats(log, 2)
        events = log[_JSON_EVENT_KEY]
        self.assertEqual(
            [events[f'{_JSON_EVENT_KEY} {i}']['Event Identifier']
             for i in range(3)],
            [0x200, 0x201, 0x202])
        self.assertEqual(
            log[_JSON_VU_EVENT_KEY][f'{_JSON_VU_EVENT_KEY} 0']
            ['VU Event Identifier'], 0x300)
        self.assertEqual(log['ASCII Table'], 'OCP_STRINGS_LOG!')
        self.assertNotIn('Errors', log)

    def test_json_ascii_table_keeps_nul_bytes(self):
        self.server.logs[_OCP_LID_TELSLG] = pack_page(
            ascii_text=b'OCP\0STRINGS\0LOG!')
        self.assertEqual(self.json_log()['ASCII Table'],
                         'OCP\0STRINGS\0LOG!')

    def test_table_larger_than_the_stack_decodes(self):
        """A table copied onto the stack overruns @_SMALL_STACK_KB and
        kills nvme with SIGSEGV instead of decoding."""
        count = 2 * _SMALL_STACK_KB * 1024 // _ENTRY_LEN
        self.server.logs[_OCP_LID_TELSLG] = pack_page(stats=count)

        result = self.assertOk(self.run_c9(stack_limit_kb=_SMALL_STACK_KB))
        self.assert_text_stats(result.stdout, count)
        self.assert_json_stats(
            self.json_log(stack_limit_kb=_SMALL_STACK_KB), count)

    def _assert_stat_table_refused(self, overrides):
        self.server.logs[_OCP_LID_TELSLG] = pack_page(overrides=overrides)
        message = f'{_STAT_TABLE} {_EXCEEDS}'

        result = self.assertOk(self.run_c9())
        self.assertIn(message, result.stderr)
        self.assertEqual(self.text_values(
            result.stdout, 'Vendor Specific Statistic Identifier'), [])
        self.assertEqual(self.text_values(result.stdout, 'Event Identifier'),
                         [0x200, 0x201, 0x202])

        log = self.json_log()
        self.assertEqual(log['Errors'], [message])
        self.assertNotIn(_JSON_STAT_KEY, log)
        self.assertEqual(len(log[_JSON_EVENT_KEY]), 3)
        self.assertEqual(log['ASCII Table'], 'OCP_STRINGS_LOG!')

    def test_table_starting_past_the_log_is_refused(self):
        self._assert_stat_table_refused({'sits': 1 << 28})

    def test_table_running_past_the_log_is_refused(self):
        """The fetch sizes the log from the table sizes alone, so a table
        that starts in its last DWORD still runs off the end."""
        self._assert_stat_table_refused({'sits': len(pack_page()) // 4 - 1})

    def test_size_that_wraps_when_scaled_is_refused(self):
        """2^62 + 8 DWORDs is 32 bytes modulo 2^64 -- the size of the two
        entries actually there -- so the fetch reads exactly the page,
        which must not then be taken to hold a 2^62-DWORD table."""
        self._assert_stat_table_refused({'sitsz': (1 << 62) + 8})

    def test_every_table_is_bounds_checked(self):
        cases = {
            _EVENT_TABLE: {'ests': 1 << 28},
            _VU_EVENT_TABLE: {'vu_eve_sts': 1 << 28},
            _ASCII_TABLE: {'ascts': 1 << 28},
        }
        for table, overrides in cases.items():
            with self.subTest(table=table):
                self.server.logs[_OCP_LID_TELSLG] = pack_page(
                    overrides=overrides)
                message = f'{table} {_EXCEEDS}'
                result = self.assertOk(self.run_c9())
                self.assertIn(message, result.stderr)
                self.assert_text_stats(result.stdout, 2)
                log = self.json_log()
                self.assertEqual(log['Errors'], [message])
                self.assert_json_stats(log, 2)


if __name__ == '__main__':
    main()
