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
  * Table sizes too large to fetch, even ones that wrap, are refused.
  * A table far larger than the stack decodes in full, so no copy of it
    lives on the stack.
  * A table that starts past the end of the log, or runs past it, is
    reported and skipped while the other tables still decode.
  * -o binary writes the log unchanged.
  * The log is saved unchanged, by default in the current directory.
  * --print-only prints what is printed otherwise, from the same reads,
    and writes no file, also when the fetch fails; --output-file is
    rejected with it.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_telemetry_string_log_mock_test.py <nvme-binary> <mock-lib>
"""
import json
import os
import re
import struct

from tests.cli.nvme_mock import (CNS_UUID_LIST, NSID_ALL, SC_INVALID_FIELD,
                                 main)
from tests.cli.ocp.ocp_mock_test import OCPController, OCPMockTestBase

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


class OCPTelemetryStringLogController(OCPController):
    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.logs[_OCP_LID_TELSLG] = pack_page()


class TestOCPTelemetryStringLog(OCPMockTestBase):
    controller_class = OCPTelemetryStringLogController

    def setUp(self):
        super().setUp()
        self.out_dir = os.path.join(self.tmp, 'c9')
        os.mkdir(self.out_dir)

    def run_c9(self, *args, stack_limit_kb=None, encoding='utf-8'):
        return self.run_ocp('telemetry-string-log', '-f',
                            os.path.join(self.out_dir, 'c9'), *args,
                            encoding=encoding,
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

    def test_binary_is_the_log(self):
        result = self.run_c9('-o', 'binary', encoding=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, pack_page())

    def files(self, path):
        """The contents of the files in @path. Their names are left out:
        -f <file> saves <file>-.bin, which is not what the help suggests."""
        contents = []
        for name in sorted(os.listdir(path)):
            with open(os.path.join(path, name), 'rb') as f:
                contents.append(f.read())
        return contents

    def test_log_is_saved(self):
        self.assertOk(self.run_c9())
        self.assertEqual(self.files(self.out_dir), [pack_page()])

    def test_log_is_saved_in_the_current_directory_by_default(self):
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.out_dir)
        self.assertOk(self.run_ocp('telemetry-string-log'))
        self.assertEqual(self.files(self.out_dir), [pack_page()])

    def test_table_sizes_too_large_to_fetch_are_refused(self):
        """Table sizes adding up past INT_MAX bytes are refused before
        the fetch, including a sum that wraps to a size that looks
        fetchable."""
        for sitsz in (1 << 29, (1 << 62) + 8):
            with self.subTest(sitsz=sitsz):
                self.server.logs[_OCP_LID_TELSLG] = pack_page(
                    overrides={'sitsz': sitsz})
                self.server.commands.clear()
                result = self.run_c9()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('C9 log is too large', result.stderr)
                reads = self.server.log_reads(_OCP_LID_TELSLG)
                self.assertEqual([c.data_len for c in reads], [_HEADER_LEN])

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


class TestOCPTelemetryStringLogPrintOnly(OCPMockTestBase):
    """--print-only prints the log and writes no file. The runs use long
    options only, so that they make seeds for the device fuzz target
    (scripts/fuzz/nvme_fuzz/seeds.py)."""

    controller_class = OCPTelemetryStringLogController

    def setUp(self):
        super().setUp()
        # an empty cwd, where the default string.bin would land
        self.chdir_out_dir()
        saved_dir = os.path.join(self.tmp, 'saved')
        os.mkdir(saved_dir)
        self.saved_prefix = os.path.join(saved_dir, 'c9')

    def run_print_only(self, *args, encoding='utf-8'):
        self.server.commands.clear()
        return self.run_ocp('telemetry-string-log', '--print-only', *args,
                            encoding=encoding)

    def run_saved(self, *args, encoding='utf-8'):
        self.server.commands.clear()
        return self.run_ocp('telemetry-string-log',
                            f'--output-file={self.saved_prefix}', *args,
                            encoding=encoding)

    def assert_nothing_written(self):
        self.assertEqual(os.listdir(self.out_dir), [])

    def reads(self):
        return [(c.lpo, c.data_len, c.nsid, c.cdw14 & 0x7F)
                for c in self.server.log_reads(_OCP_LID_TELSLG)]

    def test_prints_what_is_printed_without_it(self):
        for fmt in ('normal', 'json'):
            with self.subTest(fmt=fmt):
                printed = self.assertOk(
                    self.run_print_only(f'--output-format={fmt}')).stdout
                self.assert_nothing_written()
                without = self.assertOk(
                    self.run_saved(f'--output-format={fmt}')).stdout
                self.assertEqual(printed, without)
                if fmt == 'json':
                    log = json.loads(printed)
                    self.assertEqual(len(log[_JSON_STAT_KEY]), 2)
                    self.assertEqual(log['ASCII Table'], 'OCP_STRINGS_LOG!')
                else:
                    self.assertEqual(
                        re.findall(r'Vendor Specific Statistic Identifier'
                                   r'\s+: 0x([0-9a-f]+)$', printed,
                                   re.MULTILINE),
                        [f'{stat_id(i):x}' for i in range(2)])

    def test_binary_is_the_log(self):
        result = self.run_print_only('--output-format=binary',
                                     encoding=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, pack_page())
        self.assert_nothing_written()

    def test_log_is_read_like_without_it(self):
        """The 432-byte header, then the whole log, with the OCP UUID's
        index, as for a saved log."""
        self.assertOk(self.run_print_only())
        printed = self.reads()
        self.assertEqual(
            printed,
            [(0, _HEADER_LEN, NSID_ALL, self.server.uuid_slot + 1),
             (0, len(pack_page()), NSID_ALL, self.server.uuid_slot + 1)])
        self.assertOk(self.run_saved())
        self.assertEqual(printed, self.reads())

    def test_no_uuid_reads_with_index_zero(self):
        self.server.uuid_slot = None
        self.assertOk(self.run_print_only('--no-uuid'))
        self.assertEqual(self.server.identifies(CNS_UUID_LIST), [])
        self.assertEqual([r[3] for r in self.reads()], [0, 0])
        self.assert_nothing_written()

    def test_output_file_is_rejected(self):
        result = self.run_print_only(f'--output-file={self.saved_prefix}')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--print-only and --output-file are mutually '
                      'exclusive.', result.stderr)
        self.assertEqual(self.server.commands, [])
        self.assertEqual(result.stdout, '')
        self.assert_nothing_written()
        self.assertEqual(os.listdir(os.path.dirname(self.saved_prefix)), [])

    def test_failed_fetch_writes_nothing(self):
        self.server.logs[_OCP_LID_TELSLG] = SC_INVALID_FIELD
        result = self.run_print_only()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unable to read C9 data', result.stderr)
        self.assertEqual(result.stdout, '')
        self.assert_nothing_written()


if __name__ == '__main__':
    main()
