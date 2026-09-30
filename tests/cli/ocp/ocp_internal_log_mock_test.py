#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp internal-log -t host|controller" against a mocked
controller.

Without -l and -s, internal-log reads the telemetry log and the C9h
Telemetry String Log from the drive, saves both, and decodes them; with
them it decodes the given files. The mock serves synthetic logs built by
tests/e2e/plugins/ocp/ocp_telemetry_layout.py and records every command,
so the tests can check how each log was requested as well as how it was
decoded. Event FIFO decoding has its own suite,
ocp_internal_log_event_fifo_mock_test.py.

Tests in this module verify:
  * Fetching: the host log's header read creates a new snapshot and the
    body reads retain it, the controller log is read from LID 08h, both
    cover exactly the requested data areas, the string log is read with
    the OCP UUID index (or index 0 under --no-uuid), the saved files
    match what the drive returned, and fetch failures are reported.
  * Decoding a fetched log gives the same report as decoding the same
    bytes from files.
  * The telemetry header, Reason Identifier, Data Area 1 header and SMART
    sections decode to the values in the log, for host and controller
    logs.
  * Data Area 1 and 2 statistics: every descriptor field, names from the
    string log and the built-in table, the bad block statistics, and the
    end-of-list identifier.
  * The statistics walk: statistics of different sizes and of none, the
    statistics size bounding it, and Context Statistic Descriptors (6Dh,
    6Eh, 6Fh) stepped over whole, their context data and encapsulated
    statistics left undecoded.
  * Option handling: the controller telemetry support gate, the log ID
    check, invalid -a, -t and -o values, and -o json.

Known defects are covered by expectedFailure tests asserting the correct
behavior: a controller log's JSON header is decoded with the host
header's layout, -a 3 and -a 4 decode only Data Area 1, and invalid -a
and -t values exit 0.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_internal_log_mock_test.py <nvme-binary> <mock-lib>
"""
import os
import struct
import unittest

from tests.cli.ocp.ocp_mock_test import (CNS_UUID_LIST, LPA_TELEMETRY,
                                         MODES, NSID_ALL, SC_INVALID_FIELD,
                                         STR_DA_STATS, OCPInternalLogTestBase,
                                         OCPMockServer, main, pack_id_ctrl,
                                         text_fields, text_records)
from tests.e2e.plugins.ocp import ocp_telemetry_layout as layout

# Get Log Page Log Specific Parameter for the host-initiated log.
LSP_RETAIN = 0
LSP_CREATE = 1

LPA_TELEMETRY_DA4 = 0x40

OPC_SET_FEATURES = 0x09
OPC_GET_FEATURES = 0x0A
FID_HOST_BEHAVIOR = 0x16
# struct nvme_feat_host_behavior: 512 bytes, ETDAS at byte 1.
HOST_BEHAVIOR_SIZE = 512
HOST_BEHAVIOR_ETDAS = 1

FETCH_TELEMETRY_MSG = 'Failed to fetch telemetry-log from the drive.'
FETCH_STRING_MSG = 'Failed to fetch string-log from the drive.'
NO_UUID_MSG = 'No OCP UUID index found'

FIFO_ID = layout.virtual_fifo_id(2, 0x21)
EVENTS_DA1 = [layout.virtual_fifo_event(FIFO_ID, 0x21),
              layout.event(layout.CLASS_PCIE, 0x31, b'\xA1\xA2\xA3\xA4')]
EVENTS_DA2 = [layout.event(layout.CLASS_NVME, 0x32, bytes(8))]


def telemetry_log(lid=layout.LID_TELEMETRY_HOST, **kwargs):
    kwargs.setdefault('fifos', {1: layout.Fifo(1, EVENTS_DA1),
                                2: layout.Fifo(2, EVENTS_DA2)})
    kwargs.setdefault('da1_stats', [layout.statistic(0x22, bytes(8))])
    kwargs.setdefault('da2_stats', [layout.statistic(0x23, bytes(8))])
    return layout.pack_telemetry(lid=lid, **kwargs)


def string_log():
    return layout.pack_string_log(
        fifo_names={1: 'HOST FIFO', 2: 'PHYS FIFO 02'},
        event_strings={(layout.CLASS_VIRTUAL_FIFO, 0x21): 'VFIFO EVT'},
        vu_event_strings={(layout.CLASS_VIRTUAL_FIFO, FIFO_ID): 'VFIFO 2.33'})


def data_area_end(telemetry, da):
    last_block = layout.data_area_last_blocks(telemetry)[da - 1]
    return layout.HEADER_SIZE + last_block * layout.BLOCK_SIZE


class TestInternalLogFetch(OCPInternalLogTestBase):
    """Reading the logs from the drive."""

    def setUp(self):
        super().setUp()
        self.host = telemetry_log()
        self.ctrl = telemetry_log(lid=layout.LID_TELEMETRY_CTRL)
        self.strings = string_log()
        self.server.logs = {layout.LID_TELEMETRY_HOST: self.host,
                            layout.LID_TELEMETRY_CTRL: self.ctrl,
                            layout.LID_STRING_LOG: self.strings}

    def saved(self, suffix):
        with open(f'{self.out_prefix}-{suffix}.bin', 'rb') as f:
            return f.read()

    def assert_covers(self, reads, start, end):
        """@reads are back to back and span [@start, @end)."""
        offset = start
        for read in reads:
            self.assertEqual(read['lpo'], offset, reads)
            offset += read['len']
        self.assertEqual(offset, end, reads)

    def test_host_header_read_creates_a_snapshot(self):
        self.assertOk(self.run_internal_log())
        header = self.server.log_reads(layout.LID_TELEMETRY_HOST)[0]
        self.assertEqual((header['lsp'], header['lpo'], header['len']),
                         (LSP_CREATE, 0, layout.HEADER_SIZE))

    def test_host_body_reads_retain_the_snapshot(self):
        """The body is read from the snapshot the header read created,
        not a new one per chunk."""
        for da in (1, 2):
            with self.subTest(data_area=da):
                self.assertOk(self.run_internal_log('-a', str(da)))
                body = self.server.log_reads(layout.LID_TELEMETRY_HOST)[1:]
                self.assertTrue(body)
                self.assertEqual({r['lsp'] for r in body}, {LSP_RETAIN})
                self.assert_covers(body, layout.HEADER_SIZE,
                                   data_area_end(self.host, da))
                self.assertEqual(self.saved('telemetry'),
                                 self.host[:data_area_end(self.host, da)])

    def test_controller_log_is_read_from_lid_08h(self):
        self.assertOk(self.run_internal_log('-t', 'controller', '-a', '2'))
        self.assertEqual(self.server.log_reads(layout.LID_TELEMETRY_HOST), [])
        reads = self.server.log_reads(layout.LID_TELEMETRY_CTRL)
        self.assertEqual({r['lsp'] for r in reads}, {0})
        self.assertEqual(reads[0]['len'], layout.HEADER_SIZE)
        self.assert_covers(reads, 0, data_area_end(self.ctrl, 2))
        self.assertEqual(self.saved('telemetry'), self.ctrl)

    def test_telemetry_is_read_without_a_namespace(self):
        self.assertOk(self.run_internal_log())
        reads = (self.server.log_reads(layout.LID_TELEMETRY_HOST)
                 + self.server.log_reads(layout.LID_TELEMETRY_CTRL))
        self.assertEqual({r['nsid'] for r in reads}, {0})

    def test_string_log_is_read_with_the_ocp_uuid_index(self):
        """The 432-byte header first, then the whole log its table sizes
        add up to, both with the OCP UUID's 1-based index in CDW14."""
        self.server.uuid_slot = 1
        self.assertOk(self.run_internal_log())
        reads = self.server.log_reads(layout.LID_STRING_LOG)
        self.assertEqual((reads[0]['lpo'], reads[0]['len']),
                         (0, layout.STR_HEADER_SIZE))
        self.assert_covers(reads[1:], 0, len(self.strings))
        self.assertEqual({r['nsid'] for r in reads}, {NSID_ALL})
        self.assertEqual({r['cdw14'] & 0x7F for r in reads}, {2})
        self.assertEqual(self.saved('string'), self.strings)

    def test_no_uuid_reads_the_string_log_with_index_zero(self):
        self.server.uuid_slot = None
        for flag in ('--no-uuid', '-n'):
            with self.subTest(flag=flag):
                self.assertOk(self.run_internal_log(flag))
                self.assertEqual(
                    self.server.identify_requests(CNS_UUID_LIST), [])
                reads = self.server.log_reads(layout.LID_STRING_LOG)
                self.assertTrue(reads)
                self.assertEqual({r['cdw14'] & 0x7F for r in reads}, {0})

    def test_missing_ocp_uuid_fails_the_string_log_fetch(self):
        self.server.uuid_slot = None
        result = self.run_internal_log()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(NO_UUID_MSG, result.stderr)
        self.assertIn(FETCH_STRING_MSG, result.stderr)
        self.assertEqual(self.server.log_reads(layout.LID_STRING_LOG), [])
        self.assertFalse(os.path.exists(self.report_path('json')))

    def test_failed_header_read_is_reported(self):
        self.server.logs[layout.LID_TELEMETRY_HOST] = SC_INVALID_FIELD
        result = self.run_internal_log()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(FETCH_TELEMETRY_MSG, result.stderr)
        self.assertEqual(self.server.log_reads(layout.LID_STRING_LOG), [])
        self.assertFalse(os.path.exists(self.report_path('json')))

    def test_fetched_logs_decode_like_the_same_files(self):
        for args in ((), ('-t', 'controller')):
            with self.subTest(args=args):
                fetched = self.decode(None, None, '-a', '2', *args)
                lid = (layout.LID_TELEMETRY_CTRL if args
                       else layout.LID_TELEMETRY_HOST)
                from_files = self.decode(self.server.logs[lid], self.strings,
                                         '-a', '2', *args,
                                         prefix=self.out_prefix + '-files')
                self.assertEqual(fetched, from_files)
                fifo = fetched['Data Area 1 Event FIFO info'][
                    'EVENT FIFO 1 - HOST FIFO']
                self.assertEqual(fifo[0]['VU Virtual FIFO String'],
                                 'VFIFO 2.33')


class HostBehaviorMockServer(OCPMockServer):
    """Keeps Host Behavior Support's ETDAS bit across commands.

    libmock_nvme.c does not forward a command's outgoing data, so the
    value a Set Features writes is invisible here. Every write this path
    makes flips the bit, so a write is modeled as flipping it."""

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.etdas = False

    def respond(self, conn, cmd):
        if (cmd['opcode'] in (OPC_GET_FEATURES, OPC_SET_FEATURES)
                and cmd['cdw10'] & 0xFF == FID_HOST_BEHAVIOR):
            if cmd['opcode'] == OPC_SET_FEATURES:
                self.etdas = not self.etdas
                self.send_response(conn, 0)
                return
            data = bytearray(HOST_BEHAVIOR_SIZE)
            data[HOST_BEHAVIOR_ETDAS] = int(self.etdas)
            self.send_slice(conn, bytes(data), 0, cmd['len'])
            return
        super().respond(conn, cmd)


class TestInternalLogDataArea4(OCPInternalLogTestBase):
    """Data Area 4 is readable only while ETDAS is set."""

    server_class = HostBehaviorMockServer

    def setUp(self):
        super().setUp()
        self.host = telemetry_log()
        self.server.logs = {layout.LID_TELEMETRY_HOST: self.host,
                            layout.LID_STRING_LOG: string_log()}
        self.server.identify = pack_id_ctrl(LPA_TELEMETRY | LPA_TELEMETRY_DA4)

    def sequence(self):
        """Host Behavior writes and telemetry reads, in order."""
        return ['set' if c['opcode'] == OPC_SET_FEATURES else 'read'
                for c in self.server.commands
                if (c['opcode'] == OPC_SET_FEATURES
                    and c['cdw10'] & 0xFF == FID_HOST_BEHAVIOR)
                or c.get('lid') == layout.LID_TELEMETRY_HOST]

    def test_etdas_is_set_for_the_read_and_cleared_after(self):
        self.assertOk(self.run_internal_log('-a', '4'))
        sequence = self.sequence()
        self.assertEqual(sequence[0], 'set', sequence)
        self.assertEqual(sequence[-1], 'set', sequence)
        self.assertEqual(sequence.count('set'), 2, sequence)
        self.assertFalse(self.server.etdas)
        reads = self.server.log_reads(layout.LID_TELEMETRY_HOST)
        self.assertEqual(reads[-1]['lpo'] + reads[-1]['len'],
                         data_area_end(self.host, 4))

    def test_etdas_already_set_is_left_alone(self):
        self.server.etdas = True
        self.assertOk(self.run_internal_log('-a', '4'))
        self.assertNotIn('set', self.sequence())
        self.assertTrue(self.server.etdas)

    def test_data_area_4_needs_extended_telemetry_support(self):
        """Without LPA bit 6 the controller has no Data Area 4 to read."""
        self.server.identify = pack_id_ctrl()
        result = self.run_internal_log('-a', '4')
        self.assertIn('Telemetry data area 4 not supported by device.',
                      result.stderr)
        self.assertEqual(self.sequence(), [])


class TestInternalLogHeaders(OCPInternalLogTestBase):
    """The fixed-layout sections ahead of the statistics."""

    def _telemetry(self, lid=layout.LID_TELEMETRY_HOST):
        reason = layout.HDR_REASON_ID
        da1 = layout.DA1_START
        return telemetry_log(lid=lid, overlay={
            layout.HDR_IEEE_OUI: b'\x12\x34\x56',
            layout.HDR_BYTE_380: b'\x11\x22\x33\x44',
            reason + layout.REASON_ERROR_ID: bytes(range(64)),
            reason + layout.REASON_FILE_ID: struct.pack('<Q', 0x0102030405),
            reason + layout.REASON_LINE_NUMBER: struct.pack('<H', 0x1234),
            reason + layout.REASON_VALID_FLAGS: b'\x07',
            reason + layout.REASON_VU_EXTENSION: bytes(range(0x80, 0xA0)),
            da1 + layout.DA1_MAJOR_VERSION: struct.pack('<HH', 5, 2),
            da1 + layout.DA1_PROFILES_SUPPORTED: b'\x03\x01',
            da1 + layout.DA1_STRING_LOG_SIZE: struct.pack('<Q', 0x1234),
            da1 + layout.DA1_SMART: b'\x05\x40\x01',
            da1 + layout.DA1_SMART_EXTENDED: b'\x10',
        })

    def _header_expected(self, telemetry):
        dalb = layout.data_area_last_blocks(telemetry)
        label = 'Telemetry Host-Initiated Data Area {} Last Block'
        return {
            'LogIdentifier': f'0x{telemetry[0]:02x}',
            'IEEE OUI Identifier': '0x123456',
            label.format(1): f'0x{dalb[0]:04x}',
            label.format(2): f'0x{dalb[1]:04x}',
            label.format(3): f'0x{dalb[2]:04x}',
            label.format(4): f'0x{dalb[3]:x}',
        }

    _HOST_BYTES_380_383 = {
        'Telemetry Host-Initiated Scope': '0x11',
        'Telemetry Host Initiated Generation Number': '0x22',
        'Telemetry Host-Initiated Data Available': '0x33',
        'Telemetry Controller-Initiated Data Generation Number': '0x44',
    }
    _CTRL_BYTES_381_383 = {
        'Telemetry Controller-Initiated Scope': '0x22',
        'Telemetry Controller-Initiated Data Available': '0x33',
        'Telemetry Controller-Initiated Data Generation Number': '0x44',
    }

    _REASON_EXPECTED = {
        'Error ID': '0x' + layout.hex_upper(bytes(range(64))),
        'File ID': '0x102030405',
        'Line Number': '0x1234',
        'Valid Flags': '0x07',
        'VU Reason Extension': '0x' + layout.hex_upper(bytes(range(0x80,
                                                                   0xA0))),
    }

    def _da1_expected(self, telemetry):
        fifo1, fifo2 = layout.fifo_table(telemetry)[:2]
        return {
            'Major Version': '0x0005',
            'Minor Version': '0x0002',
            'Number Telemetry Profiles Supported': '0x03',
            'Telemetry Profile Selected': '0x01',
            'Telemetry String Log Size': '0x1234',
            'Event FIFO 1 Data Area': '0x01',
            'Event FIFO 1 Start': f'0x{fifo1.start_dw:x}',
            'Event FIFO 1 Size': f'0x{fifo1.size_dw:x}',
            'Event FIFO 2 Data Area': '0x02',
            'Event FIFO 2 Start': f'0x{fifo2.start_dw:x}',
            'Event FIFO 2 Size': f'0x{fifo2.size_dw:x}',
            'Event FIFO 3 Data Area': '0x00',
        }

    def _sections(self, report):
        """(header, reason, DA1 header, SMART, SMART extended) fields."""
        if isinstance(report, dict):
            header = dict(report['Log Page Header'])
            reason = header.pop('Reason Identifier')
            da1 = dict(report['Telemetry Host-Initiated Data Block 1'])
            smart = da1.pop('SMART / Health Information Log(LID-02h)')
            smart_ext = da1.pop('SMART / Health Information Extended(LID-C0h)')
            return header, reason, da1, smart, smart_ext
        return tuple(text_fields(self.section(report, title)) for title in (
            'Log Page Header', 'Reason Identifier',
            'Telemetry Host-Initiated Data Block 1',
            'SMART / Health Information Log(LID-02h)',
            'SMART / Health Information Extended(LID-C0h)'))

    def assertSubset(self, expected, actual):
        for key, value in expected.items():
            with self.subTest(field=key):
                self.assertIn(key, actual)
                self.assertEqual(actual[key], value)

    def test_host_log_sections(self):
        telemetry = self._telemetry()
        for mode in MODES:
            with self.subTest(mode=mode):
                header, reason, da1, smart, smart_ext = self._sections(
                    self.decode(telemetry, string_log(), mode=mode))
                self.assertSubset({**self._header_expected(telemetry),
                                   **self._HOST_BYTES_380_383}, header)
                self.assertSubset(self._REASON_EXPECTED, reason)
                self.assertSubset(self._da1_expected(telemetry), da1)
                self.assertSubset({'Critical Warning': '0x05',
                                   'Composite Temperature': '0x0140'}, smart)
                self.assertSubset({'Physical Media Units Written': '0x10'},
                                  smart_ext)

    def test_reserved_fields_are_not_reported(self):
        for mode in MODES:
            with self.subTest(mode=mode):
                for fields in self._sections(
                        self.decode(self._telemetry(), string_log(),
                                    mode=mode)):
                    self.assertEqual(
                        [k for k in fields if 'Reserved' in k], [])

    def test_controller_log_in_text(self):
        telemetry = self._telemetry(layout.LID_TELEMETRY_CTRL)
        header, reason, da1, _, _ = self._sections(self.decode(
            telemetry, string_log(), '-t', 'controller', mode='text'))
        self.assertSubset({**self._header_expected(telemetry),
                           **self._CTRL_BYTES_381_383}, header)
        self.assertNotIn('Telemetry Host-Initiated Scope', header)
        self.assertSubset(self._REASON_EXPECTED, reason)
        self.assertSubset(self._da1_expected(telemetry), da1)

    @unittest.expectedFailure
    def test_controller_log_in_json(self):
        """Defect: the JSON printer decodes every log with the host
        header's layout, so a controller log's scope, data available and
        generation number come out under host labels, one byte off."""
        telemetry = self._telemetry(layout.LID_TELEMETRY_CTRL)
        header, _, _, _, _ = self._sections(self.decode(
            telemetry, string_log(), '-t', 'controller'))
        self.assertSubset(self._CTRL_BYTES_381_383, header)
        self.assertNotIn('Telemetry Host-Initiated Scope', header)


def stat_expected(stat_id, name, size_dw, behavior=0, info_reserved=0,
                  nsid=0, valid=0, reserved=0):
    return {
        'Statistics Identifier': f'0x{stat_id:x}',
        'Statistic Identifier String': name,
        'Statistics Info Behavior Type': f'0x{behavior:x}',
        'Statistics Info Reserved': f'0x{info_reserved:x}',
        'Namespace Identifier': f'0x{nsid:x}',
        'Namespace Information Valid': f'0x{valid:x}',
        'Statistic Data Size': f'0x{size_dw:x}',
        'Reserved': f'0x{reserved:x}',
    }


# One context per Context Statistic Descriptor type. The NSID needs the
# 32 bits only 6Dh's context field has.
CONTEXTS = {
    layout.STAT_NAMESPACE_ID_CONTEXT: layout.namespace_id_context(0x12345678),
    layout.STAT_CONTROLLER_ID_CONTEXT: layout.controller_id_context(0x0102),
    layout.STAT_QUEUE_ID_CONTEXT: layout.queue_id_context(0x0304, 0x0506),
}
CONTEXT_NAMES = {
    layout.STAT_NAMESPACE_ID_CONTEXT:
        'Namespace ID Context Statistic Descriptor',
    layout.STAT_CONTROLLER_ID_CONTEXT:
        'Controller ID Context Statistic Descriptor',
    layout.STAT_QUEUE_ID_CONTEXT: 'Queue ID Context Statistic Descriptor',
}


def context_expected(stat_id, name, payload):
    """A Context Statistic Descriptor the decoder does not look into: the
    Context Index flag shows in the Statistic Information bits it reports
    as reserved, and @payload as undecoded Statistic Specific Data."""
    return {**stat_expected(stat_id, name, len(payload) // layout.DWORD,
                            info_reserved=layout.STAT_INFO_CONTEXT_INDEX >> 4),
            'Statistic Specific Data': layout.hex_upper(payload)}


class TestInternalLogStatistics(OCPInternalLogTestBase):
    """parse_statistics() and parse_statistic()."""

    def statistics(self, telemetry, strings, *args, mode='json', da=1):
        report = self.decode(telemetry, strings, *args, mode=mode)
        section = self.section(report, STR_DA_STATS.format(da))
        return section if mode == 'json' else text_records(section)

    def assert_statistics(self, da1_stats, expected, strings=None, **kwargs):
        telemetry = layout.pack_telemetry(da1_stats=da1_stats, **kwargs)
        for mode in MODES:
            with self.subTest(mode=mode):
                got = self.statistics(telemetry,
                                      strings or layout.pack_string_log(),
                                      mode=mode)
                self.assertEqual(got, expected)
                self.assertEqual([list(s) for s in got],
                                 [list(s) for s in expected],
                                 'fields are out of order')

    def test_descriptor_fields(self):
        stat = layout.statistic(0x01, bytes.fromhex('0102030405060708'),
                                behavior=3, info_reserved=0xA, nsid=0x45,
                                ns_valid=True, reserved=0x1234)
        self.assert_statistics([stat], [{
            **stat_expected(0x01, 'Outstanding Admin Commands', 2,
                            behavior=3, info_reserved=0xA, nsid=0x45,
                            valid=1, reserved=0x1234),
            'Statistic Specific Data': '0102030405060708',
        }])

    def test_names_from_the_string_log_and_the_built_in_table(self):
        """The string log names a statistic first; identifiers up to 6Fh
        fall back to the spec's names, and others stay unnamed."""
        ids = {
            0x0022: 'XOR Recovery Count',
            0x0023: 'CUSTOM UREC',
            0x006F: 'Queue ID Context Statistic Descriptor',
            0x0070: '',
            0x8001: 'VENDOR STAT',
            0x8002: '',
        }
        strings = layout.pack_string_log(stat_strings={
            0x0023: 'CUSTOM UREC', 0x8001: 'VENDOR STAT'})
        self.assert_statistics(
            [layout.statistic(i, b'\xAB\xCD\xEF\x01') for i in ids],
            [{**stat_expected(i, name, 1),
              'Statistic Specific Data': 'ABCDEF01'}
             for i, name in ids.items()], strings)

    def test_bad_block_statistics(self):
        """Max die, max NAND channel and min NAND channel bad blocks carry
        a percentage byte and a raw count at byte 2. The printers format
        them with different widths, so only the numbers are compared."""
        keys = {
            0x1B: ('Worst die % of bad blocks',
                   'Worst die raw number of bad blocks'),
            0x1C: ('Worst NAND channel % of bad blocks',
                   'Worst NAND channel number of bad blocks'),
            0x1D: ('Best NAND channel % of bad blocks',
                   'Best NAND channel number of bad blocks'),
        }
        telemetry = layout.pack_telemetry(da1_stats=[
            layout.statistic(i, bytes([i, 0]) + struct.pack('<H', 0x1200 + i))
            for i in keys])
        for mode in MODES:
            with self.subTest(mode=mode):
                stats = self.statistics(telemetry, layout.pack_string_log(),
                                        mode=mode)
                self.assertEqual(len(stats), len(keys))
                for stat, (stat_id, (percent, raw)) in zip(stats,
                                                           keys.items()):
                    with self.subTest(stat_id=stat_id):
                        self.assertNotIn('Statistic Specific Data', stat)
                        self.assertEqual(int(stat[percent], 16), stat_id)
                        self.assertEqual(int(stat[raw], 16), 0x1200 + stat_id)

    def test_context_descriptor_names(self):
        """Context Statistic Descriptors are named like any statistic: by
        the string log first, else by the spec's names."""
        custom = 'CUSTOM CNTLID CONTEXT'
        string_logs = (
            (None, {}),
            (layout.pack_string_log(stat_strings={
                layout.STAT_CONTROLLER_ID_CONTEXT: custom}),
             {layout.STAT_CONTROLLER_ID_CONTEXT: custom}),
        )
        for strings, overrides in string_logs:
            with self.subTest(string_log=bool(overrides)):
                names = {**CONTEXT_NAMES, **overrides}
                self.assert_statistics(
                    [layout.context_statistic(i, c)
                     for i, c in CONTEXTS.items()],
                    [context_expected(i, names[i], c)
                     for i, c in CONTEXTS.items()],
                    strings)

    def test_context_descriptors_are_stepped_over_whole(self):
        """A container's Statistic Data Size spans its context data and
        every statistic it encapsulates, so the walk steps over it in one
        stride: no encapsulated descriptor surfaces as a statistic of its
        own, and the statistic after the last container decodes. The
        container's payload comes out as undecoded Statistic Specific Data;
        decoding it is OCP 2.7 work, and only that expectation should
        change with it."""
        inner = [layout.statistic(0x01, bytes.fromhex('0A0B0C0D')),
                 layout.statistic(0x04, bytes(range(12)), behavior=1,
                                  nsid=5, ns_valid=True)]
        inner_dw = sum(len(s) for s in inner) // layout.DWORD
        stats, expected = [], []
        for stat_id, context in CONTEXTS.items():
            stats.append(layout.context_statistic(stat_id, context, inner))
            fields = context_expected(stat_id, CONTEXT_NAMES[stat_id],
                                      context + b''.join(inner))
            self.assertEqual(fields['Statistic Data Size'],
                             f'0x{layout.CONTEXT_DATA_DWORDS + inner_dw:x}')
            expected.append(fields)
        stats.append(layout.statistic(0x22, b'12345678'))
        expected.append({**stat_expected(0x22, 'XOR Recovery Count', 2),
                         'Statistic Specific Data': '3132333435363738'})
        self.assert_statistics(stats, expected)

    def test_statistic_without_data(self):
        """A Statistic Data Size of 0 leaves just the descriptor, and the
        next statistic starts right after it."""
        self.assert_statistics(
            [layout.statistic(0x01, bytes(4)), layout.statistic(0x02),
             layout.statistic(0x03, bytes.fromhex('0A0B0C0D'))],
            [{**stat_expected(0x01, 'Outstanding Admin Commands', 1),
              'Statistic Specific Data': '00000000'},
             {**stat_expected(0x02, 'Host Write Bandwidth', 0),
              'Statistic Specific Data': ''},
             {**stat_expected(0x03, 'GC Write Bandwidth', 1),
              'Statistic Specific Data': '0A0B0C0D'}])

    def test_statistics_of_different_sizes(self):
        sizes = {
            0x05: ('Internal Write Workload', 1),
            0x06: ('Internal Read Workload', 3),
            0x07: ('Internal Write Queue Depth', 8),
        }
        data = {i: bytes((i * 0x10 + n) & 0xFF for n in range(size * 4))
                for i, (_, size) in sizes.items()}
        self.assert_statistics(
            [layout.statistic(i, data[i]) for i in sizes],
            [{**stat_expected(i, name, size),
              'Statistic Specific Data': layout.hex_upper(data[i])}
             for i, (name, size) in sizes.items()])

    def test_statistics_end_at_the_statistics_size(self):
        """The walk stops at the size the OCP header declares, even with
        another statistic right after it."""
        first = layout.statistic(0x01, bytes(4))
        size_field = layout.DA1_START + layout.DA1_STAT_SIZE
        self.assert_statistics(
            [first, layout.statistic(0x02, bytes(4))],
            [{**stat_expected(0x01, 'Outstanding Admin Commands', 1),
              'Statistic Specific Data': '00000000'}],
            overlay={size_field: struct.pack('<Q',
                                             len(first) // layout.DWORD)})

    def test_identifier_zero_ends_the_list(self):
        self.assert_statistics(
            [layout.statistic(0x01, bytes(4)), layout.statistic(0),
             layout.statistic(0x02, bytes(4))],
            [{**stat_expected(0x01, 'Outstanding Admin Commands', 1),
              'Statistic Specific Data': '00000000'}])

    def test_no_statistics(self):
        self.assert_statistics([], [])

    def test_data_area_2_statistics(self):
        telemetry = layout.pack_telemetry(
            da1_stats=[layout.statistic(0x01, bytes(4))],
            da2_stats=[layout.statistic(0x02, bytes.fromhex('0A0B0C0D'))])
        strings = layout.pack_string_log()
        for mode in MODES:
            with self.subTest(mode=mode):
                self.assertEqual(
                    self.statistics(telemetry, strings, '-a', '2',
                                    mode=mode, da=2),
                    [{**stat_expected(0x02, 'Host Write Bandwidth', 1),
                      'Statistic Specific Data': '0A0B0C0D'}])
                self.assertEqual(
                    len(self.statistics(telemetry, strings, '-a', '2',
                                        mode=mode)), 1)
        report = self.decode(telemetry, strings)
        self.assertNotIn(STR_DA_STATS.format(2), report)


class TestInternalLogOptions(OCPInternalLogTestBase):
    """Command options and the checks made before decoding."""

    def test_controller_log_needs_telemetry_support(self):
        """A controller without LPA bit 3 has no controller-initiated log
        to decode, so nothing is written."""
        self.server.identify = pack_id_ctrl(lpa=0)
        result = self.run_internal_log(
            '-t', 'controller',
            telemetry=telemetry_log(lid=layout.LID_TELEMETRY_CTRL),
            strings=string_log())
        self.assertIn('Extracting Telemetry Controller Dump', result.stdout)
        for mode in MODES:
            self.assertFalse(os.path.exists(self.report_path(mode)))

    def test_log_that_is_not_telemetry_is_rejected(self):
        telemetry = telemetry_log(overlay={layout.HDR_LID: b'\x05'})
        result = self.run_internal_log(telemetry=telemetry,
                                       strings=string_log())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Invalid LogPageId [0x05]', result.stderr)
        self.assertFalse(os.path.exists(self.report_path('json')))

    def test_invalid_output_format_is_rejected(self):
        result = self.run_internal_log('-o', 'bogus',
                                       telemetry=telemetry_log(),
                                       strings=string_log())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Invalid output format', result.stderr)
        self.assertFalse(os.path.exists(self.report_path('json')))

    def test_explicit_json_matches_the_default(self):
        default = self.decode(telemetry_log(), string_log())
        explicit = self.decode(telemetry_log(), string_log(), '-o', 'json')
        self.assertEqual(default, explicit)

    def _invalid_option(self, *args):
        """Run with a bad option and no -l/-s, so any attempt to go on
        would show up as a log read."""
        result = self.run_internal_log(*args)
        self.assertEqual(self.server.log_reads(), [])
        for mode in MODES:
            self.assertFalse(os.path.exists(self.report_path(mode)))
        return result

    def test_invalid_data_area_is_rejected(self):
        for value in ('5', '-1'):
            with self.subTest(data_area=value):
                result = self._invalid_option('-a', value)
                self.assertIn('Invalid data-area specified', result.stdout)

    def test_invalid_telemetry_type_is_rejected(self):
        result = self._invalid_option('-t', 'bogus')
        self.assertIn('telemetry-type should be host, host0, host1 or '
                      'controller.', result.stderr)

    @unittest.expectedFailure
    def test_invalid_data_area_exits_nonzero(self):
        """Defect: the data area check jumps out with err still 0."""
        self.assertNotEqual(self._invalid_option('-a', '5').returncode, 0)

    @unittest.expectedFailure
    def test_invalid_telemetry_type_exits_nonzero(self):
        """Defect: the telemetry type check jumps out with err still 0."""
        self.assertNotEqual(self._invalid_option('-t', 'bogus').returncode,
                            0)

    @unittest.expectedFailure
    def test_data_areas_3_and_4_include_data_area_2(self):
        """Defect: -a documents "Data Areas 1, 2, and 3" for 3 (and 1..4
        for 4), but the printers decode Data Area 2 only for -a 2."""
        for value in ('3', '4'):
            with self.subTest(data_area=value):
                report = self.decode(telemetry_log(), string_log(),
                                     '-a', value)
                self.assertIn('Data Area 2 Event FIFO info', report)
                self.assertIn(STR_DA_STATS.format(2), report)


if __name__ == '__main__':
    main()
