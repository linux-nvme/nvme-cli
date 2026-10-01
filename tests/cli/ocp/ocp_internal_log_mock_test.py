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
  * Fetching: the host log's header read creates a new snapshot unless
    --host-generate=0 asks for the existing one, the body reads retain
    it, the deprecated host0 and host1 types warn and map onto
    --host-generate, the controller log is read from LID 08h and ignores
    --host-generate, both cover exactly the requested data areas, the
    string log is read with the OCP UUID index (or index 0 under --no-uuid), the saved files
    match what the drive returned, and fetch failures are reported.
  * Decoding a fetched log gives the same report as decoding the same
    bytes from files.
  * The telemetry header, Reason Identifier, Data Area 1 header and SMART
    sections decode to the values in the log, for host and controller
    logs.
  * Data Area 1 and 2 statistics: every descriptor field, each
    Statistic Information field from its own bits, names from the string
    log and the built-in table, the bad block statistics and one too
    short for its fields, and the end-of-list identifier.
  * The statistics walk: statistics of different sizes and of none, the
    statistics size bounding it, and a statistic running past that size
    being reported.
  * Context Statistic Descriptors (6Dh, 6Eh, 6Fh, and any statistic with
    the Context Index flag): the context data and each type's scope
    fields, the encapsulated statistics as records of their own, an
    invalid Context Data Size reported without changing where they
    start, a container too small for its context data, containers that
    nest, encapsulated statistics running past their container, and the
    end-of-list identifier inside one. Two containers are checked
    against a customer's example report, field for field.
  * Option handling: the controller telemetry support gate, the log ID
    check, -a 3 and -a 4 decoding Data Area 2, invalid -a, -t and -o
    values, and -o json.

Known defects are covered by expectedFailure tests asserting the correct
behavior: a controller log's JSON header is decoded with the host
header's layout, and invalid -a and -t values exit 0.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_internal_log_mock_test.py <nvme-binary> <mock-lib>
"""
import json
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

    def host_header_lsp(self, *args):
        result = self.assertOk(self.run_internal_log(*args))
        reads = self.server.log_reads(layout.LID_TELEMETRY_HOST)
        self.assertEqual((reads[0]['lpo'], reads[0]['len']),
                         (0, layout.HEADER_SIZE))
        self.assertEqual({r['lsp'] for r in reads[1:]}, {LSP_RETAIN})
        self.assertEqual(self.saved('telemetry'),
                         self.host[:data_area_end(self.host, 1)])
        return reads[0]['lsp'], result

    def test_host_generate_selects_create_or_retain(self):
        for args, lsp in ((('--host-generate=0',), LSP_RETAIN),
                          (('-g', '0'), LSP_RETAIN),
                          (('-t', 'host', '-g', '0'), LSP_RETAIN),
                          (('--host-generate=1',), LSP_CREATE),
                          (('-g', '1'), LSP_CREATE),
                          (('-t', 'host'), LSP_CREATE)):
            with self.subTest(args=args):
                got, result = self.host_header_lsp(*args)
                self.assertEqual(got, lsp)
                self.assertNotIn('deprecated', result.stderr)

    def test_deprecated_host_types_warn_and_map_to_host_generate(self):
        for value, lsp, use in (
                ('host0', LSP_RETAIN,
                 "'--telemetry-type host --host-generate=0'"),
                ('host1', LSP_CREATE, "'--telemetry-type host'")):
            with self.subTest(telemetry_type=value):
                got, result = self.host_header_lsp('-t', value)
                self.assertEqual(got, lsp)
                self.assertIn(
                    f"WARNING: '--telemetry-type {value}' is deprecated and "
                    'will be removed in the next major version. Use '
                    f'{use} instead.', result.stderr)

    def test_deprecated_host_types_decode_like_host(self):
        host = self.decode(self.host, self.strings, '-a', '2')
        for value in ('host0', 'host1'):
            with self.subTest(telemetry_type=value):
                self.assertEqual(
                    self.decode(self.host, self.strings, '-a', '2',
                                '-t', value), host)

    def test_controller_log_ignores_host_generate(self):
        for value in ('0', '1'):
            with self.subTest(host_generate=value):
                self.assertOk(self.run_internal_log('-t', 'controller',
                                                    '-g', value))
                self.assertEqual(
                    self.server.log_reads(layout.LID_TELEMETRY_HOST), [])
                reads = self.server.log_reads(layout.LID_TELEMETRY_CTRL)
                self.assertEqual({r['lsp'] for r in reads}, {0})
                self.assert_covers(reads, 0, data_area_end(self.ctrl, 1))

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


def stat_expected(stat_id, name, size_dw, behavior=0, context_index=0,
                  host_hint=0, info_reserved=0, nsid=0, valid=0, nsid_15_0=0):
    return {
        'Statistics Identifier': f'0x{stat_id:x}',
        'Statistic Identifier String': name,
        'Statistics Info Behavior Type': f'0x{behavior:x}',
        'Statistics Info Context Index': f'0x{context_index:x}',
        'Statistics Info Host Hint Type': f'0x{host_hint:x}',
        'Statistics Info Reserved': f'0x{info_reserved:x}',
        'Namespace Identifier': f'0x{nsid:x}',
        'Namespace Information Valid': f'0x{valid:x}',
        'Statistic Data Size': f'0x{size_dw:x}',
        'Namespace Identifier[15:0]': f'0x{nsid_15_0:x}',
    }


def leaf_expected(stat_id, name, data=b'', **stat):
    """A statistic whose data is printed undecoded."""
    return {**stat_expected(stat_id, name, len(data) // layout.DWORD, **stat),
            'Statistic Specific Data': layout.hex_upper(data)}


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
# (name, offset, size) of each scope field, offsets into the context data.
SCOPE_FIELDS = {
    layout.STAT_NAMESPACE_ID_CONTEXT: [('Namespace ID', 4, 4)],
    layout.STAT_CONTROLLER_ID_CONTEXT: [('Controller ID', 6, 2)],
    layout.STAT_QUEUE_ID_CONTEXT: [('Controller ID', 4, 2),
                                   ('Queue ID', 6, 2)],
}

# What the decoder reports on statistics it cannot decode as laid out.
STAT_ERRORS = ('Invalid statistic', 'Context Statistic 0x')


def context_expected(stat_id, name, context, encapsulated=(),
                     context_index=1, **stat):
    """A decoded Context Statistic Descriptor: its @context data, the
    scope fields of the three defined types, and the @encapsulated
    statistics' expected records. Its data size spans the context data
    and every encapsulated descriptor."""
    size_dw = len(context) // layout.DWORD + sum(
        layout.STAT_DESCRIPTOR_SIZE // layout.DWORD
        + int(e['Statistic Data Size'], 16) for e in encapsulated)
    context_size, reserved = struct.unpack_from('<HH', context)
    expected = {
        **stat_expected(stat_id, name, size_dw, context_index=context_index,
                        **stat),
        'Context Data Size': f'0x{context_size:x}',
        'Context Data Reserved': f'0x{reserved:x}',
        'Context Scope': layout.hex_upper(context[4:8]),
    }
    if stat_id in SCOPE_FIELDS:
        expected['Context Scope Fields'] = [
            scope_field_expected(context, *field)
            for field in SCOPE_FIELDS[stat_id]]
    expected['Encapsulated Statistic Descriptors'] = list(encapsulated)
    return expected


def scope_field_expected(context, name, offset, size):
    value = int.from_bytes(context[offset:offset + size], 'little')
    return {
        'Scope Field String': name,
        'Scope Field Offset': f'0x{offset:x}',
        'Scope Field Size': f'0x{size:x}',
        'Scope Field Value': f'0x{value:x}',
    }


XOR_RECOVERY = layout.statistic(0x22, b'12345678')
XOR_RECOVERY_EXPECTED = leaf_expected(0x22, 'XOR Recovery Count', b'12345678')

INNER = [layout.statistic(0x01, bytes.fromhex('0A0B0C0D')),
         layout.statistic(0x04, bytes(range(12)), behavior=1, nsid=5,
                          ns_valid=True)]
INNER_EXPECTED = [
    leaf_expected(0x01, 'Outstanding Admin Commands',
                  bytes.fromhex('0A0B0C0D')),
    leaf_expected(0x04, 'Active Namespaces', bytes(range(12)), behavior=1,
                  nsid=5, valid=1),
]


class TestInternalLogStatistics(OCPInternalLogTestBase):
    """parse_statistics() and parse_statistic()."""

    def statistics(self, telemetry, strings, *args, mode='json', da=1):
        return self.statistics_with_output(telemetry, strings, *args,
                                           mode=mode, da=da)[0]

    def statistics_with_output(self, telemetry, strings, *args, mode='json',
                               da=1):
        report, output = self.decode_with_output(telemetry, strings, *args,
                                                 mode=mode)
        section = self.section(report, STR_DA_STATS.format(da))
        return (section if mode == 'json' else text_records(section)), output

    def assert_statistics(self, da1_stats, expected, strings=None,
                          errors=(), **kwargs):
        """Decode @da1_stats in both modes, expecting the records in
        @expected, and each of @errors reported, or no error at all."""
        telemetry = layout.pack_telemetry(da1_stats=da1_stats, **kwargs)
        for mode in MODES:
            with self.subTest(mode=mode):
                got, output = self.statistics_with_output(
                    telemetry, strings or layout.pack_string_log(),
                    mode=mode)
                self.assertEqual(got, expected)
                self.assertEqual(json.dumps(got), json.dumps(expected),
                                 'fields are out of order')
                for error in errors:
                    self.assertIn(error, output)
                if not errors:
                    for marker in STAT_ERRORS:
                        self.assertNotIn(marker, output)

    def test_descriptor_fields(self):
        stat = layout.statistic(0x01, bytes.fromhex('0102030405060708'),
                                behavior=3, host_hint=2, info_reserved=1,
                                nsid=0x45, ns_valid=True, nsid_15_0=0x1234)
        self.assert_statistics([stat], [{
            **stat_expected(0x01, 'Outstanding Admin Commands', 2,
                            behavior=3, host_hint=2, info_reserved=1,
                            nsid=0x45, valid=1, nsid_15_0=0x1234),
            'Statistic Specific Data': '0102030405060708',
        }])

    def test_statistic_information_fields(self):
        """Behavior Type, Host Hint Type and the reserved bit each come
        from their own bits of Statistic Information, with every other
        field left clear."""
        fields = [{'behavior': 0xF}, {'host_hint': 3}, {'info_reserved': 1}]
        self.assert_statistics(
            [layout.statistic(0x01, bytes(4), **f) for f in fields],
            [leaf_expected(0x01, 'Outstanding Admin Commands', bytes(4), **f)
             for f in fields])

    def test_names_from_the_string_log_and_the_built_in_table(self):
        """The string log names a statistic first; identifiers up to 6Fh
        fall back to the spec's names, and others stay unnamed."""
        ids = {
            0x0022: 'XOR Recovery Count',
            0x0023: 'CUSTOM UREC',
            0x006C: 'Proactive Bad Die Retirement',
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

    def test_bad_block_statistic_without_data(self):
        """A bad block statistic too short for its fields is printed as
        undecoded data rather than read past its end."""
        self.assert_statistics(
            [layout.statistic(0x1B), XOR_RECOVERY],
            [leaf_expected(0x1B, 'Max Die Bad Block'),
             XOR_RECOVERY_EXPECTED])

    def test_customer_queue_id_context(self):
        """A Queue ID Context Statistic Descriptor as a drive reports it,
        with a Context Data Size equal to its Statistic Data Size. The
        encapsulated descriptors still start after the two Dwords of
        context data."""
        inner = layout.statistic(0x07, bytes.fromhex('08000000'), behavior=5)
        stat = layout.context_statistic(
            layout.STAT_QUEUE_ID_CONTEXT,
            layout.queue_id_context(1, 3, context_data_size=5), [inner],
            behavior=2)
        self.assert_statistics([stat], [{
            'Statistics Identifier': '0x6f',
            'Statistic Identifier String':
                'Queue ID Context Statistic Descriptor',
            'Statistics Info Behavior Type': '0x2',
            'Statistics Info Context Index': '0x1',
            'Statistics Info Host Hint Type': '0x0',
            'Statistics Info Reserved': '0x0',
            'Namespace Identifier': '0x0',
            'Namespace Information Valid': '0x0',
            'Statistic Data Size': '0x5',
            'Namespace Identifier[15:0]': '0x0',
            'Context Data Size': '0x5',
            'Context Data Reserved': '0x0',
            'Context Scope': '01000300',
            'Context Scope Fields': [
                {'Scope Field String': 'Controller ID',
                 'Scope Field Offset': '0x4',
                 'Scope Field Size': '0x2',
                 'Scope Field Value': '0x1'},
                {'Scope Field String': 'Queue ID',
                 'Scope Field Offset': '0x6',
                 'Scope Field Size': '0x2',
                 'Scope Field Value': '0x3'},
            ],
            'Encapsulated Statistic Descriptors': [{
                'Statistics Identifier': '0x7',
                'Statistic Identifier String': 'Internal Write Queue Depth',
                'Statistics Info Behavior Type': '0x5',
                'Statistics Info Context Index': '0x0',
                'Statistics Info Host Hint Type': '0x0',
                'Statistics Info Reserved': '0x0',
                'Namespace Identifier': '0x0',
                'Namespace Information Valid': '0x0',
                'Statistic Data Size': '0x1',
                'Namespace Identifier[15:0]': '0x0',
                'Statistic Specific Data': '08000000',
            }],
        }])

    def test_customer_vendor_context(self):
        """A vendor unique statistic with the Context Index flag set is a
        Context Statistic Descriptor too. Its scope has no defined fields,
        so only the raw scope is printed."""
        inner = layout.statistic(0x9005, bytes.fromhex('2A000000'),
                                 behavior=4)
        stat = layout.context_statistic(
            0x9100, layout.context_data(bytes.fromhex('03000000'), 5),
            [inner], behavior=1)
        self.assert_statistics([stat], [{
            'Statistics Identifier': '0x9100',
            'Statistic Identifier String': '',
            'Statistics Info Behavior Type': '0x1',
            'Statistics Info Context Index': '0x1',
            'Statistics Info Host Hint Type': '0x0',
            'Statistics Info Reserved': '0x0',
            'Namespace Identifier': '0x0',
            'Namespace Information Valid': '0x0',
            'Statistic Data Size': '0x5',
            'Namespace Identifier[15:0]': '0x0',
            'Context Data Size': '0x5',
            'Context Data Reserved': '0x0',
            'Context Scope': '03000000',
            'Encapsulated Statistic Descriptors': [{
                'Statistics Identifier': '0x9005',
                'Statistic Identifier String': '',
                'Statistics Info Behavior Type': '0x4',
                'Statistics Info Context Index': '0x0',
                'Statistics Info Host Hint Type': '0x0',
                'Statistics Info Reserved': '0x0',
                'Namespace Identifier': '0x0',
                'Namespace Information Valid': '0x0',
                'Statistic Data Size': '0x1',
                'Namespace Identifier[15:0]': '0x0',
                'Statistic Specific Data': '2A000000',
            }],
        }])

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

    def test_context_descriptors_decode(self):
        """Each type's context data comes out with its scope fields, and
        the statistics it encapsulates as records of their own under it.
        The container's Statistic Data Size spans all of that, so the
        statistic after the last container decodes."""
        values = {
            layout.STAT_NAMESPACE_ID_CONTEXT: ['0x12345678'],
            layout.STAT_CONTROLLER_ID_CONTEXT: ['0x102'],
            layout.STAT_QUEUE_ID_CONTEXT: ['0x304', '0x506'],
        }
        stats, expected = [], []
        for stat_id, context in CONTEXTS.items():
            stats.append(layout.context_statistic(stat_id, context, INNER))
            fields = context_expected(stat_id, CONTEXT_NAMES[stat_id],
                                      context, INNER_EXPECTED)
            self.assertEqual([f['Scope Field Value']
                              for f in fields['Context Scope Fields']],
                             values[stat_id])
            self.assertEqual(len(fields['Encapsulated Statistic Descriptors']),
                             len(INNER))
            expected.append(fields)
        stats.append(XOR_RECOVERY)
        expected.append(XOR_RECOVERY_EXPECTED)
        self.assert_statistics(stats, expected)

    def test_context_identifier_without_the_flag(self):
        """6Dh-6Fh are Context Statistic Descriptors even with the Context
        Index flag clear."""
        stat_id = layout.STAT_QUEUE_ID_CONTEXT
        self.assert_statistics(
            [layout.context_statistic(stat_id, CONTEXTS[stat_id], INNER,
                                      context_index=False)],
            [context_expected(stat_id, CONTEXT_NAMES[stat_id],
                              CONTEXTS[stat_id], INNER_EXPECTED,
                              context_index=0)])

    def test_invalid_context_data_size(self):
        """A Context Data Size of 0, or one larger than the Statistic Data
        Size, is reported; the encapsulated descriptors still follow the
        two Dwords of context data."""
        stat_id = layout.STAT_CONTROLLER_ID_CONTEXT
        for size in (0, 0x40, 0xFFFF):
            with self.subTest(context_data_size=size):
                context = layout.controller_id_context(0x0102, size)
                self.assert_statistics(
                    [layout.context_statistic(stat_id, context, INNER),
                     XOR_RECOVERY],
                    [context_expected(stat_id, CONTEXT_NAMES[stat_id],
                                      context, INNER_EXPECTED),
                     XOR_RECOVERY_EXPECTED],
                    errors=[f'Context Statistic 0x6e: Context Data Size '
                            f'0x{size:x} is outside 1 to 0xa'])

    def test_context_statistic_too_small_for_its_context(self):
        """A Context Statistic Descriptor of fewer than two Dwords cannot
        hold its context data: that is reported, its data printed
        undecoded, and the walk goes on after it."""
        stat_id = layout.STAT_NAMESPACE_ID_CONTEXT
        for data in (b'', bytes.fromhex('01000000')):
            with self.subTest(size_dw=len(data) // layout.DWORD):
                self.assert_statistics(
                    [layout.context_statistic(stat_id, data), XOR_RECOVERY],
                    [leaf_expected(stat_id, CONTEXT_NAMES[stat_id], data,
                                   context_index=1),
                     XOR_RECOVERY_EXPECTED],
                    errors=[f'Context Statistic 0x6d: {len(data)} data bytes '
                            'cannot hold its context data'])

    def test_context_statistics_do_not_nest(self):
        """An encapsulated descriptor flagged as a Context Statistic
        Descriptor, or with a 6Dh-6Fh identifier, is reported and printed
        with its data undecoded; its siblings still decode."""
        flagged = layout.statistic(0x01, bytes(4), context_index=True)
        typed = layout.context_statistic(layout.STAT_NAMESPACE_ID_CONTEXT,
                                         layout.namespace_id_context(7),
                                         context_index=False)
        stat_id = layout.STAT_QUEUE_ID_CONTEXT
        where = ('Encapsulated Statistic Descriptors of Context Statistic '
                 '0x6f')
        self.assert_statistics(
            [layout.context_statistic(stat_id, CONTEXTS[stat_id],
                                      [flagged, typed, INNER[0]])],
            [context_expected(stat_id, CONTEXT_NAMES[stat_id],
                              CONTEXTS[stat_id], [
                leaf_expected(0x01, 'Outstanding Admin Commands', bytes(4),
                              context_index=1),
                leaf_expected(layout.STAT_NAMESPACE_ID_CONTEXT,
                              CONTEXT_NAMES[layout.STAT_NAMESPACE_ID_CONTEXT],
                              layout.namespace_id_context(7)),
                INNER_EXPECTED[0]])],
            errors=[f'Invalid statistic at offset 0x0 of {where}: Context '
                    'Statistic Descriptor 0x1 does not nest',
                    f'Invalid statistic at offset 0xc of {where}: Context '
                    'Statistic Descriptor 0x6d does not nest'])

    def test_encapsulated_statistic_past_its_container(self):
        """An encapsulated descriptor that runs past the end of its
        container, in its descriptor or its data, is reported and ends the
        container's list; the statistic after the container still
        decodes."""
        stat_id = layout.STAT_CONTROLLER_ID_CONTEXT
        where = ('Encapsulated Statistic Descriptors of Context Statistic '
                 '0x6e')
        long_data = bytearray(layout.statistic(0x02, bytes(8)))
        struct.pack_into('<H', long_data, 4, 4)
        cases = {
            'descriptor': (bytes.fromhex('03000000'),
                           f'Invalid statistic at offset 0xc of {where}: '
                           'descriptor needs 8 bytes, 4 left'),
            'data': (bytes(long_data),
                     f'Invalid statistic at offset 0xc of {where}: '
                     'Statistic ID 0x2 declares 16 data bytes, 8 left'),
        }
        for cut, (tail, error) in cases.items():
            with self.subTest(cut=cut):
                stat = layout.context_statistic(
                    stat_id, CONTEXTS[stat_id], [INNER[0], tail])
                expected = context_expected(stat_id, CONTEXT_NAMES[stat_id],
                                            CONTEXTS[stat_id],
                                            [INNER_EXPECTED[0]])
                expected['Statistic Data Size'] = \
                    f'0x{(len(stat) - layout.STAT_DESCRIPTOR_SIZE) // 4:x}'
                self.assert_statistics([stat, XOR_RECOVERY],
                                       [expected, XOR_RECOVERY_EXPECTED],
                                       errors=[error])

    def test_identifier_zero_ends_the_encapsulated_list(self):
        stat_id = layout.STAT_QUEUE_ID_CONTEXT
        stat = layout.context_statistic(
            stat_id, CONTEXTS[stat_id],
            [INNER[0], layout.statistic(0), INNER[1]])
        expected = context_expected(stat_id, CONTEXT_NAMES[stat_id],
                                    CONTEXTS[stat_id], [INNER_EXPECTED[0]])
        expected['Statistic Data Size'] = \
            f'0x{(len(stat) - layout.STAT_DESCRIPTOR_SIZE) // 4:x}'
        self.assert_statistics([stat, XOR_RECOVERY],
                               [expected, XOR_RECOVERY_EXPECTED])

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

    def test_statistic_past_the_statistics_size(self):
        """A statistic that runs past the size the OCP header declares, in
        its descriptor or its data, is reported and ends the walk; the
        statistics before it are kept."""
        first = layout.statistic(0x01, bytes(4))
        size_field = layout.DA1_START + layout.DA1_STAT_SIZE
        cases = {
            'descriptor': (1, 'Invalid statistic at offset 0xc of Data Area '
                              '1: descriptor needs 8 bytes, 4 left'),
            'data': (3, 'Invalid statistic at offset 0xc of Data Area 1: '
                        'Statistic ID 0x2 declares 8 data bytes, 4 left'),
        }
        for cut, (extra_dw, error) in cases.items():
            with self.subTest(cut=cut):
                size_dw = len(first) // layout.DWORD + extra_dw
                self.assert_statistics(
                    [first, layout.statistic(0x02, bytes(8))],
                    [leaf_expected(0x01, 'Outstanding Admin Commands',
                                   bytes(4))],
                    errors=[error],
                    overlay={size_field: struct.pack('<Q', size_dw)})

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

    def test_data_areas_3_and_4_include_data_area_2(self):
        """-a 3 and -a 4 decode Data Areas 1 and 2; Data Areas 3 and 4
        have no OCP layout to decode."""
        for value in ('3', '4'):
            with self.subTest(data_area=value):
                report = self.decode(telemetry_log(), string_log(),
                                     '-a', value)
                self.assertIn('Data Area 2 Event FIFO info', report)
                self.assertIn(STR_DA_STATS.format(2), report)


if __name__ == '__main__':
    main()
