#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp persistent-event-log" against a mocked controller.

The mock serves a synthetic Persistent Event log built by
tests/e2e/plugins/ocp/ocp_pel_layout.py, transcribed from the NVM Express
Base specification and the OCP 2.7 TCG Activity Event Format rather than
from nvme-cli's structs. It keeps a reporting context as a controller
does: Establish Context (01b) takes a snapshot of the log and fails with
Command Sequence Error while one is held, Read Log Data (00b) serves it
and fails with Command Sequence Error without one, and Release Context
(10b) drops it. A read returns no more than the NUMD dwords it asks for.
A reserved Action or LSP bit fails with Invalid Field in Command.

Tests in this module verify:
  * -a 1 establishes the context with a 512 byte read of the header and
    reads the rest with Action 00b, from the log page of all namespaces
    and without a UUID index; -a 1 alone only establishes it.
  * -a 0 reads the Total Log Length of an established context, and fails
    without one; -a 2 releases it; -l sets the length of the read.
  * A log length which is not a multiple of 4 is read in whole dwords,
    and no more than that length is decoded or printed.
  * A failed Get Log Page and a Generation Number which changes between
    reading the log and reading its header again fail.
  * Every field of the log header decodes in text and JSON.
  * The events are walked by their lengths, also past Vendor Specific
    Information, and the standard events decode from their offsets.
  * A TCG Activity Event is recognized by its descriptor, after the Vendor
    Specific Information, and decodes from its offsets.
  * A vendor specific event which is not a TCG Activity Event goes
    through the generic Vendor Specific Event decoder.
  * -b and -o binary print the log as read.

Known defects are covered by expectedFailure tests asserting the behavior
the specifications define: the default action is reserved, the Vendor
Specific Information is dumped from byte 1 of the event, a log length
under 512 bytes fails the Generation Number check, and the --log-len
option of the man page does not exist.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_persistent_event_log_mock_test.py <nvme-binary> <mock-lib>
"""
import json
import re
import struct
import unittest

from tests.cli.nvme_mock import (NSID_ALL, SC_CMD_SEQ_ERROR, SC_INTERNAL,
                                 SC_INVALID_FIELD, main)
from tests.cli.ocp.ocp_mock_test import OCPController, OCPMockTestBase
from tests.e2e.plugins.ocp import ocp_pel_layout as layout

SHORT_LEN_HINT = 'at least 512 bytes is required'
GEN_CHANGED_MSG = 'Collected Persistent Event Log may be invalid'
TCG_ENTRY = 'TCG Activity Event Entry'
ENTRIES = 'Persistent Event Entries:'


def dword_len(log):
    """The length of @log rounded up to a whole number of dwords, which a
    read of the whole log must ask for."""
    return (len(log) + 3) & ~3


class PELController(OCPController):
    """Serves @log as the Persistent Event log through a reporting
    context, @context, which a test may set to start with one. @on_read,
    if set, gets each Command which reads the context and the data it
    reads, and returns the data to answer it with."""

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.log = layout.pack_log()
        self.context = None
        self.on_read = None
        self.logs[layout.LID] = self._answer_pel

    def _answer_pel(self, cmd):
        action = cmd.lsp & layout.ACTION_MASK
        if cmd.lsp & ~layout.ACTION_MASK or action == layout.ACTION_RESERVED:
            return SC_INVALID_FIELD
        if action == layout.ACTION_RELEASE:
            self.context = None
            return b''
        if action == layout.ACTION_ESTABLISH:
            if self.context is not None:
                return SC_CMD_SEQ_ERROR
            self.context = bytes(self.log)
        elif self.context is None:
            return SC_CMD_SEQ_ERROR
        data = self.context[cmd.lpo:cmd.lpo + cmd.numd * 4]
        if self.on_read:
            data = self.on_read(cmd, data)
        return data


class PersistentEventLogTestBase(OCPMockTestBase):

    controller_class = PELController

    def serve(self, log):
        self.server.log = log

    def run_pel(self, *args, **kwargs):
        return self.run_ocp('persistent-event-log', *args, **kwargs)

    def reads(self):
        return self.server.log_reads(layout.LID)

    def text(self, *args):
        return self.assertOk(self.run_pel(*args)).stdout

    def json_log(self, *args):
        result = self.assertOk(self.run_pel('-o', 'json', *args))
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f'-o json output is not valid JSON ({exc}): '
                      f'{result.stdout!r}')

    def reports(self, log, *args):
        """The text and the JSON report of @log, each read in a context of
        its own."""
        self.serve(log)
        args = ('-a', str(layout.ACTION_ESTABLISH),
                '-l', str(dword_len(log))) + args
        text = self.text(*args)
        self.server.context = None
        return text, self.json_log(*args)

    def text_values(self, text, label):
        """The values of every "label : value" or "label: value" line of
        @label, in order."""
        return re.findall(rf'^\s*{re.escape(label)}\s*:\s*(.*?)\s*$', text,
                          re.M)

    def text_value(self, text, label):
        values = self.text_values(text, label)
        self.assertEqual(len(values), 1, f'{label!r} in {text!r}')
        return values[0]

    def events(self, log):
        self.assertIn('list_of_event_entries', log)
        return log['list_of_event_entries']


def sample_events():
    """A Timestamp Change event with Vendor Specific Information, and a
    Firmware Commit event without."""
    return [
        layout.pack_timestamp_change(0x0123456789AB, 0x2000, vsi=b'\xaa' * 8,
                                     cntlid=7, ets=0x1111, pelpid=3),
        layout.pack_fw_commit(b'OLDFW001', b'NEWFW002', action=3, slot=2,
                              sct=1, sc=0x07, vu_rc=0x1234, cntlid=8,
                              ets=0x2222, pelpid=4),
    ]


class TestPersistentEventLogReads(PersistentEventLogTestBase):

    def test_establish_reads_the_header_then_the_log(self):
        log = layout.pack_log(sample_events())
        self.serve(log)
        text = self.text('-a', '1', '-l', str(dword_len(log)))
        reads = self.reads()
        self.assertGreaterEqual(len(reads), 2, reads)
        first, rest = reads[0], reads[1:]
        self.assertEqual(first.lsp, layout.ACTION_ESTABLISH)
        self.assertEqual(first.data_len, layout.HEADER_SIZE)
        self.assertEqual(first.lpo, 0)
        self.assertEqual([r.lsp for r in rest],
                         [layout.ACTION_READ] * len(rest))
        self.assertEqual(rest[0].data_len, dword_len(log))
        for r in reads:
            self.assertEqual(r.nsid, NSID_ALL)
            self.assertEqual(r.uuid_index, 0)
        self.assertEqual(text.count('Event Number'), 2, text)

    def test_establish_alone_only_establishes(self):
        self.serve(layout.pack_log(sample_events()))
        text = self.text('-a', '1')
        self.assertIn('Establishing Persistent Event Log Context', text)
        self.assertNotIn(ENTRIES, text)
        reads = self.reads()
        self.assertEqual([(r.lsp, r.data_len) for r in reads],
                         [(layout.ACTION_ESTABLISH, layout.HEADER_SIZE)])
        self.assertIsNotNone(self.server.context)

    def test_read_in_context_reads_the_total_log_length(self):
        log = layout.pack_log(sample_events())
        self.serve(log)
        self.server.context = log
        text = self.text('-a', '0')
        reads = self.reads()
        self.assertEqual([r.lsp for r in reads],
                         [layout.ACTION_READ] * len(reads))
        self.assertEqual(reads[0].data_len, layout.HEADER_SIZE)
        self.assertEqual(reads[1].data_len, dword_len(log))
        self.assertEqual(text.count('Event Number'), 2, text)

    def test_read_without_context_fails(self):
        self.serve(layout.pack_log(sample_events()))
        result = self.run_pel('-a', '0')
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('Command Sequence Error', result.stderr)
        self.assertNotIn(ENTRIES, result.stdout)

    def test_establish_in_context_fails(self):
        log = layout.pack_log(sample_events())
        self.serve(log)
        self.server.context = log
        result = self.run_pel('-a', '1', '-l', str(dword_len(log)))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('Command Sequence Error', result.stderr)
        self.assertNotIn(ENTRIES, result.stdout)

    def test_release_releases_the_context(self):
        log = layout.pack_log(sample_events())
        self.serve(log)
        self.server.context = log
        text = self.text('-a', '2')
        self.assertIn('Releasing Persistent Event Log Context', text)
        self.assertNotIn(ENTRIES, text)
        self.assertEqual([r.lsp for r in self.reads()],
                         [layout.ACTION_RELEASE])
        self.assertIsNone(self.server.context)

    def test_log_len_sets_the_length_of_the_read(self):
        log = layout.pack_log(sample_events())
        self.serve(log)
        self.text('-a', '1', '-l', '1024')
        reads = self.reads()
        self.assertEqual(reads[1].lsp, layout.ACTION_READ)
        self.assertEqual(reads[1].data_len, 1024)

    def test_unaligned_log_len_is_read_in_whole_dwords(self):
        log = layout.pack_log(sample_events())
        self.assertNotEqual(len(log) % 4, 0)
        self.serve(log)
        result = self.run_pel('-a', '1', '-l', str(len(log)), '-b',
                              encoding=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.reads()[1].data_len, dword_len(log))
        self.assertEqual(result.stdout, log)

    def test_get_log_error_fails(self):
        self.server.logs[layout.LID] = SC_INTERNAL
        result = self.run_pel('-a', '1', '-l', '1024')
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn(ENTRIES, result.stdout)

    def test_generation_change_fails(self):
        log = layout.pack_log(sample_events(), gen_number=5)
        self.serve(log)

        def regenerate(cmd, data):
            # The context is rebuilt after each read of it, so the header
            # read after the log has a new Generation Number.
            if cmd.lsp == layout.ACTION_READ:
                context = bytearray(self.server.context)
                struct.pack_into('<H', context, layout.GEN_NUMBER, 6)
                self.server.context = bytes(context)
            return data

        self.server.on_read = regenerate
        result = self.run_pel('-a', '1', '-l', str(dword_len(log)))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(GEN_CHANGED_MSG, result.stderr)
        self.assertNotIn(ENTRIES, result.stdout)

    @unittest.expectedFailure
    def test_default_action_is_defined(self):
        """Defect: without -a the action is FFh, which goes out as LSP
        7Fh: the reserved Action 11b, with the reserved bits of the LSP
        set. The man page's example to print the log uses no options."""
        self.serve(layout.pack_log(sample_events()))
        result = self.run_pel()
        actions = [r.lsp for r in self.reads()]
        self.assertTrue(set(actions) <= {layout.ACTION_READ,
                                         layout.ACTION_ESTABLISH,
                                         layout.ACTION_RELEASE}, actions)
        self.assertOk(result)
        self.assertEqual(result.stdout.count('Event Number'), 2,
                         result.stdout)

    @unittest.expectedFailure
    def test_short_log_len_shows_hint(self):
        """Defect: with -l under 512 bytes the Generation Number of the
        log is taken from beyond what was read, so a log with a non-zero
        one is taken as changed, and the hint that 512 bytes are needed
        is not shown."""
        self.serve(layout.pack_log(sample_events(), gen_number=5))
        result = self.run_pel('-a', '1', '-l', '256')
        self.assertOk(result)
        self.assertIn(SHORT_LEN_HINT, result.stdout)

    @unittest.expectedFailure
    def test_documented_log_len_option(self):
        """Defect: the man page documents --log-len, the command takes
        --log_len."""
        self.serve(layout.pack_log(sample_events()))
        self.assertOk(self.run_pel('-a', '1', '--log-len=1024'))
        self.assertEqual(self.reads()[1].data_len, 1024)


class TestPersistentEventLogHeader(PersistentEventLogTestBase):

    # Field, text label, JSON key, value
    FIELDS = (
        ('lid', 'Log Identifier', 'log_id', layout.LID),
        ('tnev', 'Total Number of Events', 'total_num_of_events', 0),
        ('rv', 'Log Revision', 'log_revision', 0x03),
        ('lhl', 'Log Header Length', 'log_header_len', 0x01E4),
        ('ts', 'Timestamp', 'timestamp', 0x0000018B2F0A1C00),
        ('pcc', 'Power Cycle Count', 'power_cycle_count', 0x0102030405),
        ('vid', 'PCI Vendor ID (VID)', 'pci_vid', 0x1344),
        ('ssvid', 'PCI Subsystem Vendor ID (SSVID)', 'pci_ssvid', 0x1345),
        ('gen_number', 'Generation Number', 'gen_number', 0x0BCD),
        ('rci', 'Reporting Context Information (RCI)', 'rci', 0x00030007),
    )
    STRINGS = (
        ('sn', 'Serial Number (SN)', 'sn', 'PELSN0001'),
        ('mn', 'Model Number (MN)', 'mn', 'OCP PEL MOCK MODEL'),
        ('subnqn', 'NVM Subsystem NVMe Qualified Name (SUBNQN)', 'subnqn',
         'nqn.2014-08.org.nvmexpress:pel-mock'),
    )
    POH = 777

    def test_header_fields(self):
        values = {f: v for f, _, _, v in self.FIELDS + self.STRINGS}
        log = layout.pack_log(poh=self.POH, **values)
        text, report = self.reports(log)
        for field, label, key, value in self.FIELDS:
            with self.subTest(field=field):
                self.assertEqual(self.text_value(text, label), str(value))
                self.assertEqual(report[key], value)
        for field, label, key, value in self.STRINGS:
            with self.subTest(field=field):
                self.assertEqual(self.text_value(text, label), value)
                self.assertEqual(report[key].rstrip(), value)
        self.assertEqual(self.text_value(text, 'Total Log Length'),
                         str(len(log)))
        self.assertEqual(report['total_log_len'], len(log))
        self.assertEqual(self.text_value(text, 'Power On Hours (POH)'),
                         str(self.POH))
        self.assertEqual(int(str(report['power_on_hours'])), self.POH)

    def test_supported_events_bitmap(self):
        # Timestamp Change (3) and Vendor Specific (DEh)
        seb = bytearray(layout.SEB_LEN)
        seb[0] = 1 << 3
        seb[0xDE // 8] = 1 << (0xDE % 8)
        text, report = self.reports(layout.pack_log(seb=bytes(seb)))
        self.assertEqual(re.findall(r'^\tSupport (.*)$', text, re.M),
                         ['Timestamp Change Event(0x3)',
                          'Vendor Specific Event(0xde)'])
        self.assertEqual(sorted(k for k in report if k.startswith('bitmap_')),
                         ['bitmap_3', 'bitmap_de'])


class TestPersistentEventLogEvents(PersistentEventLogTestBase):

    def test_event_headers(self):
        text, report = self.reports(layout.pack_log(sample_events()))
        self.assertEqual(self.text_values(text, 'Event Number'), ['0', '1'])
        self.assertEqual(self.text_values(text, 'Controller Identifier'),
                         ['7', '8'])
        self.assertEqual(self.text_values(text, 'Event Timestamp'),
                         [str(0x1111), str(0x2222)])
        self.assertEqual(self.text_values(text, 'Port Identifier'),
                         ['3', '4'])
        self.assertEqual(
            self.text_values(text, 'Vendor Specific Information Length'),
            ['8', '0'])
        events = self.events(report)
        self.assertEqual([e['ctrl_id'] for e in events], [7, 8])
        self.assertEqual([e['event_time_stamp'] for e in events],
                         [0x1111, 0x2222])
        self.assertEqual([e['port_id'] for e in events], [3, 4])
        self.assertEqual([e['vu_info_len'] for e in events], [8, 0])
        self.assertEqual([e['event_len'] for e in events], [8 + 16, 22])

    def test_timestamp_change_event(self):
        text, report = self.reports(layout.pack_log(sample_events()))
        self.assertEqual(self.text_value(text, 'Previous Timestamp'),
                         str(0x0123456789AB))
        self.assertEqual(self.text_value(text, 'Milliseconds Since Reset'),
                         str(0x2000))
        event = self.events(report)[0]
        self.assertEqual(event['prev_ts'], 0x0123456789AB)
        self.assertEqual(event['ml_secs_since_reset'], 0x2000)

    def test_fw_commit_event(self):
        text, report = self.reports(layout.pack_log(sample_events()))
        self.assertIn('(OLDFW001)', self.text_value(text,
                                                    'Old Firmware Revision'))
        self.assertIn('(NEWFW002)', self.text_value(text,
                                                    'New Firmware Revision'))
        self.assertEqual(self.text_value(text, 'FW Commit Action'), '3')
        self.assertEqual(self.text_value(text, 'FW Slot'), '2')
        self.assertEqual(self.text_value(
            text, 'Status Code Type for Firmware Commit Command'), '1')
        self.assertEqual(self.text_value(
            text, 'Status Returned for Firmware Commit Command'), str(0x07))
        self.assertEqual(self.text_value(
            text, 'Vendor Assigned Firmware Commit Result Code'), str(0x1234))
        event = self.events(report)[1]
        self.assertIn('(OLDFW001)', event['old_fw_rev'])
        self.assertIn('(NEWFW002)', event['new_fw_rev'])
        self.assertEqual((event['fw_commit_action'], event['fw_slot'],
                          event['sct_fw'], event['sc_fw'],
                          event['vu_assign_fw_commit_rc']),
                         (3, 2, 1, 0x07, 0x1234))

    def test_events_end_at_the_log(self):
        # TNEV counts one event more than the log holds.
        log = layout.pack_log(sample_events(), tnev=3)
        text, report = self.reports(log)
        self.assertEqual(self.text_values(text, 'Event Number'), ['0', '1'])
        self.assertEqual(len(self.events(report)), 2)

    @unittest.expectedFailure
    def test_vendor_specific_information_is_dumped(self):
        """Defect: the Vendor Specific Information of an event is dumped
        from byte 1 of the event header instead of from byte 24, after
        the header."""
        vsi = b'VSI!'
        log = layout.pack_log([layout.pack_timestamp_change(1, 2, vsi=vsi,
                                                            cntlid=1)])
        text, report = self.reports(log)
        self.assertIn('Vendor Specific Information:', text)
        dump = text.split('Vendor Specific Information:', 1)[1]
        self.assertIn(' '.join(f'{b:02x}' for b in vsi), dump)
        self.assertEqual(''.join(self.events(report)[0]['vs_info_bin']),
                         vsi.decode())

    def test_unaligned_total_log_length_is_read_whole(self):
        """A Total Log Length which is not a multiple of 4 is read as
        that many dwords rounded up (NUMD), so the last bytes of the log
        are read. The Total Log Length of these events is 606, and the
        Vendor Assigned Firmware Commit Result Code is the last 2
        bytes."""
        log = layout.pack_log(sample_events())
        self.assertNotEqual(len(log) % 4, 0)
        self.serve(log)
        self.server.context = log
        text = self.text('-a', '0')
        self.assertEqual(self.text_value(
            text, 'Vendor Assigned Firmware Commit Result Code'), str(0x1234))


def tcg_values():
    """TCG Activity Event fields, each byte distinct. ProtocolID 01h,
    Status 12h and Process Time 0345h tell the bytes 58 to 61 apart."""
    return dict(command_count=0x01020304,
                invoking_id=0x0000000900000001,
                method_id=0x0000000600000002,
                com_id=0x07FE,
                protocol_id=0x01,
                status=0x12,
                process_time=0x0345)


TCG_CONTEXT = b'0123456789'
# The OCP UUID in the UUID List slot 1, UUID Index 2, which the descriptor
# of a TCG Activity Event names (TCGCE-14). persistent-event-log does not
# read the UUID List.
OCP_UUID_SLOT = 1
OCP_UUID_INDEX = 2


class TestPersistentEventLogVendorSpecific(PersistentEventLogTestBase):

    def setUp(self):
        super().setUp()
        self.server.uuid_slot = OCP_UUID_SLOT

    def tcg_reports(self, event):
        return self.reports(layout.pack_log([event]))

    def test_generic_vendor_specific_event(self):
        desc = layout.pack_vs_desc(0x10, layout.VSEDT_ASCII_STRING,
                                   b'MOCKEVENT', uidx=OCP_UUID_INDEX)
        text, report = self.reports(layout.pack_log([layout.pack_event(
            layout.ETYPE_VENDOR_SPECIFIC, desc)]))
        self.assertNotIn(TCG_ENTRY, text)
        self.assertEqual(self.text_value(text, 'Vendor Specific Event Code'),
                         str(0x10))
        self.assertEqual(self.text_value(text, 'ASCII String Data'),
                         'MOCKEVENT')
        event = self.events(report)[0]
        self.assertNotIn('tcg_activity_event_data', event)
        vs_event = event['vs_event_entry'][0]
        self.assertEqual(vs_event['vs_event_code'], 0x10)
        self.assertEqual(vs_event['vs_event_uuid_index'], OCP_UUID_INDEX)
        self.assertEqual(vs_event['vs_event_data']['ascii_string_data'],
                         'MOCKEVENT')

    def test_other_event_code_is_not_tcg(self):
        text, report = self.tcg_reports(layout.pack_tcg_event(
            vsec=0x0002, uidx=OCP_UUID_INDEX, **tcg_values()))
        self.assertNotIn(TCG_ENTRY, text)
        self.assertEqual(self.text_value(text, 'Vendor Specific Event Code'),
                         '2')
        self.assertNotIn('tcg_activity_event_data', self.events(report)[0])

    def test_tcg_activity_event_is_decoded(self):
        """The TCG Activity Event is recognized by its Vendor Specific
        Event Descriptor at byte 28 (TCGCE-12 to -15), after the Vendor
        Specific Information at byte 24 (TCGCE-11)."""
        values = tcg_values()
        text, report = self.tcg_reports(layout.pack_tcg_event(
            uidx=OCP_UUID_INDEX, context=TCG_CONTEXT, **values))
        self.assertIn(TCG_ENTRY, text)
        for label, want in (
                ('Vendor Specific Event Code', layout.TCG_VSEC),
                ('Vendor Specific Event Data Type', layout.VSEDT_BINARY),
                ('Vendor Specific Event UIndex', OCP_UUID_INDEX),
                ('Vendor Specific Event Data Length', layout.TCG_VSEDL),
                ('TCG Command Count', values['command_count']),
                ('Invoking ID', values['invoking_id']),
                ('Method ID', values['method_id']),
                ('Com ID', values['com_id'])):
            with self.subTest(label=label):
                self.assertEqual(self.text_value(text, label), str(want))
        tcg = self.events(report)[0]['tcg_activity_event_data']
        for key, want in (
                ('vendor_specific_event_code', layout.TCG_VSEC),
                ('vendor_specific_event_data_type', layout.VSEDT_BINARY),
                ('vendor_specific_event_uindex', OCP_UUID_INDEX),
                ('vendor_specific_event_data_length', layout.TCG_VSEDL),
                ('tcg_command_count', values['command_count']),
                ('invoking_id', values['invoking_id']),
                ('method_id', values['method_id']),
                ('com_id', values['com_id'])):
            with self.subTest(key=key):
                self.assertEqual(tcg[key], want)

    def test_vsi_is_not_taken_for_the_descriptor(self):
        """An event whose Vendor Specific Information reads as event code
        0001h, binary, and whose real event code is 26h, is not a TCG
        Activity Event."""
        vsi = struct.pack('<HBB', layout.TCG_VSEC, layout.VSEDT_BINARY, 0)
        text, report = self.tcg_reports(layout.pack_tcg_event(
            vsec=layout.TCG_VSEDL, vsi=vsi, **tcg_values()))
        self.assertNotIn(TCG_ENTRY, text)
        self.assertNotIn('tcg_activity_event_data', self.events(report)[0])

    def test_tcg_fields_after_com_id(self):
        """The ProtocolID of the TCG Activity Event is one byte
        (TCGCE-21), and the Status, the Process Time and the TCG Activity
        Specific Context (TCGCE-22 to -24) follow it."""
        values = tcg_values()
        text, report = self.tcg_reports(layout.pack_tcg_event(
            uidx=OCP_UUID_INDEX, context=TCG_CONTEXT, **values))
        for label, key in (('Protocol ID', 'protocol_id'),
                           ('Status', 'status'),
                           ('Process Time', 'process_time')):
            with self.subTest(label=label):
                self.assertEqual(self.text_value(text, label),
                                 str(values[key]))
        self.assertIn('TCG Activity Specific Context:', text)
        context = text.split('TCG Activity Specific Context:', 1)[1]
        self.assertIn(f'"{TCG_CONTEXT.decode()}"', context)
        tcg = self.events(report)[0]['tcg_activity_event_data']
        for key in ('protocol_id', 'status', 'process_time'):
            with self.subTest(key=key):
                self.assertEqual(tcg[key], values[key])
        self.assertEqual(''.join(tcg['tcg_activity_specific_context']),
                         TCG_CONTEXT.decode())


class TestPersistentEventLogBinary(PersistentEventLogTestBase):

    def test_binary_is_the_log_as_read(self):
        log = layout.pack_log(sample_events(), gen_number=3)
        self.serve(log)
        length = dword_len(log)
        for args in (('-b',), ('-o', 'binary')):
            with self.subTest(args=args):
                self.server.context = None
                result = self.run_pel('-a', '1', '-l', str(length), *args,
                                      encoding=None)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, log.ljust(length, b'\0'))


if __name__ == '__main__':
    main()
