#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for the event FIFO decoding of "nvme ocp internal-log".

With -t host or -t controller, internal-log decodes the OCP telemetry
log's event FIFOs through parse_event_fifos() and parse_event_fifo(),
which hands each event to a per-class decoder and names it from the C9h
Telemetry String Log. A real drive only ever produces the events it
happens to log, so here the telemetry log and string log are synthetic
files (passed with -l and -s) built by
tests/e2e/plugins/ocp/ocp_telemetry_layout.py, and every event class,
size boundary and string table lookup is an input.

Both the JSON report and the text report (-o normal) are checked; they
carry the same keys and value strings for every event.

Tests in this module verify:
  * Virtual FIFO events (0Bh): the VU Virtual FIFO Identifier and its
    physical/virtual FIFO subfields, the virtual FIFO name from the VU
    Event String Table keyed on (0Bh, identifier) and no other table or
    class, the physical FIFO name from the string log's FIFO name array
    for FIFOs 1..16 only, the reserved half-word and any extra Dwords
    being ignored, and a zero-size event being rejected.
  * SMBUS/I2C/I3C events (0Ch): the Event Data and its name, defined for
    the NACK error Event ID only, the reserved half-word being ignored,
    the optional VU fields from one Dword past the fixed record up to the
    largest Event Data Size, and a zero-size event being rejected.
  * MCTP events (0Dh): the Event Data named from each of Event IDs 0-3's
    own tables, the Transport Protocol Information and its name, the
    Transport Header printed only with the Transport Header Valid flag
    set, the optional VU fields, and events short of the two-Dword record
    being rejected.
  * Every other class: class specific data at each class's minimum size,
    VU Event Identifier/String/Data from one Dword beyond it up to the
    largest Event Data Size, rejection at every size below it, the common
    classes' optional VU data, reserved classes with their payload dumped
    as Class Specific Data, vendor unique classes, and Statistic Snapshot
    events of different statistic sizes, with the statistic's Namespace
    Identifier[15:0], and of a Context Statistic Descriptor decoded down
    to its encapsulated statistics.
  * Event String and VU Event String lookups match on (class,
    identifier), not identifier alone, for every class, and come from the
    VU table from class 80h up.
  * An event of any class that runs past the end of its FIFO being
    rejected, and one that ends exactly at the end being decoded.
  * FIFO layout: FIFO naming and numbering, the data area each FIFO is
    decoded in, the end-of-list entry, FIFO bounds, and a bad FIFO
    aborting the whole decode.

Known defects are covered by expectedFailure tests asserting the correct
behavior: Statistic Snapshot events are left out of the JSON report, a
snapshot of a statistic with no data is left out of the text report and
runs into the next event, and a log the decoder rejects still exits 0.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_internal_log_event_fifo_mock_test.py <nvme-binary> <mock-lib>
"""
import unittest

from tests.cli.ocp.ocp_mock_test import (MODES, STR_DA_EVENT_FIFO_INFO,
                                         OCPInternalLogTestBase, main)
from tests.e2e.plugins.ocp import ocp_telemetry_layout as layout

PHYS_NAMES = {n: f'PHYS FIFO {n:02d}' for n in range(1, layout.MAX_FIFOS + 1)}
FIFO_1 = f'EVENT FIFO 1 - {PHYS_NAMES[1]}'

INVALID_EVENT_MSG = 'Invalid NVMe Event FIFO entry'
FIFO_PARSE_FAILED_MSG = 'Failed to parse Event FIFO'
INVALID_BOUNDS_MSG = 'Invalid FIFO bounds for FIFO'


def strings(fifo_names=None, **tables):
    return layout.pack_string_log(
        fifo_names=PHYS_NAMES if fifo_names is None else fifo_names,
        **tables)


def invalid_entry(offset, reason, fifo=1):
    return f'Invalid entry at offset 0x{offset:x} of Event FIFO {fifo}: {reason}'


def one_fifo(*events, da=1, **kwargs):
    return layout.pack_telemetry(fifos={1: layout.Fifo(da, events)},
                                 **kwargs)


def common(cls, event_id, size_dw, string=''):
    return {
        'Debug Event Class type': f'0x{cls:x}',
        'Event Identifier': f'0x{event_id:x}',
        'Event String': string,
        'Event Data Size': f'0x{size_dw:x}',
    }


def virtual_fifo(fifo_id, event_id=0, size_dw=1, event_string='',
                 vfifo_string='', phys_string=''):
    physical, virtual = layout.split_virtual_fifo_id(fifo_id)
    return {
        **common(layout.CLASS_VIRTUAL_FIFO, event_id, size_dw, event_string),
        'VU Virtual FIFO Identifier': f'0x{fifo_id:x}',
        'VU Virtual FIFO String': vfifo_string,
        'Physical Event FIFO Number': f'0x{physical:x}',
        'Physical Event FIFO String': phys_string,
        'Virtual FIFO Number': f'0x{virtual:x}',
    }


UNRECOGNIZED = 'unrecognized'

# OCP 2.7 Event Data names: SMBUS/I2C/I3C NACK error (EVC-SMBUS-4) and the
# four MCTP Event IDs (EVC-MCTP-4), indexed by Event Data value.
SMBUS_NACK_DATA = ['Received invalid command or data', 'Device is busy',
                   'Requested data is not available']
_PHY_ERROR = 'Bad packet data integrity or other physical layer error: '
MCTP_EVENT_DATA = {
    0x0000: ['Unexpected middle or end packet',
             _PHY_ERROR + 'Framing errors',
             _PHY_ERROR + 'Byte alignment errors',
             _PHY_ERROR + 'Invalid packet size',
             'Unexpected or expired message tag',
             'Unknown destination EID',
             'Unsupported MCTP header version',
             'Unsupported transmission unit size'],
    0x0001: ['Receipt of a new start packet',
             'Timeout waiting for a packet + threshold',
             'Out-of-sequence packet sequence number',
             'Incorrect transmission unit',
             'Bad message integrity check',
             'Invalid message type received'],
    0x0002: ['Transport Binding specific bus enumeration errors',
             'Transport Binding specific bus address assignment errors'],
    0x0003: ['Reserved', 'ERROR', 'ERROR_INVALID_DATA',
             'ERROR_INVALID_LENGTH', 'ERROR_NOT_READY',
             'ERROR_UNSUPPORTED_CMD', 'COMMAND_SPECIFIC'],
}
# EVC-MCTP-5; 02h-03h and 06h-FFh are reserved.
MCTP_PROTOCOLS = {0x00: 'PCIe VDM on device PCIe port 0',
                  0x01: 'PCIe VDM on device PCIe port 1',
                  0x04: 'I2C/SMBus',
                  0x05: 'I3C'}


def vu_fields(vu_id, data, string=''):
    return {
        'VU Event Identifier': f'0x{vu_id:x}',
        'VU Event String': string,
        'VU Data': layout.hex_upper(data),
    }


def smbus(event_id, event_data, data_string='', size_dw=1, event_string='',
          vu=None):
    return {
        **common(layout.CLASS_SMBUS_I2C_I3C, event_id, size_dw, event_string),
        'SMBUS Debug Event Data': f'0x{event_data:x}',
        'SMBUS Debug Event Data String': data_string,
        **(vu or {}),
    }


def mctp(event_id, event_data, data_string='', protocol=0,
         protocol_string=MCTP_PROTOCOLS[0], header=None, size_dw=2,
         event_string='', vu=None):
    """@header is the expected MCTP Transport Header, or None when the
    Transport Header Valid flag is clear and no header is printed."""
    fields = {
        **common(layout.CLASS_MCTP, event_id, size_dw, event_string),
        'MCTP Debug Event Data': f'0x{event_data:x}',
        'MCTP Debug Event Data String': data_string,
        'MCTP Transport Protocol Information': f'0x{protocol:x}',
        'MCTP Transport Protocol String': protocol_string,
        'MCTP Transport Header Valid': '0x0' if header is None else '0x1',
    }
    if header is not None:
        fields['MCTP Transport Header'] = layout.hex_upper(header)
    return {**fields, **(vu or {})}


PCIE_DATA = bytes.fromhex('A1A2A3A4')
PCIE_EVENT = layout.event(layout.CLASS_PCIE, 0x31, PCIE_DATA)
PCIE_EXPECTED = {**common(layout.CLASS_PCIE, 0x31, 1),
                 'Class Specific Data': 'A1A2A3A4'}


class EventFifoTestBase(OCPInternalLogTestBase):

    def assert_events(self, telemetry, strings_log, expected, *args,
                      number=1, da=1):
        """FIFO @number decodes to @expected, keys in order, in both
        output modes."""
        for mode in MODES:
            with self.subTest(mode=mode):
                events = self.fifo_events(telemetry, strings_log, number,
                                          *args, mode=mode, da=da)
                self.assertEqual(len(events), len(expected), events)
                for i, (got, want) in enumerate(zip(events, expected)):
                    with self.subTest(event=i):
                        self.assertEqual(got, want)
                        self.assertEqual(list(got), list(want),
                                         'fields are out of order')

    def assert_rejected(self, telemetry, strings_log, *messages, args=()):
        """The decoder refuses the log with each of @messages."""
        for mode in MODES:
            with self.subTest(mode=mode):
                out = self.decode_fails(telemetry, strings_log, *args,
                                        mode=mode)
                for msg in messages:
                    self.assertIn(msg, out)


class TestVirtualFifoEvent(EventFifoTestBase):
    """Debug event class 0Bh."""

    def test_identifier_splits_into_physical_and_virtual_fifo(self):
        """Bits 15:11 are the physical FIFO and 10:0 the virtual FIFO. The
        identifier is little-endian: read big-endian it would name
        physical FIFO 2 and virtual FIFO 0x218."""
        fifo_id = layout.virtual_fifo_id(3, 0x12)
        telemetry = one_fifo(layout.virtual_fifo_event(fifo_id, 0x21))
        log = strings(
            event_strings={(layout.CLASS_VIRTUAL_FIFO, 0x21): 'VFIFO EVT'},
            vu_event_strings={(layout.CLASS_VIRTUAL_FIFO, fifo_id): 'VF3.18'})
        self.assert_events(telemetry, log, [
            virtual_fifo(fifo_id, event_id=0x21, event_string='VFIFO EVT',
                         vfifo_string='VF3.18', phys_string='PHYS FIFO 03'),
        ])

    def test_virtual_fifo_number_limits(self):
        for virtual in (0, layout.VIRTUAL_FIFO_MASK):
            with self.subTest(virtual=virtual):
                fifo_id = layout.virtual_fifo_id(2, virtual)
                self.assert_events(
                    one_fifo(layout.virtual_fifo_event(fifo_id)), strings(),
                    [virtual_fifo(fifo_id, phys_string='PHYS FIFO 02')])

    def test_physical_fifo_name_at_both_ends_of_the_array(self):
        """Physical FIFO n is named by the string log's FIFO n entry, and
        a name filling all 16 bytes has no terminator to stop at."""
        names = dict(PHYS_NAMES)
        names[16] = 'ABCDEFGHIJKLMNOP'
        log = strings(fifo_names=names)
        for physical, name in ((1, 'PHYS FIFO 01'), (16, names[16])):
            with self.subTest(physical=physical):
                fifo_id = layout.virtual_fifo_id(physical, 7)
                self.assert_events(
                    one_fifo(layout.virtual_fifo_event(fifo_id)), log,
                    [virtual_fifo(fifo_id, phys_string=name)])

    def test_physical_fifo_zero_has_no_name(self):
        """0h is not a FIFO number, so no name is looked up for it -- not
        even the bytes ahead of FIFO 1's name, which hold the string
        log's ASCII table start and size."""
        fifo_id = layout.virtual_fifo_id(0, 5)
        self.assert_events(one_fifo(layout.virtual_fifo_event(fifo_id)),
                           strings(), [virtual_fifo(fifo_id)])

    def test_physical_fifo_past_sixteen_has_no_name(self):
        """The field holds up to 31 but only 16 FIFO names exist. The
        header bytes after the name array are filled, so reading past
        the array would show up as a name."""
        overlay = {layout.STR_FIFO_NAMES
                   + layout.MAX_FIFOS * layout.FIFO_NAME_LEN:
                   b'R' * (layout.STR_HEADER_SIZE - layout.STR_FIFO_NAMES
                           - layout.MAX_FIFOS * layout.FIFO_NAME_LEN)}
        log = strings(overlay=overlay)
        for physical in (17, 18, 19, layout.VIRTUAL_FIFO_PHY_MAX):
            with self.subTest(physical=physical):
                fifo_id = layout.virtual_fifo_id(physical,
                                                 layout.VIRTUAL_FIFO_MASK)
                self.assert_events(
                    one_fifo(layout.virtual_fifo_event(fifo_id)), log,
                    [virtual_fifo(fifo_id)])

    def test_name_comes_only_from_the_vu_table_entry_for_class_0bh(self):
        """Entries for the same identifier in the Event String Table, or
        under another class in the VU table, do not name the FIFO. The
        descriptor's own Event Identifier still resolves through the Event
        String Table."""
        fifo_id = layout.virtual_fifo_id(4, 0x40)
        cls = layout.CLASS_VIRTUAL_FIFO
        decoys = {
            'event_strings': {(cls, fifo_id): 'EST ENTRY'},
            'vu_event_strings': {
                (layout.CLASS_STATISTIC_SNAPSHOT, fifo_id): 'OTHER CLASS',
                (0x8B, fifo_id): 'VU CLASS',
                (cls, fifo_id + 1): 'OTHER ID',
            },
        }
        telemetry = one_fifo(layout.virtual_fifo_event(fifo_id, fifo_id))
        with self.subTest(vu_entry=False):
            self.assert_events(telemetry, strings(**decoys), [
                virtual_fifo(fifo_id, event_id=fifo_id,
                             event_string='EST ENTRY',
                             phys_string='PHYS FIFO 04'),
            ])
        decoys['vu_event_strings'][(cls, fifo_id)] = 'VIRTUAL FIFO 4.64'
        with self.subTest(vu_entry=True):
            self.assert_events(telemetry, strings(**decoys), [
                virtual_fifo(fifo_id, event_id=fifo_id,
                             event_string='EST ENTRY',
                             vfifo_string='VIRTUAL FIFO 4.64',
                             phys_string='PHYS FIFO 04'),
            ])

    def test_reserved_half_word_is_ignored(self):
        fifo_id = layout.virtual_fifo_id(5, 0x55)
        self.assert_events(
            one_fifo(layout.virtual_fifo_event(fifo_id, reserved=0xFFFF)),
            strings(), [virtual_fifo(fifo_id, phys_string='PHYS FIFO 05')])

    def test_extra_dwords_are_skipped(self):
        """The class defines one Dword; anything more the size declares
        is neither printed nor mistaken for the next event."""
        fifo_id = layout.virtual_fifo_id(6, 0x66)
        telemetry = one_fifo(
            layout.virtual_fifo_event(fifo_id, extra=b'\x02\xEE\xEE\xEE'),
            PCIE_EVENT)
        self.assert_events(telemetry, strings(), [
            virtual_fifo(fifo_id, size_dw=2, phys_string='PHYS FIFO 06'),
            PCIE_EXPECTED,
        ])

    def test_consecutive_events(self):
        ids = (layout.virtual_fifo_id(1, 0),
               layout.virtual_fifo_id(2, 0x100),
               layout.virtual_fifo_id(16, layout.VIRTUAL_FIFO_MASK))
        telemetry = one_fifo(*(layout.virtual_fifo_event(i, 0x21 + n)
                               for n, i in enumerate(ids)))
        self.assert_events(telemetry, strings(), [
            virtual_fifo(ids[0], event_id=0x21, phys_string='PHYS FIFO 01'),
            virtual_fifo(ids[1], event_id=0x22, phys_string='PHYS FIFO 02'),
            virtual_fifo(ids[2], event_id=0x23, phys_string='PHYS FIFO 16'),
        ])

    def test_event_in_a_data_area_2_fifo(self):
        fifo_id = layout.virtual_fifo_id(9, 0x99)
        telemetry = layout.pack_telemetry(fifos={
            3: layout.Fifo(2, [layout.virtual_fifo_event(fifo_id)]),
        })
        self.assert_events(telemetry, strings(),
                           [virtual_fifo(fifo_id, phys_string='PHYS FIFO 09')],
                           '-a', '2', number=3, da=2)

    def test_zero_size_event_is_rejected(self):
        """The class carries one Dword, so an event declaring none has no
        identifier to decode."""
        fifo_id = layout.virtual_fifo_id(3, 0x12)
        telemetry = one_fifo(layout.virtual_fifo_event(fifo_id, 0x21,
                                                       size_dw=0))
        self.assert_rejected(telemetry, strings(), INVALID_EVENT_MSG,
                             'FIFO: 1, offset: 0x0',
                             'Type: 0xb, ID: 0x21, Size: 0x0',
                             FIFO_PARSE_FAILED_MSG)


class TestSmbusEvent(EventFifoTestBase):
    """Debug event class 0Ch (SMBUS/I2C/I3C)."""

    def test_nack_error_event_data(self):
        """Event Data is named for the NACK error Event ID. Values past
        the defined ones are unrecognized, and the events that follow
        still decode."""
        nack = layout.SMBUS_NACK_ERROR
        values = [*range(len(SMBUS_NACK_DATA)), len(SMBUS_NACK_DATA), 0xFFFF]
        telemetry = one_fifo(*(layout.smbus_event(nack, value)
                               for value in values), PCIE_EVENT)
        self.assert_events(telemetry, strings(), [
            *(smbus(nack, value, (SMBUS_NACK_DATA + [UNRECOGNIZED] * 2)[i])
              for i, value in enumerate(values)),
            PCIE_EXPECTED])

    def test_event_data_is_unnamed_for_other_event_ids(self):
        """Only NACK error defines Event Data values, so every other Event
        ID, reserved and vendor unique ones included, prints the value
        with an empty name."""
        ids = (0x0000, 0x0001, 0x0002, 0x0004, 0x7FFF, 0x8000, 0xFFFF)
        telemetry = one_fifo(*(layout.smbus_event(i, 0x0001) for i in ids))
        self.assert_events(telemetry, strings(),
                           [smbus(i, 0x0001) for i in ids])

    def test_event_data_is_little_endian(self):
        """0002h read big-endian would be 0200h, which is unrecognized."""
        nack = layout.SMBUS_NACK_ERROR
        self.assert_events(one_fifo(layout.smbus_event(nack, 0x0002)),
                           strings(), [smbus(nack, 0x0002, SMBUS_NACK_DATA[2])])

    def test_reserved_half_word_is_ignored(self):
        nack = layout.SMBUS_NACK_ERROR
        self.assert_events(
            one_fifo(layout.smbus_event(nack, 0x0001, reserved=0xFFFF)),
            strings(), [smbus(nack, 0x0001, SMBUS_NACK_DATA[1])])

    def test_vu_fields_follow_the_fixed_record(self):
        """One Dword past the record holds the VU Event Identifier and two
        bytes of VU data. Both strings are looked up on class 0Ch: the
        Event String in the Event String Table and the VU Event String in
        the VU table, whose entries under another class and whose Event
        String Table entry for the VU identifier are decoys."""
        cls, nack, vu_id = layout.CLASS_SMBUS_I2C_I3C, 0x0003, 0x8001
        telemetry = one_fifo(
            layout.smbus_event(nack, 0x0000,
                               vu=layout.vu_part(vu_id, b'\xAA\xBB')),
            PCIE_EVENT)
        log = strings(
            event_strings={(cls, nack): 'SMBUS NACK',
                           (layout.CLASS_MCTP, nack): 'MCTP DECOY',
                           (cls, vu_id): 'EST DECOY'},
            vu_event_strings={(cls, vu_id): 'SMBUS VU',
                              (layout.CLASS_MCTP, vu_id): 'MCTP DECOY'})
        self.assert_events(telemetry, log, [
            smbus(nack, 0x0000, SMBUS_NACK_DATA[0], size_dw=2,
                  event_string='SMBUS NACK',
                  vu=vu_fields(vu_id, b'\xAA\xBB', 'SMBUS VU')),
            PCIE_EXPECTED])

    def test_largest_event_size(self):
        """VU Data is (Event Data Size * 4) - 6 bytes."""
        vu_data = bytes(i & 0xFF for i in range(0xFF * 4 - 6))
        telemetry = one_fifo(
            layout.smbus_event(0x8000, 0x1234,
                               vu=layout.vu_part(0x9001, vu_data)),
            PCIE_EVENT)
        self.assert_events(telemetry, strings(), [
            smbus(0x8000, 0x1234, size_dw=0xFF,
                  vu=vu_fields(0x9001, vu_data)),
            PCIE_EXPECTED])

    def test_zero_size_event_is_rejected(self):
        """The class carries one Dword, so an event declaring none has no
        Event Data to decode."""
        telemetry = one_fifo(layout.smbus_event(0x0003, 0x0001, size_dw=0))
        self.assert_rejected(telemetry, strings(), INVALID_EVENT_MSG,
                             'FIFO: 1, offset: 0x0',
                             'Type: 0xc, ID: 0x3, Size: 0x0',
                             FIFO_PARSE_FAILED_MSG)


class TestMctpEvent(EventFifoTestBase):
    """Debug event class 0Dh (MCTP)."""

    def test_event_data_per_event_id(self):
        """Each of Event IDs 0-3 names its Event Data from its own table;
        a value one past the end of a table is unrecognized, as is
        FFFFh."""
        events, expected = [], []
        for event_id, names in MCTP_EVENT_DATA.items():
            for value, name in [*enumerate(names), (len(names), UNRECOGNIZED),
                                (0xFFFF, UNRECOGNIZED)]:
                events.append(layout.mctp_event(event_id, value))
                expected.append(mctp(event_id, value, name))
        self.assert_events(one_fifo(*events, PCIE_EVENT), strings(),
                           [*expected, PCIE_EXPECTED])

    def test_event_data_is_unnamed_for_other_event_ids(self):
        ids = (0x0004, 0x7FFF, 0x8000, 0xFFFF)
        telemetry = one_fifo(*(layout.mctp_event(i, 0x0001) for i in ids))
        self.assert_events(telemetry, strings(),
                           [mctp(i, 0x0001) for i in ids])

    def test_transport_protocols(self):
        """00h, 01h, 04h and 05h are named; the reserved values around and
        after them are unrecognized."""
        protocols = (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFF)
        telemetry = one_fifo(*(layout.mctp_event(0x0003, 0x0001, protocol=p)
                               for p in protocols))
        self.assert_events(telemetry, strings(), [
            mctp(0x0003, 0x0001, MCTP_EVENT_DATA[3][1], protocol=p,
                 protocol_string=MCTP_PROTOCOLS.get(p, UNRECOGNIZED))
            for p in protocols])

    def test_transport_header_only_when_valid(self):
        """The header prints, bytes in log order, only with Event Flags
        bit 7 set; the reserved bits 6:0 neither set nor hide it."""
        header = bytes.fromhex('01020304')
        cases = ((0x80, header), (0xFF, header), (0x7F, None), (0x00, None))
        telemetry = one_fifo(*(layout.mctp_event(0x0000, 0x0005,
                                                 protocol=0x04, flags=flags,
                                                 header=header)
                               for flags, _ in cases), PCIE_EVENT)
        self.assert_events(telemetry, strings(), [
            *(mctp(0x0000, 0x0005, MCTP_EVENT_DATA[0][5], protocol=0x04,
                   protocol_string='I2C/SMBus', header=shown)
              for _, shown in cases),
            PCIE_EXPECTED])

    def test_vu_fields_follow_the_fixed_record(self):
        """One Dword past the two-Dword record holds the VU Event
        Identifier and two bytes of VU data, named on class 0Dh."""
        cls, vu_id = layout.CLASS_MCTP, 0x8002
        header = bytes.fromhex('0A0B0C0D')
        telemetry = one_fifo(
            layout.mctp_event(0x0003, 0x0002, protocol=0x05,
                              flags=layout.MCTP_HEADER_VALID, header=header,
                              vu=layout.vu_part(vu_id, b'\xD1\xD2')),
            PCIE_EVENT)
        log = strings(
            event_strings={(cls, 0x0003): 'MCTP ERROR STATUS',
                           (cls, vu_id): 'EST DECOY'},
            vu_event_strings={(cls, vu_id): 'MCTP VU',
                              (layout.CLASS_SMBUS_I2C_I3C, vu_id): 'DECOY'})
        self.assert_events(telemetry, log, [
            mctp(0x0003, 0x0002, MCTP_EVENT_DATA[3][2], protocol=0x05,
                 protocol_string='I3C', header=header, size_dw=3,
                 event_string='MCTP ERROR STATUS',
                 vu=vu_fields(vu_id, b'\xD1\xD2', 'MCTP VU')),
            PCIE_EXPECTED])

    def test_largest_event_size(self):
        """VU Data is (Event Data Size * 4) - 10 bytes."""
        vu_data = bytes((i * 5) & 0xFF for i in range(0xFF * 4 - 10))
        telemetry = one_fifo(
            layout.mctp_event(0x8000, 0x1234, protocol=0x01,
                              vu=layout.vu_part(0x9002, vu_data)),
            PCIE_EVENT)
        self.assert_events(telemetry, strings(), [
            mctp(0x8000, 0x1234, protocol=0x01,
                 protocol_string=MCTP_PROTOCOLS[1], size_dw=0xFF,
                 vu=vu_fields(0x9002, vu_data)),
            PCIE_EXPECTED])

    def test_event_short_of_the_fixed_record_is_rejected(self):
        """The class carries two Dwords; an event declaring fewer would
        have its protocol, flags or header read from past its end."""
        for size_dw in (0, 1):
            with self.subTest(size_dw=size_dw):
                telemetry = one_fifo(layout.mctp_event(0x0001, 0x0002,
                                                       size_dw=size_dw))
                self.assert_rejected(telemetry, strings(), INVALID_EVENT_MSG,
                                     'FIFO: 1, offset: 0x0',
                                     f'Type: 0xd, ID: 0x1, Size: 0x{size_dw:x}',
                                     FIFO_PARSE_FAILED_MSG)


class TestEventClassDecode(EventFifoTestBase):
    """Every other debug event class parse_event_fifo() dispatches."""

    def test_class_specific_data_at_minimum_size(self):
        events, expected = [], []
        for cls, size in layout.CLASS_SPECIFIC_SIZE.items():
            data = bytes(range(0x10 + cls, 0x10 + cls + size))
            events.append(layout.event(cls, 0x40 + cls, data))
            expected.append({**common(cls, 0x40 + cls, size // 4),
                             'Class Specific Data': layout.hex_upper(data)})
        self.assert_events(layout.pack_telemetry(
            fifos={1: layout.Fifo(1, events)}), strings(), expected)

    def test_vu_fields_follow_class_specific_data(self):
        """Past the class specific data come a VU Event Identifier, named
        from the VU Event String Table on (class, identifier), and VU
        data. The Event String Table entry for the same pair is a decoy."""
        vu_data = bytes.fromhex('DEADBEEF0102')
        events, expected, vu_names, decoys = [], [], {}, {}
        for cls, size in layout.CLASS_SPECIFIC_SIZE.items():
            data = bytes(range(0x10 + cls, 0x10 + cls + size))
            vu_id = 0x100 + cls
            vu_names[(cls, vu_id)] = f'VU EVENT {cls:02X}'
            decoys[(cls, vu_id)] = 'EST DECOY'
            events.append(layout.event(cls, 0x40 + cls,
                                       data + layout.vu_part(vu_id, vu_data)))
            expected.append({**common(cls, 0x40 + cls, size // 4 + 2),
                             'Class Specific Data': layout.hex_upper(data),
                             'VU Event Identifier': f'0x{vu_id:x}',
                             'VU Event String': f'VU EVENT {cls:02X}',
                             'VU Data': 'DEADBEEF0102'})
        self.assert_events(
            layout.pack_telemetry(fifos={1: layout.Fifo(1, events)}),
            strings(event_strings=decoys, vu_event_strings=vu_names),
            expected)

    def test_class_specific_data_too_short_is_rejected(self):
        """Every size short of the class specific data, down to none at
        all, where the event has no data to point at."""
        for cls, size in layout.CLASS_SPECIFIC_SIZE.items():
            for size_dw in range(size // 4):
                with self.subTest(cls=cls, size_dw=size_dw):
                    telemetry = one_fifo(layout.event(cls, 0x40,
                                                      bytes(size_dw * 4)))
                    self.assert_rejected(telemetry, strings(),
                                         INVALID_EVENT_MSG,
                                         'FIFO: 1, offset: 0x0',
                                         f'Type: 0x{cls:x}, ID: 0x40, '
                                         f'Size: 0x{size_dw:x}',
                                         FIFO_PARSE_FAILED_MSG)

    def test_common_classes_without_vu_data(self):
        """Reset, boot sequence, firmware assert, temperature and media
        events define no class specific data, so a zero-size one is just
        its descriptor."""
        telemetry = one_fifo(*(layout.event(cls, 0x50 + cls)
                               for cls in layout.COMMON_CLASSES))
        self.assert_events(telemetry, strings(),
                           [common(cls, 0x50 + cls, 0)
                            for cls in layout.COMMON_CLASSES])

    def test_common_classes_with_vu_data(self):
        vu_names = {(cls, 0x200 + cls): f'COMMON VU {cls:02X}'
                    for cls in layout.COMMON_CLASSES}
        telemetry = one_fifo(*(
            layout.event(cls, 0x50 + cls,
                         layout.vu_part(0x200 + cls,
                                        bytes.fromhex('112233445566')))
            for cls in layout.COMMON_CLASSES))
        self.assert_events(telemetry, strings(vu_event_strings=vu_names), [
            {**common(cls, 0x50 + cls, 2),
             'VU Event Identifier': f'0x{0x200 + cls:x}',
             'VU Event String': f'COMMON VU {cls:02X}',
             'VU Data': '112233445566'}
            for cls in layout.COMMON_CLASSES])

    def test_string_lookups_use_each_events_own_class(self):
        """Every class shares one Event Identifier and one VU Event
        Identifier, and each has its own names for them, so a lookup under
        any other class finds another class's name. Each event is the
        smallest one with VU data: one Dword past its class specific data,
        holding the VU Event Identifier and two bytes of VU data."""
        event_id, vu_id, vu_data = 0x42, 0x1234, b'\xAA\xBB'
        classes = sorted([*layout.CLASS_SPECIFIC_SIZE,
                          *layout.COMMON_CLASSES])
        events, expected = [], []
        for cls in classes:
            size = layout.CLASS_SPECIFIC_SIZE.get(cls, 0)
            data = bytes(range(0x10 + cls, 0x10 + cls + size))
            events.append(layout.event(cls, event_id,
                                       data + layout.vu_part(vu_id, vu_data)))
            fields = common(cls, event_id, size // 4 + 1, f'EVENT {cls:02X}')
            if size:
                fields['Class Specific Data'] = layout.hex_upper(data)
            expected.append({**fields,
                             'VU Event Identifier': f'0x{vu_id:x}',
                             'VU Event String': f'VU EVENT {cls:02X}',
                             'VU Data': 'AABB'})
        log = strings(
            event_strings={(cls, event_id): f'EVENT {cls:02X}'
                           for cls in classes},
            vu_event_strings={(cls, vu_id): f'VU EVENT {cls:02X}'
                              for cls in classes})
        self.assert_events(one_fifo(*events), log, expected)

    def test_largest_event_size(self):
        """Event Data Size is a byte, so 0xFF Dwords is the largest event
        any class can declare."""
        max_bytes = 0xFF * 4
        nvme_data = bytes(range(8))
        nvme_vu = bytes(i & 0xFF for i in range(max_bytes - 8 - 2))
        reset_vu = bytes((i * 3) & 0xFF for i in range(max_bytes - 2))
        vu_class = bytes((i * 7) & 0xFF for i in range(max_bytes))
        telemetry = one_fifo(
            layout.event(layout.CLASS_NVME, 0x61,
                         nvme_data + layout.vu_part(0x7001, nvme_vu)),
            layout.event(layout.CLASS_RESET, 0x62,
                         layout.vu_part(0x7002, reset_vu)),
            layout.event(0x80, 0x63, vu_class),
            PCIE_EVENT)
        self.assert_events(telemetry, strings(), [
            {**common(layout.CLASS_NVME, 0x61, 0xFF),
             'Class Specific Data': layout.hex_upper(nvme_data),
             'VU Event Identifier': '0x7001',
             'VU Event String': '',
             'VU Data': layout.hex_upper(nvme_vu)},
            {**common(layout.CLASS_RESET, 0x62, 0xFF),
             'VU Event Identifier': '0x7002',
             'VU Event String': '',
             'VU Data': layout.hex_upper(reset_vu)},
            {**common(0x80, 0x63, 0xFF), 'VU Data': layout.hex_upper(vu_class)},
            PCIE_EXPECTED,
        ])

    def test_reserved_classes_dump_class_specific_data(self):
        """A class the parser has no decoder for is still stepped over by
        its declared size, and its payload is printed undecoded as Class
        Specific Data. Up to 7Fh its Event String comes from the Event
        String Table; the VU table entries for the same pairs are decoys.
        0Eh is the first class OCP 2.7 leaves reserved."""
        events = [
            (0x0E, 0x0E, b'\x01\x02\x03\x04'),
            (0x0E, 0x8000, bytes.fromhex('C1C2C3C4C5C6C7C8')),
            (0x7F, 0x7F, bytes(8)),
            (0x7F, 0x80, b''),
        ]
        named = {(cls, event_id): f'RESERVED {cls:02X} {event_id:X}'
                 for cls, event_id, _ in events[:-1]}
        telemetry = one_fifo(*(layout.event(cls, event_id, data)
                               for cls, event_id, data in events),
                             PCIE_EVENT)
        log = strings(event_strings=named,
                      vu_event_strings={pair: 'VU DECOY' for pair in named})
        self.assert_events(telemetry, log, [
            *({**common(cls, event_id, len(data) // layout.DWORD,
                        named.get((cls, event_id), '')),
               'Class Specific Data': layout.hex_upper(data)}
              for cls, event_id, data in events),
            PCIE_EXPECTED])

    def test_vendor_unique_classes(self):
        """Classes 80h..FFh are all VU data, and their Event String comes
        from the VU Event String Table."""
        data = bytes.fromhex('0102030405060708')
        telemetry = one_fifo(layout.event(0x80, 0x99, data),
                             layout.event(0xFF, 0x99, data),
                             layout.event(0x80, 0x9A))
        log = strings(
            event_strings={(0x80, 0x99): 'EST DECOY'},
            vu_event_strings={(0x80, 0x99): 'VU CLASS 80',
                              (0xFF, 0x99): 'VU CLASS FF'})
        self.assert_events(telemetry, log, [
            {**common(0x80, 0x99, 2, 'VU CLASS 80'),
             'VU Data': '0102030405060708'},
            {**common(0xFF, 0x99, 2, 'VU CLASS FF'),
             'VU Data': '0102030405060708'},
            {**common(0x80, 0x9A, 0), 'VU Data': ''},
        ])

    def test_event_string_is_keyed_on_class_and_identifier(self):
        telemetry = one_fifo(
            layout.event(layout.CLASS_PCIE, 0x10, PCIE_DATA),
            layout.event(layout.CLASS_PCIE, 0x11, PCIE_DATA),
            layout.event(layout.CLASS_NVME, 0x11, bytes(8)))
        log = strings(event_strings={(layout.CLASS_PCIE, 0x10): 'PCIE LINK',
                                     (layout.CLASS_NVME, 0x11): 'NVME CMD'})
        self.assert_events(telemetry, log, [
            {**common(layout.CLASS_PCIE, 0x10, 1, 'PCIE LINK'),
             'Class Specific Data': 'A1A2A3A4'},
            {**common(layout.CLASS_PCIE, 0x11, 1),
             'Class Specific Data': 'A1A2A3A4'},
            {**common(layout.CLASS_NVME, 0x11, 2, 'NVME CMD'),
             'Class Specific Data': '0000000000000000'},
        ])

    def _snapshot_fifo(self):
        stat = layout.statistic(0x22, b'12345678', behavior=2, nsid=3,
                                ns_valid=True)
        return one_fifo(layout.statistic_snapshot_event(stat), PCIE_EVENT)

    _SNAPSHOT_EXPECTED = {
        'Debug Event Class type': '0xa',
        'Event String': '',
        'Statistics Identifier': '0x22',
        'Statistic Identifier String': 'XOR Recovery Count',
        'Statistics Info Behavior Type': '0x2',
        'Statistics Info Context Index': '0x0',
        'Statistics Info Host Hint Type': '0x0',
        'Statistics Info Reserved': '0x0',
        'Namespace Identifier': '0x3',
        'Namespace Information Valid': '0x1',
        'Statistic Data Size': '0x2',
        'Namespace Identifier[15:0]': '0x0',
        'Statistic Specific Data': '3132333435363738',
    }

    def test_statistic_snapshot_in_text(self):
        """The snapshot prints its class and the statistic it carries,
        and spans the whole statistic, so the next event decodes."""
        events = self.fifo_events(self._snapshot_fifo(), strings(),
                                  mode='text')
        self.assertEqual(events, [self._SNAPSHOT_EXPECTED, PCIE_EXPECTED])

    def test_statistic_snapshot_is_stepped_over_in_json(self):
        events = self.fifo_events(self._snapshot_fifo(), strings())
        self.assertEqual(events[-1], PCIE_EXPECTED)

    @unittest.expectedFailure
    def test_statistic_snapshot_in_json(self):
        """Defect: the JSON printer builds the snapshot's object but never
        adds it to the FIFO's event array."""
        events = self.fifo_events(self._snapshot_fifo(), strings())
        self.assertEqual(events, [self._SNAPSHOT_EXPECTED, PCIE_EXPECTED])

    @staticmethod
    def _snapshot(stat_id, name, data):
        return {**TestEventClassDecode._SNAPSHOT_EXPECTED,
                'Statistics Identifier': f'0x{stat_id:x}',
                'Statistic Identifier String': name,
                'Statistics Info Behavior Type': '0x0',
                'Namespace Identifier': '0x0',
                'Namespace Information Valid': '0x0',
                'Statistic Data Size': f'0x{len(data) // 4:x}',
                'Statistic Specific Data': layout.hex_upper(data)}

    def test_statistic_snapshots_of_different_sizes_in_text(self):
        small, large = bytes.fromhex('0A0B0C0D'), bytes(range(0x20, 0x2C))
        telemetry = one_fifo(
            layout.statistic_snapshot_event(layout.statistic(0x01, small)),
            layout.statistic_snapshot_event(layout.statistic(0x04, large)),
            PCIE_EVENT)
        events = self.fifo_events(telemetry, strings(), mode='text')
        self.assertEqual(events, [
            self._snapshot(0x01, 'Outstanding Admin Commands', small),
            self._snapshot(0x04, 'Active Namespaces', large),
            PCIE_EXPECTED])

    def test_statistic_snapshot_namespace_identifier_15_0_in_text(self):
        """Snapshot bytes 11:10 are the statistic's Namespace
        Identifier[15:0]."""
        stat = layout.statistic(0x22, b'12345678', behavior=2, nsid=3,
                                ns_valid=True, nsid_15_0=0xBEEF)
        telemetry = one_fifo(layout.statistic_snapshot_event(stat),
                             PCIE_EVENT)
        events = self.fifo_events(telemetry, strings(), mode='text')
        self.assertEqual(events, [
            {**self._SNAPSHOT_EXPECTED,
             'Namespace Identifier[15:0]': '0xbeef'},
            PCIE_EXPECTED])

    def test_statistic_snapshot_of_a_context_descriptor_in_text(self):
        """A snapshot may carry a Context Statistic Descriptor like any
        other statistic. It decodes as it does in the statistics area,
        with its context data and encapsulated statistics, and the
        snapshot spans all of it, so the next event decodes."""
        context = layout.queue_id_context(0x0102, 0x0304)
        small = bytes.fromhex('0A0B0C0D')
        inner = [layout.statistic(0x01, small),
                 layout.statistic(0x02, bytes(8))]
        stat = layout.context_statistic(layout.STAT_QUEUE_ID_CONTEXT,
                                        context, inner)
        telemetry = one_fifo(layout.statistic_snapshot_event(stat),
                             PCIE_EVENT)
        events = self.fifo_events(telemetry, strings(), mode='text')

        def encapsulated(stat_id, name, data):
            return {k: v for k, v in self._snapshot(stat_id, name,
                                                    data).items()
                    if k not in ('Debug Event Class type', 'Event String')}

        container = self._snapshot(layout.STAT_QUEUE_ID_CONTEXT,
                                   'Queue ID Context Statistic Descriptor',
                                   context + b''.join(inner))
        del container['Statistic Specific Data']
        container.update({
            'Statistics Info Context Index': '0x1',
            'Context Data Size': '0x2',
            'Context Data Reserved': '0x0',
            'Context Scope': '02010403',
            'Context Scope Fields': [
                {'Scope Field String': 'Controller ID',
                 'Scope Field Offset': '0x4', 'Scope Field Size': '0x2',
                 'Scope Field Value': '0x102'},
                {'Scope Field String': 'Queue ID',
                 'Scope Field Offset': '0x6', 'Scope Field Size': '0x2',
                 'Scope Field Value': '0x304'},
            ],
            'Encapsulated Statistic Descriptors': [
                encapsulated(0x01, 'Outstanding Admin Commands', small),
                encapsulated(0x02, 'Host Write Bandwidth', bytes(8)),
            ],
        })
        self.assertEqual(events, [container, PCIE_EXPECTED])

    def _empty_snapshot_fifo(self):
        return one_fifo(
            layout.statistic_snapshot_event(layout.statistic(0x02)),
            PCIE_EVENT)

    def test_statistic_snapshot_without_data_is_stepped_over_in_json(self):
        """A statistic with no data leaves the snapshot its two
        descriptors, and the next event follows them."""
        events = self.fifo_events(self._empty_snapshot_fifo(), strings())
        self.assertEqual(events[-1], PCIE_EXPECTED)

    @unittest.expectedFailure
    def test_statistic_snapshot_without_data_in_text(self):
        """Defect: parse_event_fifo() skips parse_statistic() when the
        statistic carries no data, so neither the statistic nor the record
        separator is printed."""
        events = self.fifo_events(self._empty_snapshot_fifo(), strings(),
                                  mode='text')
        self.assertEqual(events, [
            self._snapshot(0x02, 'Host Write Bandwidth', b''), PCIE_EXPECTED])


class TestTruncatedEvent(EventFifoTestBase):
    """An event whose declared length runs past the end of its FIFO is
    rejected, whatever its class, rather than decoded from the bytes that
    follow the FIFO. Each event here follows a PCIe event that fits, in a
    FIFO that ends short of it, with the rest of the event still in the
    log just past the FIFO."""

    def truncated(self, event, cut_dw):
        size_dw = (len(PCIE_EVENT) + len(event)) // layout.DWORD - cut_dw
        return layout.pack_telemetry(fifos={
            1: layout.Fifo(1, [PCIE_EVENT, event], size_dw=size_dw)})

    def assert_truncated_rejected(self, event, reason, cut_dw=1):
        self.assert_rejected(self.truncated(event, cut_dw), strings(),
                             invalid_entry(len(PCIE_EVENT), reason),
                             FIFO_PARSE_FAILED_MSG)

    def assert_event_one_dword_short(self, cls, event_id, event):
        data = len(event) - layout.EVENT_DESCRIPTOR_SIZE
        self.assert_truncated_rejected(
            event, f'class 0x{cls:x}, Event ID 0x{event_id:x} declares '
                   f'{data} data bytes, {data - layout.DWORD} left in FIFO')

    def test_virtual_fifo_descriptor_at_the_fifo_end(self):
        """The FIFO holds the descriptor of a size-1 class 0Bh event but
        not the Dword carrying its identifier."""
        self.assert_event_one_dword_short(
            layout.CLASS_VIRTUAL_FIFO, 0x21,
            layout.virtual_fifo_event(layout.virtual_fifo_id(1, 1), 0x21))

    def test_every_class_one_dword_short(self):
        events = {cls: layout.event(cls, 0x40, bytes(range(size)))
                  for cls, size in layout.CLASS_SPECIFIC_SIZE.items()}
        events.update({cls: layout.event(cls, 0x40, layout.vu_part(0x100))
                       for cls in layout.COMMON_CLASSES})
        events[layout.CLASS_VIRTUAL_FIFO] = layout.virtual_fifo_event(
            layout.virtual_fifo_id(1, 1), 0x40)
        events[layout.CLASS_SMBUS_I2C_I3C] = layout.smbus_event(
            0x40, vu=layout.vu_part(0x100, b'\x01\x02'))
        events[layout.CLASS_MCTP] = layout.mctp_event(
            0x40, vu=layout.vu_part(0x100, b'\x01\x02'))
        events[0x0E] = layout.event(0x0E, 0x40, bytes(4))
        events[0x80] = layout.event(0x80, 0x40, bytes(8))
        for cls, event in sorted(events.items()):
            with self.subTest(cls=cls):
                self.assert_event_one_dword_short(cls, 0x40, event)

    def test_largest_event_one_dword_short(self):
        self.assert_event_one_dword_short(
            0x80, 0x40, layout.event(0x80, 0x40, bytes(0xFF * 4)))

    # A snapshot's Event ID and Event Data Size bytes are reserved; these
    # give them values that differ from the statistic's own fields.
    SNAPSHOT = layout.statistic_snapshot_event(
        layout.statistic(0x22, b'1234'), event_id=0x77)

    def test_statistic_snapshot_cut_in_its_header(self):
        """The FIFO ends before the statistic's data size field."""
        self.assert_truncated_rejected(
            self.SNAPSHOT,
            'class 0xa needs a 12-byte header, 8 bytes left in FIFO',
            cut_dw=2)

    def test_statistic_snapshot_cut_in_its_data(self):
        self.assert_truncated_rejected(
            self.SNAPSHOT,
            'class 0xa, Statistic ID 0x22 declares 4 data bytes, '
            '0 left in FIFO')

    def test_event_ending_at_the_fifo_end_is_decoded(self):
        fifo_id = layout.virtual_fifo_id(1, 1)
        telemetry = self.truncated(layout.virtual_fifo_event(fifo_id), 0)
        self.assert_events(telemetry, strings(), [
            PCIE_EXPECTED, virtual_fifo(fifo_id, phys_string='PHYS FIFO 01')])


class TestEventFifoLayout(EventFifoTestBase):
    """parse_event_fifos(): which FIFOs are decoded, and where."""

    def fifo_titles_for(self, telemetry, log, *args, da=1):
        titles = {}
        for mode in MODES:
            report = self.decode(telemetry, log, *args, mode=mode)
            titles[mode] = self.fifo_titles(report, da)
        self.assertEqual(titles['json'], titles['text'],
                         'the printers disagree about the FIFOs')
        return titles['json']

    def test_fifos_are_named_from_the_string_log(self):
        """An unnamed FIFO keeps the separator, trailing space and all."""
        telemetry = layout.pack_telemetry(fifos={
            1: layout.Fifo(1, [PCIE_EVENT]), 2: layout.Fifo(1, [PCIE_EVENT])})
        self.assertEqual(
            self.fifo_titles_for(telemetry,
                                 strings(fifo_names={1: 'HOST EVENTS'})),
            ['EVENT FIFO 1 - HOST EVENTS', 'EVENT FIFO 2 - '])

    def test_sparse_fifo_numbers_are_kept(self):
        telemetry = layout.pack_telemetry(fifos={
            n: layout.Fifo(1, [PCIE_EVENT]) for n in (1, 5, 16)})
        self.assertEqual(self.fifo_titles_for(telemetry, strings()),
                         [f'EVENT FIFO {n} - {PHYS_NAMES[n]}'
                          for n in (1, 5, 16)])

    def test_data_area_2_fifos_are_decoded_from_data_area_2_up(self):
        nvme_event = layout.event(layout.CLASS_NVME, 0x32, bytes(8))
        telemetry = layout.pack_telemetry(fifos={
            1: layout.Fifo(1, [PCIE_EVENT]), 2: layout.Fifo(2, [nvme_event])})
        with self.subTest(data_area=1):
            self.assertEqual(self.fifo_titles_for(telemetry, strings()),
                             [FIFO_1])
            for mode in MODES:
                report = self.decode(telemetry, strings(), mode=mode)
                titles = (list(report) if mode == 'json'
                          else [name for name, _ in report])
                self.assertNotIn(STR_DA_EVENT_FIFO_INFO.format(2), titles)
        with self.subTest(data_area=2):
            self.assertEqual(
                self.fifo_titles_for(telemetry, strings(), '-a', '2'),
                [FIFO_1])
            self.assertEqual(
                self.fifo_titles_for(telemetry, strings(), '-a', '2', da=2),
                [f'EVENT FIFO 2 - {PHYS_NAMES[2]}'])
            self.assert_events(telemetry, strings(), [
                {**common(layout.CLASS_NVME, 0x32, 2),
                 'Class Specific Data': '0000000000000000'},
            ], '-a', '2', number=2, da=2)
        for value in ('3', '4'):
            with self.subTest(data_area=value):
                self.assertEqual(
                    self.fifo_titles_for(telemetry, strings(), '-a', value,
                                         da=2),
                    [f'EVENT FIFO 2 - {PHYS_NAMES[2]}'])

    def test_fifos_outside_data_areas_1_and_2_are_skipped(self):
        telemetry = layout.pack_telemetry(fifos={
            1: layout.Fifo(0, [PCIE_EVENT]),
            2: layout.Fifo(3, [PCIE_EVENT]),
            3: layout.Fifo(1, [PCIE_EVENT])})
        self.assertEqual(
            self.fifo_titles_for(telemetry, strings(), '-a', '2'),
            [f'EVENT FIFO 3 - {PHYS_NAMES[3]}'])
        self.assertEqual(
            self.fifo_titles_for(telemetry, strings(), '-a', '2', da=2), [])

    def test_end_of_list_entry_stops_the_fifo(self):
        """Class 00h ends the list; what follows it is not an event."""
        telemetry = one_fifo(PCIE_EVENT, b'\x00\xFF\xFF\xFF',
                             layout.event(0xFF, 0xFFFF, b'\xFF' * 4))
        self.assert_events(telemetry, strings(), [PCIE_EXPECTED])

    def test_fifo_ends_at_its_size(self):
        """A FIFO filled to its size with no end-of-list entry stops there,
        even though the next FIFO's events follow it directly."""
        nvme_event = layout.event(layout.CLASS_NVME, 0x32, bytes(8))
        telemetry = layout.pack_telemetry(fifos={
            1: layout.Fifo(1, [PCIE_EVENT]), 2: layout.Fifo(1, [nvme_event])})
        self.assert_events(telemetry, strings(), [PCIE_EXPECTED])

    def test_no_fifos(self):
        telemetry = layout.pack_telemetry()
        self.assertEqual(self.fifo_titles_for(telemetry, strings()), [])
        report = self.decode(telemetry, strings())
        self.assertEqual(report[STR_DA_EVENT_FIFO_INFO.format(1)], {})

    def test_fifo_ending_exactly_at_the_data_area_end(self):
        blocks = 4
        last_dw = blocks * layout.BLOCK_SIZE // layout.DWORD - 1
        telemetry = layout.pack_telemetry(
            fifos={1: layout.Fifo(1, [layout.event(layout.CLASS_RESET, 1)],
                                  start_dw=last_dw)},
            da1_blocks=blocks)
        self.assert_events(telemetry, strings(),
                           [common(layout.CLASS_RESET, 1, 0)])

    def test_fifo_overrunning_its_data_area_is_rejected(self):
        """One Dword past the end of Data Area 1 is out of bounds, even
        though Data Area 2 follows it in the log."""
        blocks = 4
        last_dw = blocks * layout.BLOCK_SIZE // layout.DWORD - 1
        telemetry = layout.pack_telemetry(
            fifos={1: layout.Fifo(1, start_dw=last_dw, size_dw=2)},
            da1_blocks=blocks, da2_blocks=1)
        self.assert_rejected(telemetry, strings(), INVALID_BOUNDS_MSG)

    def test_zero_size_fifo_is_rejected(self):
        """A FIFO assigned to a data area has to hold something."""
        telemetry = layout.pack_telemetry(fifos={1: layout.Fifo(1)})
        self.assert_rejected(telemetry, strings(), INVALID_BOUNDS_MSG)

    def test_bad_fifo_after_a_good_one_fails_the_decode(self):
        telemetry = layout.pack_telemetry(fifos={
            1: layout.Fifo(1, [PCIE_EVENT]), 2: layout.Fifo(1)})
        self.assert_rejected(telemetry, strings(), INVALID_BOUNDS_MSG)


class TestDecodeFailureExitStatus(EventFifoTestBase):
    """A rejected log has to be visible to a caller that checks only the
    exit status."""

    def _assert_fails(self, telemetry):
        result = self.run_internal_log(telemetry=telemetry,
                                       strings=strings())
        self.assertNotEqual(result.returncode, 0,
                            'a log the decoder rejected exited 0')

    @unittest.expectedFailure
    def test_invalid_event_exits_nonzero(self):
        """Defect: parse_ocp_telemetry_log() returns 0 whatever the
        printer reported."""
        self._assert_fails(one_fifo(layout.virtual_fifo_event(
            layout.virtual_fifo_id(1, 1), size_dw=0)))

    @unittest.expectedFailure
    def test_invalid_fifo_bounds_exit_nonzero(self):
        """Defect: parse_ocp_telemetry_log() returns 0 whatever the
        printer reported."""
        self._assert_fails(layout.pack_telemetry(fifos={1: layout.Fifo(1)}))


if __name__ == '__main__':
    main()
