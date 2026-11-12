#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp set-error-injection" and "nvme ocp
get-error-injection" against a mocked controller.

The commands and the Event Injection Entry are checked against the OCP
specification (2.7 sections 4.15.3 and 4.15.4, called Error Injection up
to 2.6), not against nvme-cli's struct: Set Features for FID C0h carries
the Number of Event Injections in CDW11 bits 6:0 (SERRI-14) and the
entries in its data (SERRI-9, ERRIE, ERRIEDP), and Get Features returns
the number in Dword 0 bits 6:0 (GERRI-2) and the entries in its data.

Tests in this module verify:
  * set-error-injection sends one enabled, single instance entry of the
    given type and Number of Reads to Trigger Device Event, or the
    entries of a --data file, never with Save set (SERRI-10).
  * get-error-injection prints the number and each entry, its type named
    as the Event Definition Table names it.
  * --all-ns sends NSID FFFFFFFFh and 0 otherwise (NVMe Base 2.1
    section 4.4, and GETF-4 for the Get), the OCP UUID index or with
    --no-uuid index 0 (UUID-3), and a failing Set Features fails the
    command.

Known defects are covered by expectedFailure tests asserting the
behavior the specification defines: the data is not the 4096-byte range
SERRI-9 describes, a number too large for CDW11 bits 6:0 is sent, the
capabilities a Get with SEL 3 returns are listed as
entries, the types OCP 2.7 adds are named "unknown", and with no OCP UUID
both commands exit 0.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_error_injection_mock_test.py <nvme-binary> <mock-lib>
"""
import os
import struct
import unittest

from tests.cli.nvme_mock import (CNS_UUID_LIST, NSID_ALL, OPC_GET_FEATURES,
                                 OPC_SET_FEATURES, SC_INVALID_FIELD, Reply,
                                 main)
from tests.cli.ocp.ocp_mock_test import (CHANGEABLE_CAPABILITIES, UUID_INDEX,
                                         OCPFeatureController,
                                         OCPFeatureTestBase, OCPUUIDTests)

# Set Features CDW10 bit 31 (SERRI-10), CDW11 bits 6:0 (SERRI-14) and
# the data range DPTR points to (SERRI-9).
SV = 1 << 31
NUMBER_MASK = 0x7F
DATA_RANGE = 4096

# Event Injection Entry (ERRIE-1..4, ERRIEDP-1..4).
ENTRY_SIZE = 32
ENTRY_FLAGS = 0
ENTRY_TYPE = 2
ENTRY_NRTDE = 4
ENTRY_LATENCY = 8
FLAG_ENABLE = 1 << 0
FLAG_SINGLE = 1 << 1

# Event Definition Table: 0001h-0016h as OCP 2.6 names them, the name OCP
# 2.7 gives 0016h (EVTDEF-23), and what OCP 2.7 adds.
TYPE_NAMES = {
    0x01: 'CPU/Controller Hang',
    0x02: 'NAND Hang',
    0x03: 'PLP Defect',
    0x04: 'Logical Firmware Error',
    0x05: 'DRAM Corruption Critical Path',
    0x06: 'DRAM Corruption Non-Critical Path',
    0x07: 'NAND Corruption',
    0x08: 'SRAM Corruption',
    0x09: 'HW Malfunction',
    0x0A: 'No More NAND Spares Available',
    0x0B: 'Incomplete Shutdown',
    0x0C: 'Metadata Corruption',
    0x0D: 'Critical Garbage Collection',
    0x0E: 'Latency Spike',
    0x0F: 'I/O command failure',
    0x10: 'I/O command timeout',
    0x11: 'Admin command failure',
    0x12: 'Admin command timeout',
    0x13: 'Thermal Throttle Engaged',
    0x14: 'Thermal Throttle Disengaged',
    0x15: 'Critical Temperature Event',
    0x16: 'Die Offline',
}
RENAMED_IN_2_7 = {0x16: 'NAND Die Offline'}
TYPE_NAMES_2_7 = {
    0x17: 'Sanitize Command Failure',
    0x19: 'Require Format NVM Use User Data Erase',
    0x1A: 'Inject PCIe Correctable Errors',
    0x1B: 'Inject PCIe Uncorrectable Errors',
    0x1C: 'Clear the Persistent Event Log',
    0x1D: 'Sanitize Operation Failure',
    0x1E: 'Random I/O Latency Spikes Over Time',
    0x1F: 'Reset To Factory Default Settings',
    0x20: 'Supply Voltage Drop',
    0x21: 'Available Spare Threshold',
    0x22: 'Volatile Memory Backup Failure',
}


def entry(type_, nrtde=0, flags=FLAG_ENABLE | FLAG_SINGLE, latency=0):
    data = bytearray(ENTRY_SIZE)
    data[ENTRY_FLAGS] = flags
    struct.pack_into('<H', data, ENTRY_TYPE, type_)
    struct.pack_into('<H', data, ENTRY_NRTDE, nrtde)
    struct.pack_into('<I', data, ENTRY_LATENCY, latency)
    return bytes(data)


class EventInjectionController(OCPFeatureController):
    """Answers Get Features of FID C0h with @nume in Dword 0 and
    @entries as the data, whatever the SEL."""

    fid = 0xC0

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.nume = 0
        self.entries = b''

    def answer_feature(self, cmd):
        if cmd.opcode == OPC_SET_FEATURES:
            return Reply(status=self.set_status)
        return Reply(result=self.nume, data=self.entries)


class EventInjectionTestBase(OCPFeatureTestBase):

    controller_class = EventInjectionController

    def sent(self, *args):
        """Run set-error-injection with @args and return its Set
        Features."""
        self.assertOk(self.run_cmd('set-error-injection', *args))
        return self.only(OPC_SET_FEATURES)

    def got(self, *args):
        """Run get-error-injection with @args, returning its output and
        its Get Features."""
        result = self.assertOk(self.run_cmd('get-error-injection', *args))
        return result.stdout, self.only(OPC_GET_FEATURES)

    def entry_lines(self, stdout):
        return [line for line in stdout.splitlines()
                if line.startswith('Entry: ')]


class TestSetErrorInjection(OCPUUIDTests, EventInjectionTestBase):

    without_uuid = (OPC_SET_FEATURES, 'set-error-injection', '--type', '1')

    def test_one_entry_of_the_given_type(self):
        cmd = self.sent('--type', '0xe', '--nrtdp', '0x1234')
        self.assertEqual(cmd.cdw10 & SV, 0)
        self.assertEqual(cmd.cdw11, 1)
        self.assertEqual(cmd.nsid, 0)
        self.assertEqual(cmd.data[:ENTRY_SIZE], entry(0x0E, 0x1234))
        self.assertEqual(cmd.data[ENTRY_SIZE:],
                         bytes(len(cmd.data) - ENTRY_SIZE))

    def test_entry_from_a_data_file(self):
        data = entry(0x0E, 0x0102, latency=0x0A0B0C0D)
        path = os.path.join(self.tmp, 'erri.bin')
        with open(path, 'wb') as f:
            f.write(data)
        cmd = self.sent('--data', path)
        self.assertEqual(cmd.cdw11, 1)
        self.assertEqual(cmd.data[:ENTRY_SIZE], data)

    def test_number_0_clears_the_injection(self):
        """ERRI-2: 0 clears an untriggered injection."""
        cmd = self.sent('--number', '0')
        self.assertEqual(cmd.cdw11, 0)

    def test_all_ns_sends_nsid_ffffffff(self):
        self.assertEqual(self.sent('--type', '1', '--all-ns').nsid,
                         NSID_ALL)

    def test_no_uuid_skips_the_uuid_lookup(self):
        """With --no-uuid the UUID List is not read and index 0 is
        sent."""
        cmd = self.sent('--type', '1', '--no-uuid')
        self.assertEqual(self.server.identifies(CNS_UUID_LIST), [])
        self.assertEqual(cmd.uuid_index, 0)

    def test_sent_with_the_ocp_uuid_index(self):
        self.assertEqual(self.sent('--type', '1').uuid_index, UUID_INDEX)

    @unittest.expectedFailure
    def test_data_is_the_4096_byte_range(self):
        """Defect: SERRI-9 has DPTR describe a 4096-byte range; the
        command transfers 32 bytes per entry."""
        self.assertEqual(self.sent('--type', '1').data_len, DATA_RANGE)

    @unittest.expectedFailure
    def test_number_too_large_for_its_field_is_refused(self):
        """Defect: the number goes into CDW11 unchecked, so 128 sets
        reserved bit 7 (SERRI-13). OCP 2.5 and 2.6 allow up to 127
        entries, 2.7 only 1 (SERRI-14)."""
        result = self.run_cmd('set-error-injection', '--type', '1',
                              '--number', str(NUMBER_MASK + 1))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.cmds(OPC_SET_FEATURES), [])

    def test_failing_set_features_fails(self):
        self.server.set_status = SC_INVALID_FIELD
        result = self.run_cmd('set-error-injection', '--type', '1')
        self.assertNotEqual(result.returncode, 0)


class TestGetErrorInjection(OCPUUIDTests, EventInjectionTestBase):

    without_uuid = (OPC_GET_FEATURES, 'get-error-injection')

    def test_current_value_is_read(self):
        stdout, cmd = self.got()
        self.assertEqual((cmd.sel, cmd.nsid, cmd.uuid_index),
                         (0, 0, UUID_INDEX))
        self.assertGreaterEqual(cmd.data_len, ENTRY_SIZE)
        self.assertIn('(Current: 0)', stdout)
        self.assertEqual(self.entry_lines(stdout), [])

    def test_sel_all_ns_and_no_uuid(self):
        _, cmd = self.got('--sel', '1', '--all-ns', '--no-uuid')
        self.assertEqual((cmd.sel, cmd.nsid, cmd.uuid_index),
                         (1, NSID_ALL, 0))

    def test_entry_is_printed(self):
        self.server.nume = 1
        self.server.entries = entry(0x0E, 0x1234)
        stdout, _ = self.got()
        self.assertIn('(Current: 1)', stdout)
        self.assertEqual(
            self.entry_lines(stdout),
            ['Entry: 0, Flags: 3 (Enabled, Single instance), '
             'Type: e (Latency Spike), NRTDP: 4660'])

    def test_number_is_dword_0_bits_6_0(self):
        """GERRI-1: bits 31:7 are reserved."""
        self.server.nume = 0xFFFFFF80 | 1
        self.server.entries = entry(0x01)
        stdout, _ = self.got()
        self.assertIn('(Current: 1)', stdout)
        self.assertEqual(len(self.entry_lines(stdout)), 1)

    def type_names(self, types):
        """The type name printed for each of @types, one entry each."""
        self.server.nume = len(types)
        self.server.entries = b''.join(entry(t) for t in types)
        stdout, _ = self.got()
        lines = self.entry_lines(stdout)
        self.assertEqual(len(lines), len(types), stdout)
        return {t: line.split(' (')[2].split(')')[0]
                for t, line in zip(types, lines)}

    def test_type_names(self):
        names = self.type_names(list(TYPE_NAMES))
        for t, name in TYPE_NAMES.items():
            with self.subTest(type=hex(t)):
                self.assertIn(names[t].casefold(),
                              {name.casefold(),
                               RENAMED_IN_2_7.get(t, name).casefold()})

    @unittest.expectedFailure
    def test_type_names_added_in_2_7(self):
        """Defect: the types the OCP 2.7 Event Definition Table adds
        (EVTDEF-24..35) are named "unknown"."""
        names = self.type_names(list(TYPE_NAMES_2_7))
        for t, name in TYPE_NAMES_2_7.items():
            with self.subTest(type=hex(t)):
                self.assertEqual(names[t].casefold(), name.casefold())

    def test_sel_3_prints_the_capabilities(self):
        self.server.nume = CHANGEABLE_CAPABILITIES
        stdout, cmd = self.got('--sel', '3')
        self.assertEqual(cmd.sel, 3)
        self.assertIn('Feature is changeable', stdout)
        self.assertNotIn('Feature is saveable', stdout)

    @unittest.expectedFailure
    def test_sel_3_lists_no_entries(self):
        """Defect: Dword 0 of SEL 3 holds the capabilities (GERRI-2,
        GETF-5), yet it is taken for the number of entries to list."""
        self.server.nume = CHANGEABLE_CAPABILITIES
        stdout, _ = self.got('--sel', '3')
        self.assertEqual(self.entry_lines(stdout), [])


if __name__ == '__main__':
    main()
