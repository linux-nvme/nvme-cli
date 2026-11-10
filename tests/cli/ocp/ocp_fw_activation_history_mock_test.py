#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp fw-activate-history" and "nvme ocp
clear-fw-activate-history" against a mocked controller.

The mock serves synthetic C2h Firmware Activation History pages built by
tests/e2e/plugins/ocp/ocp_c2_layout.py, transcribed from the OCP
specification 2.0 (section 4.8.7) rather than from nvme-cli's struct.
Clear Firmware Update History (FID C1h) is checked against 2.0 section
4.12.4 (CFUH), and what the plugin shows against the plug-in
requirements of section 16.2.2 (UTIL-FWHST). OCP 2.5 makes the page and
the feature obsolete.

Tests in this module verify:
  * The page is read as LID C2h, 4096 bytes, for all namespaces (the
    page has NVM subsystem scope), with the OCP UUID index (UUID-5), or
    index 0 without the OCP UUID.
  * The header and every field of each valid entry (FAHL-3, FAHE-1..12)
    are printed in text and JSON, never more than the 20 entries the page
    holds.
  * A page with a different GUID (FAHL-7) is rejected.
  * clear-fw-activate-history sets bit 31 of CDW11 of Set Features for
    FID C1h with NSID 0 and without Save (CFUH-6, 10, 13), after which
    the history is empty (FAHL-3); a failing Set Features fails the
    command.

Known defects are covered by expectedFailure tests asserting the
behavior the specification defines: once the circular buffer has wrapped
the entries are not listed oldest first (FWHST-LOG-1, UTIL-FWHST-3), the
Result is not shown as Pass or Failed with the status code
(UTIL-FWHST-15), -o binary prints "unhandled output format" and exits
0, and with no OCP UUID clear-fw-activate-history sends nothing yet
exits 0.

Section 16 also asks for a table (UTIL-NM-3) with the Power on Hours to
the second (UTIL-FWHST-9) and the Commit Action Type in binary, as in
its example output; the plugin prints one "key: value" line per field,
the Timestamp in milliseconds and the Commit Action Type in decimal.
These tests check the values, not that presentation.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_fw_activation_history_mock_test.py <nvme-binary> <mock-lib>
"""
import unittest

from tests.cli.nvme_mock import (NSID_ALL, OPC_SET_FEATURES,
                                 SC_INVALID_FIELD, Reply, main)
from tests.cli.ocp.ocp_mock_test import (UUID_INDEX, UUID_SLOT,
                                         OCPController, OCPMockTestBase,
                                         OCPUUIDTests)
from tests.e2e.plugins.ocp import ocp_c2_layout as layout
from tests.e2e.plugins.ocp.ocp_c2_layout import Entry

FID_CLEAR_FW_UPDATE_HISTORY = 0xC1
CLEAR = 1 << 31
SV = 1 << 31

UNKNOWN_GUID_MSG = 'Unknown GUID in C2 Log Page data'
GUID_TEXT = '0x' + layout.GUID_BYTES[::-1].hex()

ENTRIES = (
    Entry(version=1, length=64, activation_count=0x0102,
          timestamp_ms=0x0000_0A0B_0C0D_0E0F, timestamp_attr=0x02,
          power_cycle_count=0x1112_1314_1516_1718,
          previous_fw=b'FWREV001', new_fw=b'FWREV002', slot=2,
          commit_action=3, result=0x0004),
    Entry(version=1, length=64, activation_count=0x0203,
          timestamp_ms=0x0000_1A1B_1C1D_1E1F,
          power_cycle_count=0x2122_2324_2526_2728,
          previous_fw=b'FWREV002', new_fw=b'FWREV003', slot=1,
          commit_action=1, result=0x0106),
)

# The value each printer shows for each entry field.
ENTRY_FIELDS = {
    'version number': lambda e: e.version,
    'entry length': lambda e: e.length,
    'activation count': lambda e: e.activation_count,
    'timestamp': lambda e: e.timestamp_ms,
    'power cycle count': lambda e: e.power_cycle_count,
    'previous firmware': lambda e: e.previous_fw.decode(),
    'new firmware': lambda e: e.new_fw.decode(),
    'slot number': lambda e: e.slot,
    'commit action type': lambda e: e.commit_action,
    'result': lambda e: e.result,
}


def expected_entry(e, text):
    """Entry @e as the text or JSON printer shows it. The text Result is
    left out; test_result_is_pass_or_failed checks how it is shown."""
    if text:
        return {k: str(f(e)) for k, f in ENTRY_FIELDS.items()
                if k != 'result'}
    return {k: f(e) for k, f in ENTRY_FIELDS.items()}


def parse_text(stdout):
    """The header fields and the list of entries of the text report."""
    header, entries = {}, []
    for line in stdout.splitlines():
        key, sep, value = line.strip().partition(':')
        if not sep:
            continue
        if line.startswith('    entry['):
            entries.append({})
        elif line.startswith('      ') and entries:
            entries[-1][key] = value.strip()
        elif line.startswith('  ') and not line.startswith('   '):
            header[key] = value.strip()
    return header, entries


class FwHistoryController(OCPController):
    """Serves the C2h page in @logs. Set Features for FID C1h answers
    @clear_status and, when it succeeds with bit 31 of CDW11 set, empties
    the history."""

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.uuid_slot = UUID_SLOT
        self.clear_status = 0
        self.features[FID_CLEAR_FW_UPDATE_HISTORY] = self._clear

    def _clear(self, cmd):
        if cmd.opcode == OPC_SET_FEATURES and not self.clear_status \
                and cmd.cdw11 & CLEAR:
            self.logs[layout.LID] = layout.pack()
        return Reply(status=self.clear_status)


class FwHistoryTestBase(OCPMockTestBase):

    controller_class = FwHistoryController

    def setUp(self):
        super().setUp()
        self.serve(layout.pack(ENTRIES))

    def serve(self, page):
        self.page = page
        self.server.logs[layout.LID] = page

    def run_cmd(self, command, *args, encoding='utf-8'):
        self.server.commands.clear()
        return self.run_ocp(command, *args, encoding=encoding)

    def text_log(self, *args):
        return parse_text(self.assertOk(
            self.run_cmd('fw-activate-history', *args)).stdout)

    def json_log(self, *args):
        self.server.commands.clear()
        return self.run_json('fw-activate-history', *args)

    def cmds(self, opcode):
        return [c for c in self.server.admin_cmds(opcode)
                if c.fid == FID_CLEAR_FW_UPDATE_HISTORY]

    def clears(self):
        return self.cmds(OPC_SET_FEATURES)


class TestFwActivationHistory(FwHistoryTestBase):

    def test_page_is_read_with_the_ocp_uuid_index(self):
        self.text_log()
        reads = self.server.log_reads(layout.LID)
        self.assertEqual(len(reads), 1, reads)
        self.assertEqual(
            (reads[0].lpo, reads[0].data_len, reads[0].nsid,
             reads[0].uuid_index),
            (0, layout.LOG_PAGE_SIZE, NSID_ALL, UUID_INDEX))

    def test_without_the_ocp_uuid_index_0_is_used(self):
        self.server.uuid_slot = None
        _, entries = self.text_log()
        self.assertEqual(len(entries), len(ENTRIES))
        self.assertEqual(
            [r.uuid_index for r in self.server.log_reads(layout.LID)], [0])

    def test_fields_in_text(self):
        header, entries = self.text_log()
        self.assertEqual(header['log identifier'], str(layout.LID))
        self.assertEqual(header['valid entries'], str(len(ENTRIES)))
        self.assertEqual(header['log page version'], '1')
        self.assertEqual(header['log page guid'], GUID_TEXT)
        # How Result is shown is test_result_is_pass_or_failed's to check,
        # so that fixing that defect leaves this test alone; here it only
        # has to be there.
        for entry in entries:
            self.assertIn('result', entry)
            del entry['result']
        self.assertEqual(entries, [expected_entry(e, True) for e in ENTRIES])

    def test_fields_in_json(self):
        log = self.json_log()
        self.assertEqual(log['log identifier'], layout.LID)
        self.assertEqual(log['valid entries'], len(ENTRIES))
        self.assertEqual(log['log page version'], 1)
        self.assertEqual(log['log page guid'], GUID_TEXT)
        self.assertEqual(log['entries'],
                         [expected_entry(e, False) for e in ENTRIES])

    def test_no_valid_entries(self):
        self.serve(layout.pack(ENTRIES, valid=0))
        self.assertEqual(self.text_log()[1], [])
        self.assertEqual(self.json_log()['entries'], [])

    def test_no_more_than_the_entries_of_the_page(self):
        entries = [ENTRIES[i % 2]._replace(activation_count=i,
                                           timestamp_ms=i * 60_000)
                   for i in range(layout.MAX_ENTRIES)]
        self.serve(layout.pack(entries, valid=0xFFFFFFFF))
        _, text = self.text_log()
        self.assertEqual([e['activation count'] for e in text],
                         [str(i) for i in range(layout.MAX_ENTRIES)])
        self.assertEqual(len(self.json_log()['entries']),
                         layout.MAX_ENTRIES)

    def test_unknown_guid_is_rejected(self):
        self.serve(layout.pack(ENTRIES, guid=bytes(16)))
        result = self.run_cmd('fw-activate-history')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(UNKNOWN_GUID_MSG, result.stdout + result.stderr)
        self.assertNotIn('entries', result.stdout)

    @unittest.expectedFailure
    def test_wrapped_history_is_listed_oldest_first(self):
        """Defect: the 21st activation goes into entry 0 (FWHST-LOG-1) and
        the entries are listed oldest first (UTIL-FWHST-3), but the plugin
        lists them in entry order, so after a wrap the newest come
        first."""
        # Activations 3 to 22; 21 and 22 have wrapped into entries 0 and 1.
        counts = range(3, 23)
        history = [ENTRIES[0]._replace(activation_count=n,
                                       timestamp_ms=n * 60_000)
                   for n in counts]
        self.serve(layout.pack(history, start=2))
        _, text = self.text_log()
        self.assertEqual([e['activation count'] for e in text],
                         [str(n) for n in counts])
        self.assertEqual([e['activation count']
                          for e in self.json_log()['entries']], list(counts))

    @unittest.expectedFailure
    def test_result_is_pass_or_failed(self):
        """Defect: a Result of 0000h is shown as "Pass" and any other as
        "Failed" with the status code (UTIL-FWHST-15, FAHE-12); the plugin
        prints the number."""
        failed = ENTRIES[1].result
        self.serve(layout.pack([ENTRIES[0]._replace(result=0), ENTRIES[1]]))
        _, text = self.text_log()
        self.assertEqual(text[0]['result'], 'Pass')
        self.assertTrue(text[1]['result'].startswith('Fail'),
                        text[1]['result'])
        self.assertTrue(any(code in text[1]['result'].lower()
                            for code in (str(failed), f'{failed:x}')),
                        text[1]['result'])

    @unittest.expectedFailure
    def test_binary_is_the_page(self):
        """Defect: the binary printer has no fw_act_history, so -o binary
        prints "unhandled output format" and exits 0."""
        result = self.run_cmd('fw-activate-history', '-o', 'binary',
                              encoding=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.page)


class TestClearFwActivationHistory(OCPUUIDTests, FwHistoryTestBase):

    without_uuid = (OPC_SET_FEATURES, 'clear-fw-activate-history')

    def test_clear_sets_cdw11_bit_31(self):
        self.assertOk(self.run_cmd('clear-fw-activate-history'))
        clears = self.clears()
        self.assertEqual(len(clears), 1, clears)
        self.assertEqual(
            (clears[0].cdw11, clears[0].cdw10 & SV, clears[0].nsid,
             clears[0].uuid_index),
            (CLEAR, 0, 0, UUID_INDEX))

    def test_no_uuid_clears_with_index_0(self):
        self.assertOk(self.run_cmd('clear-fw-activate-history',
                                   '--no-uuid'))
        self.assertEqual([c.uuid_index for c in self.clears()], [0])

    def test_history_is_empty_after_a_clear(self):
        self.assertOk(self.run_cmd('clear-fw-activate-history'))
        header, entries = self.text_log()
        self.assertEqual((header['valid entries'], entries), ('0', []))

    def test_failing_clear_fails(self):
        self.server.clear_status = SC_INVALID_FIELD
        result = self.run_cmd('clear-fw-activate-history')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.text_log()[1]), len(ENTRIES))


if __name__ == '__main__':
    main()
