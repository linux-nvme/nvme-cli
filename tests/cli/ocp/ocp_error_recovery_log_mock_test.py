#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp error-recovery-log" against a mocked controller.

The mock serves synthetic C1h Error Recovery pages built by
tests/e2e/plugins/ocp/ocp_c1_layout.py, transcribed from the OCP
specification (2.7 section 4.8.7.2) rather than from nvme-cli's struct.
The reports label the fields with the names OCP 2.6 gives them (Panic
for what 2.7 calls Error).

Tests in this module verify:
  * The page is read as LID C1h, 512 bytes, for all namespaces, with the
    OCP UUID index, or index 0 with --no-uuid; without the OCP UUID
    nothing is read.
  * Every field decodes to the value in the page in text and JSON, the
    eight-byte Error ID whole and four-byte fields unsigned, and both
    reports carry the Error / Assert Count (EREC-16) and list the four
    Previous Error IDs (EREC-17).
  * A page with a different GUID is rejected, and -o binary writes the
    page unchanged.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_error_recovery_log_mock_test.py <nvme-binary> <mock-lib>
"""
import re

from tests.cli.nvme_mock import NSID_ALL, main
from tests.cli.ocp.ocp_mock_test import (UUID_INDEX, UUID_SLOT,
                                         OCPMockTestBase, report_fields)
from tests.e2e.plugins.ocp import ocp_c1_layout as layout

UNKNOWN_GUID_MSG = 'Unknown GUID in C1 Log Page data'
GUID_TEXT = '0x' + layout.GUID_BYTES[::-1].hex()

# The label both reports give each field.
LABELS = {
    layout.ERROR_RESET_WAIT_TIME: 'Panic Reset Wait Time',
    layout.ERROR_RESET_ACTION: 'Panic Reset Action',
    layout.DEVICE_RECOVERY_ACTION_1: 'Device Recovery Action 1',
    layout.ERROR_ID: 'Panic ID',
    layout.DEVICE_CAPABILITIES: 'Device Capabilities',
    layout.VS_RECOVERY_OPCODE: 'Vendor Specific Recovery Opcode',
    layout.VS_COMMAND_CDW12: 'Vendor Specific Command CDW12',
    layout.VS_COMMAND_CDW13: 'Vendor Specific Command CDW13',
    layout.VS_COMMAND_TIMEOUT: 'Vendor Specific Command Timeout',
    layout.DEVICE_RECOVERY_ACTION_2: 'Device Recovery Action 2',
    layout.DEVICE_RECOVERY_ACTION_2_TIMEOUT:
        'Device Recovery Action 2 Timeout',
    layout.ERROR_ASSERT_COUNT: 'Panic Count',
}
DWORD_FIELDS = (layout.DEVICE_CAPABILITIES, layout.VS_COMMAND_CDW12,
                layout.VS_COMMAND_CDW13)

PREVIOUS_ID_RE = re.compile(r'Panic ID N-(\d) : (0x[0-9a-f]+)$')


def scalars(value):
    """Every value in the JSON @value, however deeply nested."""
    if isinstance(value, dict):
        value = list(value.values())
    if isinstance(value, list):
        return {s for v in value for s in scalars(v)}
    return {value}


class ErrorRecoveryLogTestBase(OCPMockTestBase):

    def setUp(self):
        super().setUp()
        self.server.uuid_slot = UUID_SLOT
        self.serve()

    def serve(self, values=None, **kwargs):
        self.page, self.values = layout.pack(values, **kwargs)
        self.server.logs = {layout.LID: self.page}

    def run_c1(self, *args, encoding='utf-8'):
        self.server.commands.clear()
        return self.run_ocp('error-recovery-log', *args, encoding=encoding)

    def text_report(self, *args):
        return self.assertOk(self.run_c1(*args)).stdout

    def text_log(self, *args):
        return report_fields(self.text_report(*args))

    def json_log(self, *args):
        self.server.commands.clear()
        return self.run_json('error-recovery-log', *args)

    def assertTextFields(self, fields, names):
        """@names of the page decode in the text report @fields."""
        for name in names:
            with self.subTest(mode='text', field=name):
                self.assertEqual(fields.get(LABELS[name]),
                                 f'0x{self.values[name]:x}')

    def assertJsonFields(self, log, names):
        """@names of the page decode in the JSON report @log."""
        for name in names:
            with self.subTest(mode='json', field=name):
                self.assertEqual(log.get(LABELS[name]), self.values[name])


class TestErrorRecoveryLog(ErrorRecoveryLogTestBase):

    def test_page_is_read_with_the_ocp_uuid_index(self):
        self.assertOk(self.run_c1())
        reads = self.server.log_reads(layout.LID)
        self.assertEqual(len(reads), 1, reads)
        self.assertEqual(
            (reads[0].lpo, reads[0].data_len, reads[0].nsid,
             reads[0].uuid_index),
            (0, layout.LOG_PAGE_SIZE, NSID_ALL, UUID_INDEX))

    def test_no_uuid_reads_index_0(self):
        self.assertOk(self.run_c1('--no-uuid'))
        self.assertEqual(
            [r.uuid_index for r in self.server.log_reads(layout.LID)], [0])

    def test_without_the_ocp_uuid_nothing_is_read(self):
        self.server.uuid_slot = None
        result = self.run_c1()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.server.log_reads(layout.LID), [])

    def test_fields_in_text(self):
        fields = self.text_log()
        self.assertTextFields(fields, layout.FIELDS)
        self.assertEqual(fields['Log Page Version'], '0x3')
        self.assertEqual(fields['Log page GUID'], GUID_TEXT)

    def test_fields_in_json(self):
        log = self.json_log()
        self.assertJsonFields(log, layout.FIELDS)
        self.assertEqual(log['Log Page Version'], 3)
        self.assertEqual(log['Log page GUID'], GUID_TEXT)

    def test_previous_error_ids_in_text(self):
        ids = [PREVIOUS_ID_RE.search(line).groups()
               for line in self.text_report().splitlines()
               if PREVIOUS_ID_RE.search(line)]
        self.assertEqual(ids, [(str(n + 1), f'0x{v:x}') for n, v in
                               enumerate(layout.DEFAULT_PREVIOUS_IDS)])

    def test_unknown_guid_is_rejected(self):
        self.serve(guid=bytes(16))
        result = self.run_c1()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(UNKNOWN_GUID_MSG, result.stdout + result.stderr)
        self.assertNotIn('Log Page Version', result.stdout)

    def test_whole_error_id_in_text(self):
        """The Error ID is eight bytes (EREC-4)."""
        self.serve({layout.ERROR_ID: 0x1122334455667788})
        self.assertTextFields(self.text_log(), [layout.ERROR_ID])

    def test_whole_error_id_in_json(self):
        self.serve({layout.ERROR_ID: 0x1122334455667788})
        self.assertJsonFields(self.json_log(), [layout.ERROR_ID])

    def test_previous_error_ids_in_json(self):
        values = scalars(self.json_log())
        for error_id in layout.DEFAULT_PREVIOUS_IDS:
            with self.subTest(error_id=hex(error_id)):
                self.assertTrue({error_id, f'0x{error_id:x}'} & values)

    def test_large_dwords_in_json(self):
        """A four-byte field from 80000000h is not negative."""
        self.serve({name: 0x80000000 + i
                    for i, name in enumerate(DWORD_FIELDS)})
        self.assertJsonFields(self.json_log(), DWORD_FIELDS)

    def test_binary_is_the_page(self):
        result = self.run_c1('-o', 'binary', encoding=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.page)


if __name__ == '__main__':
    main()
