#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp unsupported-reqs-log" against a mocked controller.

The mock serves synthetic C5h Unsupported Requirements pages built by
tests/e2e/plugins/ocp/ocp_c5_layout.py, transcribed from the OCP
specification (2.7 section 4.8.12) rather than from nvme-cli's struct.

Tests in this module verify:
  * The page is read as LID C5h, 4096 bytes, for all namespaces, with the
    OCP UUID index, or index 0 with --no-uuid; without the OCP UUID
    nothing is read.
  * The Unsupported Count and each Requirement ID decode in text and
    JSON, a 16-character ID included, and a count larger than the list
    lists the 253 entries it has.
  * A page with a different GUID is rejected.

A known defect is covered by an expectedFailure test: -o binary prints
the text report.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_unsupported_reqs_log_mock_test.py <nvme-binary> <mock-lib>
"""
import unittest

from tests.cli.nvme_mock import NSID_ALL, main
from tests.cli.ocp.ocp_mock_test import (UUID_INDEX, UUID_SLOT,
                                         OCPMockTestBase, report_fields)
from tests.e2e.plugins.ocp import ocp_c5_layout as layout

UNKNOWN_GUID_MSG = 'Unknown GUID in C5 Log Page data'
GUID_HEX = layout.GUID_BYTES[::-1].hex()

COUNT = 'Number Unsupported Req IDs'
ENTRY = 'Unsupported Requirement List {}'

# Requirement IDs as the specification spells them, in alphabetical
# order (URLP-3), one of them all 16 bytes and followed by another.
REQUIREMENT_IDS = (b'EREC-14', b'LMDATA-12', b'SEC-12',
                   b'TEL-CFG-SF-1234X', b'UUID-3')


class UnsupportedReqsLogTestBase(OCPMockTestBase):

    def setUp(self):
        super().setUp()
        self.server.uuid_slot = UUID_SLOT
        self.serve(layout.pack(REQUIREMENT_IDS))

    def serve(self, page):
        self.page = page
        self.server.logs = {layout.LID: page}

    def run_c5(self, *args, encoding='utf-8'):
        self.server.commands.clear()
        return self.run_ocp('unsupported-reqs-log', *args,
                            encoding=encoding)

    def text_log(self, *args):
        return report_fields(self.assertOk(self.run_c5(*args)).stdout)

    def json_log(self, *args):
        self.server.commands.clear()
        return self.run_json('unsupported-reqs-log', *args)

    def listed(self, log):
        """The requirement IDs a report lists, in order."""
        ids = []
        while ENTRY.format(len(ids)) in log:
            ids.append(log[ENTRY.format(len(ids))])
        return ids


class TestUnsupportedReqsLog(UnsupportedReqsLogTestBase):

    def test_page_is_read_with_the_ocp_uuid_index(self):
        self.assertOk(self.run_c5())
        reads = self.server.log_reads(layout.LID)
        self.assertEqual(len(reads), 1, reads)
        self.assertEqual(
            (reads[0].lpo, reads[0].data_len, reads[0].nsid,
             reads[0].uuid_index),
            (0, layout.LOG_PAGE_SIZE, NSID_ALL, UUID_INDEX))

    def test_no_uuid_reads_index_0(self):
        self.assertOk(self.run_c5('--no-uuid'))
        self.assertEqual(
            [r.uuid_index for r in self.server.log_reads(layout.LID)], [0])

    def test_without_the_ocp_uuid_nothing_is_read(self):
        self.server.uuid_slot = None
        result = self.run_c5()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.server.log_reads(layout.LID), [])

    def test_list_in_text(self):
        log = self.text_log()
        self.assertEqual(log[COUNT], f'0x{len(REQUIREMENT_IDS):x}')
        self.assertEqual(self.listed(log),
                         [i.decode() for i in REQUIREMENT_IDS])
        self.assertEqual(log['Log Page Version'], '0x1')
        self.assertEqual(log['Log page GUID'], '0x' + GUID_HEX)

    def test_list_in_json(self):
        log = self.json_log()
        self.assertEqual(log[COUNT], len(REQUIREMENT_IDS))
        self.assertEqual(self.listed(log),
                         [i.decode() for i in REQUIREMENT_IDS])
        self.assertEqual(log['Log Page Version'], 1)
        self.assertEqual(log['Log page GUID'].lower().removeprefix('0x'),
                         GUID_HEX)

    def test_empty_list(self):
        self.serve(layout.pack())
        for mode, log in (('text', self.text_log()),
                          ('json', self.json_log())):
            with self.subTest(mode=mode):
                self.assertEqual(self.listed(log), [])

    def test_count_beyond_the_list(self):
        """The list holds 253 entries; a larger count lists them all and
        nothing past them."""
        ids = [f'REQ-{i:03d}'.encode() for i in range(layout.MAX_ENTRIES)]
        self.serve(layout.pack(ids, count=0xFFFF))
        for mode, log in (('text', self.text_log()),
                          ('json', self.json_log())):
            with self.subTest(mode=mode):
                self.assertEqual(self.listed(log),
                                 [i.decode() for i in ids])

    def test_unknown_guid_is_rejected(self):
        self.serve(layout.pack(REQUIREMENT_IDS, guid=bytes(16)))
        result = self.run_c5()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(UNKNOWN_GUID_MSG, result.stdout + result.stderr)
        self.assertNotIn('Log Page Version', result.stdout)

    @unittest.expectedFailure
    def test_binary_is_the_page(self):
        """Defect: the output format is fixed to "normal", so -o binary
        prints the text report."""
        result = self.run_c5('-o', 'binary', encoding=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.page)


if __name__ == '__main__':
    main()
