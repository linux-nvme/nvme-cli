#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp tcg-configuration-log" against a mocked
controller.

The mock serves synthetic C7h TCG Configuration pages built by
tests/e2e/plugins/ocp/ocp_c7_layout.py, transcribed from the OCP
specification (2.7 section 4.8.14, and 2.5 and 2.6 for log page
versions 1 and 2) rather than from nvme-cli's struct.

Tests in this module verify:
  * The page is read as LID C7h, 512 bytes, for all namespaces, with the
    OCP UUID index, or index 0 with --no-uuid; without the OCP UUID
    nothing is read.
  * Every field of a version 1 and a version 2 page decodes to the value
    in the page in text and JSON, four-byte counters unsigned, and the
    field version 2 adds is absent from version 1.
  * A page with a different GUID is rejected, and -o binary writes the
    page unchanged.

Known defects are covered by expectedFailure tests asserting the
behavior the specification defines: a version 3 page (OCP 2.7) is
decoded with the version 2 layout.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_tcg_configuration_log_mock_test.py <nvme-binary> <mock-lib>
"""
import unittest

from tests.cli.nvme_mock import NSID_ALL, main
from tests.cli.ocp.ocp_mock_test import (UUID_INDEX, UUID_SLOT,
                                         OCPMockTestBase, report_fields)
from tests.e2e.plugins.ocp import ocp_c7_layout as layout

UNKNOWN_GUID_MSG = 'Unknown GUID in C7 Log Page data'
GUID_HEX = layout.GUID_BYTES[::-1].hex()


class TcgConfigurationLogTestBase(OCPMockTestBase):

    def setUp(self):
        super().setUp()
        self.server.uuid_slot = UUID_SLOT
        self.serve()

    def serve(self, version=2, values=None, guid=layout.GUID_BYTES):
        self.page, self.values = layout.pack(version, values, guid)
        self.server.logs = {layout.LID: self.page}

    def run_c7(self, *args, encoding='utf-8'):
        self.server.commands.clear()
        return self.run_ocp('tcg-configuration-log', *args,
                            encoding=encoding)

    def text_log(self, *args):
        return report_fields(self.assertOk(self.run_c7(*args)).stdout)

    def json_log(self, *args):
        self.server.commands.clear()
        return self.run_json('tcg-configuration-log', *args)

    def assertTextFields(self, fields, names):
        for name in names:
            with self.subTest(mode='text', field=name):
                self.assertEqual(fields.get(name),
                                 f'0x{self.values[name]:x}')

    def assertJsonFields(self, log, names):
        for name in names:
            with self.subTest(mode='json', field=name):
                self.assertEqual(log.get(name), self.values[name])


class TestTcgConfigurationLog(TcgConfigurationLogTestBase):

    def test_page_is_read_with_the_ocp_uuid_index(self):
        self.assertOk(self.run_c7())
        reads = self.server.log_reads(layout.LID)
        self.assertEqual(len(reads), 1, reads)
        self.assertEqual(
            (reads[0].lpo, reads[0].data_len, reads[0].nsid,
             reads[0].uuid_index),
            (0, layout.LOG_PAGE_SIZE, NSID_ALL, UUID_INDEX))

    def test_no_uuid_reads_index_0(self):
        self.assertOk(self.run_c7('--no-uuid'))
        self.assertEqual(
            [r.uuid_index for r in self.server.log_reads(layout.LID)], [0])

    def test_without_the_ocp_uuid_nothing_is_read(self):
        self.server.uuid_slot = None
        result = self.run_c7()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.server.log_reads(layout.LID), [])

    def test_fields_in_text(self):
        for version in (1, 2):
            self.serve(version)
            fields = self.text_log()
            with self.subTest(version=version):
                self.assertTextFields(fields, layout.field_names(version))
                self.assertEqual(fields['Log Page Version'],
                                 f'0x{version:x}')
                self.assertEqual(fields['Log page GUID'], '0x' + GUID_HEX)

    def test_fields_in_json(self):
        for version in (1, 2):
            self.serve(version)
            log = self.json_log()
            with self.subTest(version=version):
                self.assertJsonFields(log, layout.field_names(version))
                self.assertEqual(log['Log Page Version'], version)
                self.assertEqual(log['Log page GUID'].lower()
                                 .removeprefix('0x'), GUID_HEX)

    def test_extended_count_is_absent_from_version_1(self):
        """TCGL-23 is defined from version 2 (OCP 2.6)."""
        self.serve(1)
        self.assertNotIn(layout.NS_OBJECTS_EXT, self.text_log())
        self.assertNotIn(layout.NS_OBJECTS_EXT, self.json_log())

    def test_state_bits(self):
        """TCGL-1 State bits 0..3, printed as the byte."""
        for bits in (layout.STATE_C_PIN_SID_NOT_MSID,
                     layout.STATE_C_PIN_SID_BLOCKED,
                     layout.STATE_LOCKING_ENABLED,
                     layout.STATE_SUM_OWNER_ADMINS):
            with self.subTest(state=bits):
                self.serve(values={layout.STATE: bits})
                self.assertEqual(self.text_log()[layout.STATE],
                                 f'0x{bits:x}')
                self.assertEqual(self.json_log()[layout.STATE], bits)

    def test_unknown_guid_is_rejected(self):
        self.serve(guid=bytes(16))
        result = self.run_c7()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(UNKNOWN_GUID_MSG, result.stdout + result.stderr)
        self.assertNotIn('Log Page Version', result.stdout)

    @unittest.expectedFailure
    def test_version_3_fields_in_text(self):
        """Defect: the struct and the printers know only versions 1 and
        2, so a version 3 page (OCP 2.7) is decoded at the version 2
        offsets."""
        self.serve(3)
        self.assertTextFields(self.text_log(), layout.field_names(3))

    @unittest.expectedFailure
    def test_version_3_fields_in_json(self):
        """Defect: as test_version_3_fields_in_text."""
        self.serve(3)
        self.assertJsonFields(self.json_log(), layout.field_names(3))

    def test_large_counts_in_json(self):
        """A four-byte counter from 80000000h is not negative."""
        self.serve(values={name: 0x80000000 + i
                           for i, name in enumerate(layout.DWORDS)})
        self.assertJsonFields(self.json_log(), layout.DWORDS)

    def test_binary_is_the_page(self):
        result = self.run_c7('-o', 'binary', encoding=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.page)


if __name__ == '__main__':
    main()
