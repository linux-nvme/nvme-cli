#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp device-capability-log" against a mocked controller.

The mock serves a synthetic C4h Device Capabilities page built by
tests/e2e/plugins/ocp/ocp_c4_layout.py, transcribed from the OCP
specification rather than from nvme-cli's struct.

Tests in this module verify:
  * The page is read as LID C4h, 4096 bytes, with the OCP UUID index.
  * The fixed fields, log page version and GUID decode to the values in
    the page in text and JSON, and -o binary writes the page unchanged.
  * FIPS 140 Validation and its status names (version 2 up), and its
    absence below version 2.
  * A page with a different GUID is rejected.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_device_capability_log_mock_test.py <nvme-binary> <mock-lib>
"""
import json

from tests.cli.ocp.ocp_mock_test import OCPMockTestBase, main
from tests.e2e.plugins.ocp import ocp_c4_layout as layout

UNKNOWN_GUID_MSG = 'Unknown GUID in C4 Log Page data'
READ_FAILURE_MSG = 'Failure reading the C4h Log Page'

GUID_TEXT = '0x' + layout.GUID_BYTES[::-1].hex()

# Label in both reports for each of layout.FIXED_FIELDS.
FIXED_LABELS = {
    layout.PCIE_EXP_PORT: 'PCI Express Ports',
    layout.OOB_MANAGEMENT_SUPPORT: 'OOB Management Support',
    layout.WZ_CMD_SUPPORT: 'Write Zeroes Command Support',
    layout.SANITIZE_CMD_SUPPORT: 'Sanitize Command Support',
    layout.DSM_CMD_SUPPORT: 'Dataset Management Command Support',
    layout.WU_CMD_SUPPORT: 'Write Uncorrectable Command Support',
    layout.FUSED_OPERATION_SUPPORT: 'Fused Operation Support',
    layout.MIN_VALID_DSSD_PWR_STATE: 'Minimum Valid DSSD Power State',
}


class DeviceCapabilityLogTestBase(OCPMockTestBase):

    def setUp(self):
        super().setUp()
        self.serve(layout.pack())

    def serve(self, page):
        self.server.logs = {layout.LID: page}

    def run_c4(self, *args, encoding='utf-8'):
        return self.run_ocp('device-capability-log', *args,
                            encoding=encoding)

    def text_log(self, *args):
        return layout.parse_stdout(self.assertOk(self.run_c4(*args)).stdout)

    def json_log(self, *args):
        result = self.assertOk(self.run_c4('-o', 'json', *args))
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f'-o json output is not valid JSON ({exc}): '
                      f'{result.stdout!r}')


class TestDeviceCapabilityLog(DeviceCapabilityLogTestBase):

    def test_page_is_read_with_the_ocp_uuid_index(self):
        self.server.uuid_slot = 1
        self.assertOk(self.run_c4())
        reads = self.server.log_reads(layout.LID)
        self.assertEqual(len(reads), 1, reads)
        self.assertEqual((reads[0]['lpo'], reads[0]['len']),
                         (0, layout.LOG_PAGE_SIZE))
        self.assertEqual(reads[0]['cdw14'] & 0x7F, 2)

    def test_fixed_fields_in_text(self):
        fields = self.text_log()
        for offset, label in FIXED_LABELS.items():
            with self.subTest(field=label):
                self.assertEqual(fields[label],
                                 f'0x{layout.FIXED_FIELDS[offset]:x}')
        self.assertEqual(fields['Log Page Version'], '0x2')
        self.assertEqual(fields['Log page GUID'], GUID_TEXT)

    def test_fixed_fields_in_json(self):
        log = self.json_log()
        for offset, label in FIXED_LABELS.items():
            with self.subTest(field=label):
                self.assertEqual(log[label], layout.FIXED_FIELDS[offset])
        self.assertEqual(log['Log Page Version'], 2)
        self.assertEqual(log['Log page GUID'], GUID_TEXT)

    def test_binary_is_the_page(self):
        page = layout.pack(version=2, fips=0x0004)
        self.serve(page)
        result = self.run_c4('-o', 'binary', encoding=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, page)

    def reports(self, page):
        """The text and JSON reports of @page, values as strings."""
        self.serve(page)
        text = self.text_log()
        log = {k: v if isinstance(v, str) else f'0x{v:x}'
               for k, v in self.json_log().items()}
        return {'text': text, 'json': log}

    def test_fields_are_gated_on_the_log_page_version(self):
        """FIPS 140 Validation is defined from version 2."""
        for version in (0, 1, 2, 3):
            page = layout.pack(version=version, fips=0x0003)
            for mode, fields in self.reports(page).items():
                with self.subTest(version=version, mode=mode):
                    self.assertEqual('FIPS 140 Validation' in fields,
                                     version >= layout.FIPS_140_MIN_VERSION)

    def test_fips_140_validation_status(self):
        """Bits 3:0 select the status; bits 15:4 are reserved."""
        names = {
            0x0: 'Not FIPS 140 validated and not intended to be',
            0x1: 'Intended to be FIPS 140 validated, not yet submitted',
            0x2: 'Submitted for FIPS 140 validation, not yet validated',
            0x3: 'Interim FIPS 140 validation',
            0x4: 'Full FIPS 140 validation',
            0x5: 'Reserved',
            0xF: 'Reserved',
            0xFFF2: 'Submitted for FIPS 140 validation, not yet validated',
        }
        for fips, name in names.items():
            for mode, fields in self.reports(
                    layout.pack(version=2, fips=fips)).items():
                with self.subTest(fips=fips, mode=mode):
                    self.assertEqual(fields['FIPS 140 Validation'],
                                     f'0x{fips:x}')
                    self.assertEqual(fields['FIPS 140 Validation Status'],
                                     name)

    def test_unknown_guid_is_rejected(self):
        """With -o json errors are reported as one JSON object, which
        keeps only the last of them."""
        self.serve(layout.pack(guid=bytes(16)))
        for args, msg in (((), UNKNOWN_GUID_MSG),
                          (('-o', 'json'), READ_FAILURE_MSG)):
            with self.subTest(args=args):
                result = self.run_c4(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(msg, result.stdout + result.stderr)
                self.assertNotIn('Log Page Version', result.stdout)


if __name__ == '__main__':
    main()
