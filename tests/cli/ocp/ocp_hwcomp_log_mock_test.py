#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp hardware-component-log" against a mocked
controller.

The mock serves synthetic C6h Hardware Component pages built by
tests/e2e/plugins/ocp/ocp_c6_layout.py, transcribed from the OCP
specification (2.7 section 4.8.13) rather than from nvme-cli's struct.

Tests in this module verify:
  * The header is read first, then the descriptors from log page offset
    64, as long as the Hardware Component Log Size says, both with the
    OCP UUID index; the size counts dwords in log page version 1 and
    bytes from version 2.
  * Every descriptor field decodes to the value in the page in text and
    JSON, a field of size 0 is absent, and each Component Identifier is
    named as the CITYPE table describes it.
  * --comp-id selects the descriptors of one identifier and --list prints
    only their names.
  * A descriptor that does not fit into the log is not decoded, a log
    size that leaves no room for descriptors or is too large is refused,
    and -o binary writes the page unchanged.

Known defects are covered by expectedFailure tests asserting the
behavior the specification defines: a page with a different GUID is
decoded anyway, the Hardware Component Log Size shown is not the
HWCLOG-4 value, --comp-id vendor selects 8000h only rather than the
vendor unique range, and 0007h is not named a resistor component.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_hwcomp_log_mock_test.py <nvme-binary> <mock-lib>
"""
import unittest

from tests.cli.nvme_mock import main
from tests.cli.ocp.ocp_mock_test import (UUID_INDEX, UUID_SLOT,
                                         OCPMockTestBase)
from tests.e2e.plugins.ocp import ocp_c6_layout as layout
from tests.e2e.plugins.ocp.ocp_c6_layout import Descriptor

NO_INFORMATION = 'No information provided'

# One descriptor per kind of content, each value distinct so a field read
# from the wrong offset shows.
ASIC = Descriptor(layout.ID_ASIC, mfg=0x1112131415161718,
                  rev=0x2122232425262728, mfg_code=0x3132333435363738,
                  date_lot=bytes(range(0x41, 0x49)),
                  add_info=bytes(range(0x51, 0x55)))
NAND = Descriptor(layout.ID_NAND, mfg=0x0102030405060708,
                  rev=0x090A0B0C0D0E0F10, mfg_code=0x1A1B1C1D1E1F2021,
                  date_lot=bytes(range(0x61, 0x65)))
SERIAL = Descriptor(layout.ID_SN, add_info=b'SN0123456789ABCD')
DESCRIPTORS = (ASIC, NAND, SERIAL)


def le_hex(data, upper):
    """A field as both printers show it: a little-endian number."""
    text = data[::-1].hex()
    return '0x' + (text.upper() if upper else text)


def expected_fields(d, text):
    """The decoded fields of descriptor @d, as the text (@text) or JSON
    report shows them. Text leaves out a field of size 0."""
    fields = {
        'Identifier': f'0x{d.ident:08x}',
        'Manufacture': f'0x{d.mfg:016x}',
        'Revision': f'0x{d.rev:016x}',
        'Manufacture Code': f'0x{d.mfg_code:016x}',
    }
    for label, value in (('Date/Lot Code', d.date_lot),
                         ('Additional Information', d.add_info)):
        if value:
            fields[label] = le_hex(value, upper=text)
        elif not text:
            fields[label] = NO_INFORMATION
    return fields


def parse_text(stdout):
    """Split the text report into its header fields and a list of
    components, each a dict with the component's name under 'name'."""
    header, components = {}, []
    for line in stdout.splitlines():
        key, sep, value = line.strip().partition(': ')
        if not sep:
            continue
        if line.startswith('  Component '):
            components.append({'name': value})
        elif line.startswith('    ') and components:
            components[-1][key] = value
        elif not line.startswith(' '):
            header[key] = value
    return header, components


def json_components(log):
    """The components of a JSON report in order: for --list the names,
    otherwise the field objects."""
    descs = log['Component Descriptions']
    if not descs:
        return []
    entries = descs[0]
    values = [entries[f'Component {n}'] for n in range(1, len(entries) + 1)]
    return [v if isinstance(v, str) else v[0] for v in values]


class HwcompLogTestBase(OCPMockTestBase):

    def setUp(self):
        super().setUp()
        self.server.uuid_slot = UUID_SLOT
        self.serve(layout.pack(DESCRIPTORS))

    def serve(self, page):
        self.page = page
        self.server.logs = {layout.LID: page}

    def run_c6(self, *args, encoding='utf-8'):
        self.server.commands.clear()
        return self.run_ocp('hardware-component-log', *args,
                            encoding=encoding)

    def text_log(self, *args):
        return parse_text(self.assertOk(self.run_c6(*args)).stdout)

    def json_log(self, *args):
        self.server.commands.clear()
        return self.run_json('hardware-component-log', *args)

    def names(self, *args):
        """The component names of both reports, by mode."""
        _, components = self.text_log(*args)
        return {'text': [c['name'] for c in components],
                'json': [c if isinstance(c, str) else c['Description']
                         for c in json_components(self.json_log(*args))]}

    def assertNames(self, expected, *args):
        for mode, names in self.names(*args).items():
            with self.subTest(mode=mode, args=args):
                self.assertEqual(names, expected)


class TestHwcompLogReads(HwcompLogTestBase):

    def test_header_then_descriptors_are_read(self):
        self.assertOk(self.run_c6())
        reads = self.server.log_reads(layout.LID)
        self.assertEqual(
            [(r.lpo, r.data_len) for r in reads],
            [(0, layout.HEADER_SIZE),
             (layout.HEADER_SIZE, len(self.page) - layout.HEADER_SIZE)])
        self.assertEqual(reads[0].uuid_index, UUID_INDEX)

    def test_descriptors_are_read_with_the_ocp_uuid_index(self):
        """The header and the descriptors come from the same log
        page."""
        self.assertOk(self.run_c6())
        reads = self.server.log_reads(layout.LID)
        self.assertEqual([r.uuid_index for r in reads],
                         [UUID_INDEX, UUID_INDEX])

    def test_without_the_ocp_uuid_index_0_is_used(self):
        self.server.uuid_slot = None
        self.assertOk(self.run_c6())
        self.assertEqual(
            [r.uuid_index for r in self.server.log_reads(layout.LID)],
            [0, 0])

    def test_version_1_size_counts_dwords(self):
        """HWCLOG-4 is in dwords in log page version 1 (OCP 2.5)."""
        self.serve(layout.pack(DESCRIPTORS, version=1))
        _, components = self.text_log()
        self.assertEqual([c['name'] for c in components],
                         [layout.id_name(d.ident) for d in DESCRIPTORS])
        reads = self.server.log_reads(layout.LID)
        self.assertEqual(reads[-1].data_len,
                         len(self.page) - layout.HEADER_SIZE)

    def test_size_without_room_for_descriptors_is_refused(self):
        for size in (0, layout.HEADER_SIZE):
            with self.subTest(size=size):
                self.serve(layout.pack(DESCRIPTORS, size=size))
                result = self.run_c6()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(self.server.log_reads(layout.LID)), 1)
                self.assertNotIn('Component Descriptions', result.stdout)

    def test_size_too_large_is_refused(self):
        """A size the 32-bit read length cannot hold."""
        self.serve(layout.pack(DESCRIPTORS, size=1 << 64))
        result = self.run_c6()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.server.log_reads(layout.LID)), 1)

    def test_binary_is_the_page(self):
        result = self.run_c6('-o', 'binary', encoding=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.page)

    @unittest.expectedFailure
    def test_unknown_guid_is_rejected(self):
        """Defect: the Log Page GUID (HWCLOG-3) is never checked, so a
        page that is not the OCP Hardware Component log is decoded."""
        self.serve(layout.pack(DESCRIPTORS, guid=bytes(16)))
        result = self.run_c6()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Component Descriptions', result.stdout)


class TestHwcompLogFields(HwcompLogTestBase):

    def test_header_in_text(self):
        header, _ = self.text_log()
        self.assertEqual(header['Log Page Version'], '0x2')
        self.assertEqual(header['Log page GUID'],
                         le_hex(layout.GUID_BYTES, upper=True))

    def test_header_in_json(self):
        log = self.json_log()
        self.assertEqual(log['Log Identifier'], '0xc6')
        self.assertEqual(log['Log Page Version'], '0x2')
        self.assertEqual(log['Log page GUID'],
                         le_hex(layout.GUID_BYTES, upper=False))

    @unittest.expectedFailure
    def test_log_size_is_the_hwclog4_value(self):
        """Defect: "Hardware Component Log Size" shows the length of the
        descriptors (the size less the 64-byte header), not HWCLOG-4."""
        header, _ = self.text_log()
        log = self.json_log()
        for mode, value in (('text', header['Hardware Component Log Size']),
                            ('json', log['Hardware Component Log Size'])):
            with self.subTest(mode=mode):
                self.assertEqual(value, f'0x{len(self.page):x}')

    def test_descriptor_fields_in_text(self):
        _, components = self.text_log()
        self.assertEqual(len(components), len(DESCRIPTORS))
        for d, c in zip(DESCRIPTORS, components):
            with self.subTest(ident=d.ident):
                self.assertEqual(c['name'], layout.id_name(d.ident))
                fields = {k: c[k] for k in expected_fields(d, True)
                          if k in c}
                self.assertEqual(fields, expected_fields(d, True))
                for label in ('Date/Lot Code', 'Additional Information'):
                    if label not in expected_fields(d, True):
                        self.assertNotIn(label, c)

    def test_descriptor_fields_in_json(self):
        components = json_components(self.json_log())
        self.assertEqual(len(components), len(DESCRIPTORS))
        for d, c in zip(DESCRIPTORS, components):
            with self.subTest(ident=d.ident):
                self.assertEqual(c['Description'], layout.id_name(d.ident))
                self.assertEqual({k: c[k] for k in expected_fields(d, False)},
                                 expected_fields(d, False))

    def test_component_names(self):
        """Every row of the Component Identifier Table but 0007h, which
        has a test of its own."""
        idents = [layout.ID_RESERVED, *sorted(layout.ID_NAMES), 0x000D,
                  0x7FFF, layout.ID_VENDOR_FIRST, 0x8001,
                  layout.ID_VENDOR_LAST]
        idents.remove(layout.ID_RESISTOR)
        self.serve(layout.pack(Descriptor(i) for i in idents))
        self.assertNames([layout.id_name(i) for i in idents])

    @unittest.expectedFailure
    def test_resistor_name(self):
        """Defect: 0007h is named a "registor component"."""
        self.serve(layout.pack([Descriptor(layout.ID_RESISTOR)]))
        self.assertNames([layout.ID_NAMES[layout.ID_RESISTOR]])

    def test_list_prints_names_only(self):
        _, components = self.text_log('--list')
        self.assertEqual(components,
                         [{'name': layout.id_name(d.ident)}
                          for d in DESCRIPTORS])
        self.assertEqual(json_components(self.json_log('--list')),
                         [layout.id_name(d.ident) for d in DESCRIPTORS])

    def test_comp_id_selects_one_identifier(self):
        nand2 = NAND._replace(mfg=0x5A5A5A5A5A5A5A5A)
        self.serve(layout.pack([ASIC, NAND, SERIAL, nand2]))
        for comp_id in ('nand', str(layout.ID_NAND)):
            _, components = self.text_log('--comp-id', comp_id)
            with self.subTest(comp_id=comp_id):
                self.assertEqual(
                    [c['Manufacture'] for c in components],
                    [f'0x{d.mfg:016x}' for d in (NAND, nand2)])
        self.assertNames([layout.id_name(layout.ID_NAND)] * 2,
                         '--comp-id', 'nand', '--list')

    @unittest.expectedFailure
    def test_comp_id_vendor_selects_the_vendor_range(self):
        """Defect: --comp-id vendor matches 8000h only; CITYPE-14 makes
        all of 8000h-FFFFh vendor unique."""
        idents = (layout.ID_VENDOR_FIRST, 0x8001, layout.ID_VENDOR_LAST)
        self.serve(layout.pack([ASIC, *(Descriptor(i) for i in idents)]))
        self.assertNames([layout.VENDOR_NAME] * len(idents),
                         '--comp-id', 'vendor', '--list')


class TestHwcompLogBounds(HwcompLogTestBase):
    """Descriptors that do not fit into the log end the list."""

    def test_descriptor_past_the_log_is_not_decoded(self):
        for name, last in (
                ('date/lot size', ASIC._replace(date_lot_dw=1 << 40)),
                ('additional information size',
                 ASIC._replace(add_info_dw=1 << 40)),
                ('one dword past the log',
                 ASIC._replace(date_lot_dw=3, add_info_dw=1))):
            with self.subTest(name):
                self.serve(layout.pack([NAND, last]))
                self.assertNames([layout.id_name(layout.ID_NAND)])

    def test_partial_descriptor_is_not_decoded(self):
        tail = layout.pack_descriptor(ASIC)[:layout.DESC_SIZE - 4]
        self.serve(layout.pack([NAND], tail=tail))
        self.assertNames([layout.id_name(layout.ID_NAND)])


if __name__ == '__main__':
    main()
