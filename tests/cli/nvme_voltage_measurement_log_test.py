#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
"""Tests for the `nvme log voltage-measurement` command (Log Identifier
27h) against a mocked controller.

The log page has a 64 byte header which says how long the whole page is,
followed by interval voltage measurement descriptors and vendor specific
data. The tests check that the command decodes the header, reads the page
at the length the header gives (but never more than the log reads allow),
and prints the descriptors and the vendor specific data only as far as the
page holds them.

Usage: python3 nvme_voltage_measurement_log_test.py <nvme-binary> <mock-lib>
"""
import json
import struct
import unittest

from tests.cli.nvme_mock import HAVE_JSON, MockTestCase, main

needs_json = unittest.skipUnless(HAVE_JSON, 'built without json-c')

_LID_VOLTAGE_MEASUREMENT = 0x27

_HEADER_LEN = 64          # struct nvme_voltage_measurement_log
_IVMD_LEN = 2             # an interval voltage measurement descriptor
_NCVM = 1 << 14           # non contiguous voltage measurement
_PERCENT_ERROR_NOT_REPORTED = 0xff
_MAX_LOG_LEN = 4 * 1024 * 1024  # what the command reads of a log at most


def _voltage_meas_log(nvmde, descs=(), vendor=b'', vmlsz=None, vlvss=None,
                      iovpe=_PERCENT_ERROR_NOT_REPORTED,
                      iuvpe=_PERCENT_ERROR_NOT_REPORTED):
    """A voltage measurement log page which says it has @nvmde interval
    voltage measurement descriptors, and holds @descs (raw descriptors)
    and @vendor data. @vmlsz and @vlvss default to the page length and the
    length of @vendor. The sensor is scaled by 0.001 V, supplies 12 V, and
    has a maximum overvoltage of 12.5 V. No undervoltage was measured."""
    body = b''.join(struct.pack('<H', d) for d in descs) + vendor
    if vmlsz is None:
        vmlsz = _HEADER_LEN + len(body)
    if vlvss is None:
        vlvss = len(vendor)
    vsi = (1 << 14) | 240
    ovol = (1 << 14) | 12500
    uvol = 0x3fff
    hdr = struct.pack('<BBHIHHH8sHH6xHHH8sBHHH8sB2x', 1, 0x13, vsi, vmlsz,
                      len(descs), nvmde, 0, bytes(8), 0, vlvss,
                      ovol, 3, 12400, bytes(8), iovpe,
                      uvol, 0, 0, bytes(8), iuvpe)
    assert len(hdr) == _HEADER_LEN
    return hdr + body


def _kv(text):
    """The "key : value" lines of a text output as (key, value) pairs."""
    pairs = []
    for line in text.splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            pairs.append((k.strip(), v.strip()))
    return pairs


class VoltageMeasurementLogTest(MockTestCase):
    """Serves the voltage measurement log page of a test."""

    def _run(self, *args):
        return self.assertOk(self.nvme('log', 'voltage-measurement', *args,
                                       self.ctrl)).stdout

    def _run_json(self, *args):
        return json.loads(self._run(*args, '-o', 'json'))

    def _serve(self, page):
        self.server.logs[_LID_VOLTAGE_MEASUREMENT] = page

    def test_values_are_decoded(self):
        """The raw fields are printed, and their decoded parts only with
        --verbose."""
        self._serve(_voltage_meas_log(2, [12000, 12001]))
        out = self._run()
        self.assertIn(('Overvoltage', '0x70d4'), _kv(out))
        self.assertNotIn('Maximum Overvoltage Value', out)
        out = self._run('--verbose')
        self.assertIn('Maximum Overvoltage Value: 12.500 V', out)
        self.assertIn('Overvoltage Valid', out)
        self.assertIn('Voltage Sensor Supply Value: 12.00 V', out)

    @needs_json
    def test_values_are_decoded_json(self):
        self._serve(_voltage_meas_log(2, [12000, 12001]))
        out = self._run_json()
        self.assertEqual(out['movv'], 12500)
        self.assertEqual(out['ovv'], 1)
        self.assertEqual(out['vmc'], 1)
        self.assertEqual(out['vssv'], 240)
        self.assertEqual(out['vmlsz'], _HEADER_LEN + 2 * _IVMD_LEN)

    def test_minimum_undervoltage_not_measured(self):
        """The all ones value means no undervoltage was measured."""
        self._serve(_voltage_meas_log(0))
        self.assertIn('Minimum Undervoltage Value: not measured',
                      self._run('--verbose'))

    @needs_json
    def test_minimum_undervoltage_not_measured_json(self):
        self._serve(_voltage_meas_log(0))
        self.assertEqual(self._run_json()['muvv'], 0x3fff)

    def test_percent_error_not_reported(self):
        self._serve(_voltage_meas_log(0))
        kv = _kv(self._run())
        self.assertIn(('Interval Overvoltage Percent Error',
                       'not reported'), kv)
        self.assertIn(('Interval Undervoltage Percent Error',
                       'not reported'), kv)

    @needs_json
    def test_percent_error_not_reported_json(self):
        self._serve(_voltage_meas_log(0))
        self.assertEqual(self._run_json()['iovpe'], 0xff)

    def test_percent_error_reported(self):
        self._serve(_voltage_meas_log(0, iovpe=5, iuvpe=0))
        kv = _kv(self._run())
        self.assertIn(('Interval Overvoltage Percent Error', '5%'), kv)
        self.assertIn(('Interval Undervoltage Percent Error', '0%'), kv)

    def test_descriptors(self):
        self._serve(_voltage_meas_log(2, [12000, 12001 | _NCVM]))
        kv = _kv(self._run())
        self.assertIn(('Voltage Value', '12.001 V'), kv)
        self.assertEqual([v for k, v in kv
                          if k == 'Non Contiguous Voltage Measurement'],
                         ['0', '1'])

    @needs_json
    def test_descriptors_json(self):
        self._serve(_voltage_meas_log(2, [12000, 12001 | _NCVM]))
        out = self._run_json()
        self.assertEqual(out['ivmd'], [{'volv': 12000, 'ncvm': 0},
                                       {'volv': 12001, 'ncvm': 1}])

    def test_verbose_describes_the_bit_fields(self):
        """The bit tables are only printed with --verbose."""
        self._serve(_voltage_meas_log(1, [12000]))
        self.assertNotIn('[3:2]', self._run())
        out = self._run('--verbose')
        self.assertIn('[3:2]', out)
        self.assertIn('[15:14]', out)

    def test_more_descriptors_than_the_page(self):
        """More interval voltage measurement descriptors than the page
        holds: only those in it are printed."""
        self._serve(_voltage_meas_log(100, [12000]))
        out = self._run()
        self.assertEqual(out.count('Voltage Measurement Descriptor ['), 1)

    @needs_json
    def test_more_descriptors_than_the_page_json(self):
        self._serve(_voltage_meas_log(100, [12000]))
        out = self._run_json()
        self.assertEqual(out['nvmde'], 100)
        self.assertEqual(len(out['ivmd']), 1)

    def test_vendor_specific_data(self):
        vendor = b'VENDOR-SPECIFIC!'
        self._serve(_voltage_meas_log(2, [12000, 12001], vendor=vendor))
        out = self._run()
        self.assertIn(('Voltage Log Vendor Specific Size (bytes)',
                       str(len(vendor))), _kv(out))
        self.assertIn('Voltage Log Vendor Specific:', out)
        self.assertIn('VENDOR-SPECIFIC!', out)

    def test_vendor_specific_data_past_the_page(self):
        """Vendor specific data the page doesn't hold is not printed."""
        self._serve(_voltage_meas_log(1, [12000], vlvss=64))
        out = self._run()
        self.assertIn(('Voltage Log Vendor Specific Size (bytes)', '64'),
                      _kv(out))
        self.assertNotIn('Voltage Log Vendor Specific:', out)

    def test_header_is_read_then_the_page(self):
        """The first read is the header; the page is then read as long as
        its header says."""
        descs = list(range(12000, 12000 + 4000))
        self._serve(_voltage_meas_log(len(descs), descs))
        out = self._run()
        self.assertEqual(out.count('Voltage Measurement Descriptor ['),
                         len(descs))
        reads = self.server.log_reads(_LID_VOLTAGE_MEASUREMENT)
        self.assertGreater(len(reads), 2, 'page read in one go')
        self.assertEqual((reads[0].lpo, reads[0].data_len), (0, _HEADER_LEN))
        self.assertEqual(reads[1].lpo, 0)
        self.assertEqual(sum(r.data_len for r in reads[1:]),
                         _HEADER_LEN + len(descs) * _IVMD_LEN)

    def test_header_only_page_is_read_once(self):
        self._serve(_voltage_meas_log(0))
        self._run()
        reads = self.server.log_reads(_LID_VOLTAGE_MEASUREMENT)
        self.assertEqual([r.data_len for r in reads], [_HEADER_LEN])

    def test_page_length_shorter_than_the_header(self):
        """A length shorter than the header still reads the header."""
        self._serve(_voltage_meas_log(0, vmlsz=4))
        out = self._run()
        self.assertIn(('Log Size (bytes)', '4'), _kv(out))
        self.assertNotIn('Voltage Measurement Descriptor [', out)
        reads = self.server.log_reads(_LID_VOLTAGE_MEASUREMENT)
        self.assertEqual([r.data_len for r in reads], [_HEADER_LEN])

    def test_page_length_is_limited(self):
        """A length no log read is as long as is not read in full."""
        self._serve(_voltage_meas_log(0, vmlsz=0xffffffff))
        self._run()
        reads = self.server.log_reads(_LID_VOLTAGE_MEASUREMENT)
        self.assertEqual(sum(r.data_len for r in reads[1:]), _MAX_LOG_LEN)

    def test_raw_binary(self):
        page = _voltage_meas_log(2, [12000, 12001], vendor=b'VS')
        self._serve(page)
        result = self.assertOk(self.nvme(
            'log', 'voltage-measurement', self.ctrl, '--raw-binary',
            encoding=None))
        self.assertEqual(result.stdout, page)


if __name__ == '__main__':
    main()
