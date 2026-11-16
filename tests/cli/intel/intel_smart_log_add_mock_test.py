#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Hardware-free tests for the intel smart-log-add command.

The Intel additional SMART log (LID 0xCA) is an array of 12-byte items, each
a key, a normalized value and a 6-byte little-endian raw counter. Drives
report counters past 2^31: an SSDPE2KX020T7 reported a CRC error count of
2313581831. Every counter below is past 2^31, so the JSON output must carry
the full 48-bit values that the normal output prints.

Usage: python3 intel_smart_log_add_mock_test.py <nvme-binary> <mock-lib>
"""

import json
import struct
import sys

from tests.cli.nvme_mock import HAVE_JSON, MockTestCase, main

_LID_INTEL_SMART = 0xCA

# struct field -> (item key, JSON name, normalized, raw) for the items whose
# raw value is a 48-bit counter, in log order.
_COUNTERS = {
    'program_fail_cnt': (0xAB, 'program_fail_count', 100, 0x0000_8000_0001),
    'erase_fail_cnt': (0xAC, 'erase_fail_count', 99, 0x0000_9000_0002),
    'e2e_err_cnt': (0xB8, 'end_to_end_error_detection_count', 98,
                    0x0001_0000_0003),
    'crc_err_cnt': (0xC7, 'crc_error_count', 97, 2313581831),
    'timed_workload_host_reads': (0xE3, 'timed_workload_host_reads', 96,
                                  0x0002_0000_0004),
    'timed_workload_timer': (0xE4, 'timed_workload_timer', 95,
                             0x0003_0000_0005),
    'retry_buffer_overflow_cnt': (0xF0, 'retry_buffer_overflow_count', 94,
                                  0x0004_0000_0006),
    'pll_lock_loss_cnt': (0xF3, 'pll_lock_loss_count', 93, 0x0005_0000_0007),
    'nand_bytes_written': (0xF4, 'nand_bytes_written', 92, 0xFFFF_FFFF_FFFF),
    'host_bytes_written': (0xF5, 'host_bytes_written', 91, 0xFEDC_BA98_7654),
    'host_ctx_wear_used': (0xF6, 'host_ctx_wear_used', 90, 0x0006_0000_0008),
    'perf_stat_indicator': (0xF7, 'perf_stat_indicator', 89,
                            0x0007_0000_0009),
    're_alloc_sectr_cnt': (0x05, 're_alloc_sectr_cnt', 88, 0x0008_0000_000A),
    'soft_ecc_err_rate': (0x0D, 'soft_ecc_err_rate', 87, 0x0009_0000_000B),
    'unexp_power_loss': (0xAE, 'unexp_power_loss', 86, 0x000A_0000_000C),
    'media_bytes_read': (0xF8, 'media_bytes_read', 85, 0x000B_0000_000D),
    'avail_fw_downgrades': (0xF9, 'avail_fw_downgrades', 84,
                            0x000C_0000_000E),
}

# The JSON reports timed_workload_media_wear as raw / 1024.
_MEDIA_WEAR_RAW = 3 << 31


def _item(key, norm, raw):
    """Pack one 12-byte item: key, 2 reserved, norm, 1 reserved, raw[6],
    1 reserved."""
    return struct.pack('<B2xBx6sx', key, norm, raw)


def _u48(value):
    return value.to_bytes(6, 'little')


def _intel_smart_log():
    """The log page, with every item in struct nvme_additional_smart_log
    order."""
    c = {name: _item(key, norm, _u48(raw))
         for name, (key, _, norm, raw) in _COUNTERS.items()}
    # wear_level is three __le16; thermal_throttle is a u8 and a host-endian
    # __u32.
    wear = _item(0xAD, 83, struct.pack('<HHH', 11, 22, 33))
    media_wear = _item(0xE2, 82, _u48(_MEDIA_WEAR_RAW))
    throttle = _item(0xEA, 81, struct.pack('=BIx', 44, 0x8000_0055))
    return b''.join([
        c['program_fail_cnt'], c['erase_fail_cnt'], wear, c['e2e_err_cnt'],
        c['crc_err_cnt'], media_wear, c['timed_workload_host_reads'],
        c['timed_workload_timer'], throttle,
        c['retry_buffer_overflow_cnt'], c['pll_lock_loss_cnt'],
        c['nand_bytes_written'], c['host_bytes_written'],
        c['host_ctx_wear_used'], c['perf_stat_indicator'],
        c['re_alloc_sectr_cnt'], c['soft_ecc_err_rate'],
        c['unexp_power_loss'], c['media_bytes_read'],
        c['avail_fw_downgrades'],
    ])


class TestIntelSmartLogAdd(MockTestCase):
    """intel smart-log-add against a mocked LID 0xCA."""

    def setUp(self):
        super().setUp()
        self.server.logs[_LID_INTEL_SMART] = _intel_smart_log()

    def run_smart_log_add(self, *args):
        return self.assertOk(
            self.nvme('intel', 'smart-log-add', self.ctrl, *args))

    def test_normal_output_prints_48_bit_counters(self):
        out = self.run_smart_log_add().stdout
        rows = {int(f[0], 16): f for f in map(str.split, out.splitlines())
                if f and f[0].startswith('0x')}
        for key, _, norm, raw in _COUNTERS.values():
            self.assertEqual(rows[key][-2:], [str(norm), str(raw)],
                             f'item {key:#x}')

    def test_json_output_keeps_48_bit_counters(self):
        if not HAVE_JSON:
            self.skipTest('built without json-c')
        for flag in ('--json', '--output-format=json'):
            with self.subTest(flag=flag):
                out = self.run_smart_log_add(flag).stdout
                stats = json.loads(out)['Device stats']
                for _, name, norm, raw in _COUNTERS.values():
                    self.assertEqual(stats[name],
                                     {'normalized': norm, 'raw': raw},
                                     name)
                self.assertEqual(stats['wear_leveling'],
                                 {'normalized': 83,
                                  'raw': {'min': 11, 'max': 22, 'avg': 33}})
                # Doubles are printed as strings, such as "6291456.000000".
                media_wear = stats['timed_workload_media_wear']
                self.assertEqual(media_wear['normalized'], 82)
                self.assertEqual(float(media_wear['raw']),
                                 _MEDIA_WEAR_RAW / 1024)
                self.assertEqual(
                    stats['thermal_throttle_status'],
                    {'normalized': 81, 'raw': {'pct': 44,
                                               'cnt': 0x8000_0055}})

    def test_reads_lid_0xca(self):
        self.run_smart_log_add()
        self.assertEqual(self.server.lids_read(), {_LID_INTEL_SMART})


if __name__ == '__main__':
    sys.exit(main())
