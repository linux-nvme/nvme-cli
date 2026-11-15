#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Hardware-free tests for the DapuStor smart-log-add command.

Tests retrieval of DapuStor vendor-specific additional SMART log (LID 0xCA)
and optional extended additional SMART log (LID 0xCB):
- Normal text output formatting for base and extended logs
- JSON output formatting (-o json, -j)
- Raw binary dump (-b)
- Namespace ID parameter handling (-n)
- Failure reporting when log retrieval fails

Usage: python3 dapustor_smart_log_mock_test.py <nvme-binary> <mock-lib>
"""

import os
import struct
import sys

from tests.cli.nvme_mock import (HAVE_JSON, MOCK_LIB, NVME_BIN,
                                 SC_INVALID_FIELD, MockTestCase, main)

_LID_DAPUSTOR_SMART = 0xCA
_LID_DAPUSTOR_EXT_SMART = 0xCB

_ITEM_SIZE = 12  # struct nvme_additional_smart_log_item is 12 bytes


def _detect_endian():
    """Detect byte order of the target binary or mock library."""
    for path in (NVME_BIN, MOCK_LIB):
        try:
            with open(os.path.realpath(path), 'rb') as f:
                header = f.read(6)
                if header[:4] == b'\x7fELF':
                    return '>' if header[5] == 2 else '<'
        except Exception:
            pass
    return '>' if sys.byteorder == 'big' else '<'


_ENDIAN = _detect_endian()


def _make_item(norm=100, raw_bytes=b'\x00' * 6):
    """Pack an nvme_additional_smart_log_item."""
    buf = bytearray(_ITEM_SIZE)
    buf[3] = norm & 0xFF
    raw = bytes(raw_bytes)[:6]
    buf[5:5 + len(raw)] = raw
    return bytes(buf)


def _u48(val):
    """Pack a 48-bit little-endian integer."""
    return struct.pack('<Q', val & 0xFFFFFFFFFFFF)[:6]


def _wear_level(min_v, max_v, avg_v):
    """Pack wear_level struct (min, max, avg u16le)."""
    return struct.pack('<HHH', min_v, max_v, avg_v)


def _thermal_throttle(pct, count):
    """Pack thermal_throttle struct (pct u8 + count u32 + 1 byte padding)."""
    return struct.pack(f'{_ENDIAN}BIx', pct, count)


def _temperature(max_v, min_v, cur_v):
    """Pack temperature struct (max, min, cur u16le)."""
    return struct.pack('<HHH', max_v, min_v, cur_v)


def _power_consumption(max_v, min_v, avg_v):
    """Pack power_consumption struct (max, min, avg u16le)."""
    return struct.pack('<HHH', max_v, min_v, avg_v)


def make_dapustor_smart_log(
    program_fail_cnt=(100, 5),
    erase_fail_cnt=(99, 2),
    wear_leveling_cnt=(95, (10, 50, 25)),
    e2e_err_cnt=(100, 0),
    crc_err_cnt=(100, 1),
    timed_workload_media_wear=(100, 2048),
    timed_workload_host_reads=(98, 50),
    timed_workload_timer=(100, 120),
    thermal_throttle_status=(100, (15, 3)),
    retry_buffer_overflow_cnt=(100, 0),
    pll_lock_loss_cnt=(100, 0),
    nand_bytes_written=(90, 123456),
    host_bytes_written=(92, 654321),
):
    """Build a 156-byte DapuStor additional SMART log buffer (LID 0xCA)."""
    items = [
        _make_item(program_fail_cnt[0], _u48(program_fail_cnt[1])),
        _make_item(erase_fail_cnt[0], _u48(erase_fail_cnt[1])),
        _make_item(wear_leveling_cnt[0],
                   _wear_level(*wear_leveling_cnt[1])),
        _make_item(e2e_err_cnt[0], _u48(e2e_err_cnt[1])),
        _make_item(crc_err_cnt[0], _u48(crc_err_cnt[1])),
        _make_item(timed_workload_media_wear[0],
                   _u48(timed_workload_media_wear[1])),
        _make_item(timed_workload_host_reads[0],
                   _u48(timed_workload_host_reads[1])),
        _make_item(timed_workload_timer[0], _u48(timed_workload_timer[1])),
        _make_item(thermal_throttle_status[0],
                   _thermal_throttle(*thermal_throttle_status[1])),
        _make_item(retry_buffer_overflow_cnt[0],
                   _u48(retry_buffer_overflow_cnt[1])),
        _make_item(pll_lock_loss_cnt[0], _u48(pll_lock_loss_cnt[1])),
        _make_item(nand_bytes_written[0], _u48(nand_bytes_written[1])),
        _make_item(host_bytes_written[0], _u48(host_bytes_written[1])),
    ]
    return b''.join(items)


def make_dapustor_ext_smart_log(
    sys_area_life_remain=(95, 95),
    nand_bytes_read=(100, 987654),
    temperature=(100, (65, 25, 42)),
    power_consumption=(100, (15, 5, 8)),
    power_on_temperature=(100, (70, 20, 40)),
    power_loss_protection=(100, 0),
    read_fail_count=(100, 4),
    thermal_throttle_time=(100, 0),
    flash_error_media_count=(100, 0),
    lifetime_write_amplification=(100, 1),
    firmware_update_count=(100, 2),
    dram_cecc_count=(100, 0),
    dram_uecc_count=(100, 0),
    xor_pass_count=(100, 100),
    xor_fail_count=(100, 0),
    xor_invoked_count=(100, 100),
    inflight_read_io_cmd=(100, 0),
    temp_since_born=(100, (80, 15, 38)),
    temp_since_bootup=(100, (60, 22, 35)),
    inflight_write_io_cmd=(100, 0),
):
    """Build a 240-byte DapuStor extended SMART log buffer (LID 0xCB)."""
    items = [
        _make_item(sys_area_life_remain[0], _u48(sys_area_life_remain[1])),
        _make_item(nand_bytes_read[0], _u48(nand_bytes_read[1])),
        _make_item(temperature[0], _temperature(*temperature[1])),
        _make_item(power_consumption[0],
                   _power_consumption(*power_consumption[1])),
        _make_item(power_on_temperature[0],
                   _temperature(*power_on_temperature[1])),
        _make_item(power_loss_protection[0],
                   _u48(power_loss_protection[1])),
        _make_item(read_fail_count[0], _u48(read_fail_count[1])),
        _make_item(thermal_throttle_time[0], _u48(thermal_throttle_time[1])),
        _make_item(flash_error_media_count[0],
                   _u48(flash_error_media_count[1])),
        _make_item(lifetime_write_amplification[0],
                   _u48(lifetime_write_amplification[1])),
        _make_item(firmware_update_count[0], _u48(firmware_update_count[1])),
        _make_item(dram_cecc_count[0], _u48(dram_cecc_count[1])),
        _make_item(dram_uecc_count[0], _u48(dram_uecc_count[1])),
        _make_item(xor_pass_count[0], _u48(xor_pass_count[1])),
        _make_item(xor_fail_count[0], _u48(xor_fail_count[1])),
        _make_item(xor_invoked_count[0], _u48(xor_invoked_count[1])),
        _make_item(inflight_read_io_cmd[0], _u48(inflight_read_io_cmd[1])),
        _make_item(temp_since_born[0], _temperature(*temp_since_born[1])),
        _make_item(temp_since_bootup[0], _temperature(*temp_since_bootup[1])),
        _make_item(inflight_write_io_cmd[0], _u48(inflight_write_io_cmd[1])),
    ]
    return b''.join(items)


class TestDapustorSmartLog(MockTestCase):
    """Run dapustor smart-log-add against simulated SMART log pages."""

    def setUp(self):
        super().setUp()
        # By default extended log page (0xCB) is treated as unsupported
        # unless explicitly populated by the test.
        self.server.logs[_LID_DAPUSTOR_EXT_SMART] = SC_INVALID_FIELD

    def run_smart_log(self, *args, **kwargs):
        return self.nvme('dapustor', 'smart-log-add', self.ctrl,
                         *args, **kwargs)

    def test_smart_log_without_ext(self):
        """Base SMART log output when extended log page 0xCB is unavailable."""
        self.server.logs[_LID_DAPUSTOR_SMART] = make_dapustor_smart_log()

        normal = self.assertOk(self.run_smart_log())
        lines = normal.stdout.splitlines()

        self.assertIn('Additional Smart Log for NVME device:', normal.stdout)
        self.assertTrue(any('program_fail_count' in line and '5' in line
                            for line in lines))
        self.assertTrue(any('erase_fail_count' in line and '2' in line
                            for line in lines))
        self.assertTrue(any('wear_leveling' in line and
                            'min: 10, max: 50, avg: 25' in line
                            for line in lines))
        self.assertTrue(any('thermal_throttle_status' in line and
                            '15%, cnt: 3' in line
                            for line in lines))
        self.assertTrue(any('nand_bytes_written' in line and '123456' in line
                            for line in lines))
        self.assertNotIn('system_area_life_remaining', normal.stdout)

        if HAVE_JSON:
            json_res = self.assertOk(self.run_smart_log('-o', 'json'))
            data = self.parse_json_output(json_res.stdout,
                                          'dapustor smart-log-add -o json')
            self.assertIn('Device stats', data)
            stats = data['Device stats']
            self.assertEqual(stats['program_fail_count']['normalized'], 100)
            self.assertEqual(stats['program_fail_count']['raw'], 5)
            self.assertEqual(stats['wear_leveling']['normalized'], 95)
            self.assertEqual(stats['wear_leveling']['raw'],
                             {'min': 10, 'max': 50, 'avg': 25})
            self.assertEqual(stats['thermal_throttle_status']['raw'],
                             {'pct': 15, 'cnt': 3})
            self.assertNotIn('system_area_life_remaining', stats)

    def test_smart_log_with_ext(self):
        """Both base and extended SMART log pages are retrieved and printed."""
        self.server.logs[_LID_DAPUSTOR_SMART] = make_dapustor_smart_log()
        self.server.logs[_LID_DAPUSTOR_EXT_SMART] = (
            make_dapustor_ext_smart_log()
        )

        normal = self.assertOk(self.run_smart_log())
        lines = normal.stdout.splitlines()

        self.assertIn('Additional Smart Log for NVME device:', normal.stdout)
        self.assertTrue(
            any('system_area_life_remaining' in line and '95' in line
                for line in lines)
        )
        self.assertTrue(any('temperature' in line and
                            'min: 25, max: 65, cur: 42' in line
                            for line in lines))
        self.assertTrue(any('temp_since_born' in line and
                            'min: 15, max: 80, cur: 38' in line
                            for line in lines))

        if HAVE_JSON:
            json_res = self.assertOk(self.run_smart_log('-o', 'json'))
            data = self.parse_json_output(json_res.stdout,
                                          'dapustor smart-log-add -o json')
            self.assertIn('Device stats', data)
            stats = data['Device stats']
            self.assertEqual(stats['system_area_life_remaining']['raw'], 95)
            self.assertEqual(stats['temperature']['raw'],
                             {'min': 25, 'max': 65, 'cur': 42})
            self.assertEqual(stats['temp_since_born']['raw'],
                             {'min': 15, 'max': 80, 'cur': 38})

    def test_smart_log_json_flag(self):
        """Verify -j flag triggers JSON output format."""
        if not HAVE_JSON:
            return

        self.server.logs[_LID_DAPUSTOR_SMART] = make_dapustor_smart_log()
        result = self.assertOk(self.run_smart_log('-j'))
        data = self.parse_json_output(result.stdout,
                                      'dapustor smart-log-add -j')
        self.assertIn('Device stats', data)

    def test_smart_log_namespace_argument(self):
        """Verify -n/--namespace-id sets the namespace ID in header."""
        self.server.logs[_LID_DAPUSTOR_SMART] = make_dapustor_smart_log()

        res_ns1 = self.assertOk(self.run_smart_log('-n', '1'))
        self.assertIn('namespace-id:1', res_ns1.stdout)

        res_default = self.assertOk(self.run_smart_log())
        self.assertIn('namespace-id:ffffffff', res_default.stdout)

    def test_smart_log_raw_binary(self):
        """Verify -b dumps raw binary log data."""
        log_ca = make_dapustor_smart_log()
        log_cb = make_dapustor_ext_smart_log()
        self.server.logs[_LID_DAPUSTOR_SMART] = log_ca
        self.server.logs[_LID_DAPUSTOR_EXT_SMART] = log_cb

        res = self.assertOk(self.run_smart_log('-b', encoding=None))
        self.assertEqual(res.stdout, log_ca + log_cb)

        self.server.logs[_LID_DAPUSTOR_EXT_SMART] = SC_INVALID_FIELD
        res_ca = self.assertOk(self.run_smart_log('-b', encoding=None))
        self.assertEqual(res_ca.stdout, log_ca)

    def test_smart_log_failure_is_reported(self):
        """A controller status error on base log page must exit non-zero."""
        self.server.logs[_LID_DAPUSTOR_SMART] = SC_INVALID_FIELD

        result = self.run_smart_log()
        self.assertNotEqual(result.returncode, 0)
        combined = result.stdout + result.stderr
        self.assertIn('Invalid Field in Command', combined)


if __name__ == '__main__':
    main()
