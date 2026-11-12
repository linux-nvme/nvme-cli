#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Hardware-free tests for the Solidigm smart-log-add command.

The Solidigm 'solidigm smart-log-add' command retrieves a vendor-specific
SMART log at log page ID 0xCA.  The 512-byte payload is an array of up to
64 items, each 8 bytes:

  Offset  Field       Size
  0       id          u8   (attribute ID, 0 == unused slot)
  1..2    _kp         2 bytes (key padding)
  3       normalized  u8   (0..100 normalized value)
  4..9    raw         6 bytes (little-endian 48-bit raw value)
  10 (alias for raw[0]) pct (thermal throttle percentage, for ID 0xEA)
  11..14 (alias for raw[1..4]) count (thermal throttle count, for ID 0xEA)

Selected well-known attribute IDs (from solidigm-smart.c):
  0xAB  program_fail_count
  0xAC  erase_fail_count
  0xAD  wear_leveling_count  (raw is min:le16, max:le16, avg:le16)
  0xAE  unexpected_power_loss
  0xC7  crc_error_count      (or bad_tlp_error_count when E7/E8 present)
  0xE2  media_wear_percentage
  0xE3  timed_work_load_host_reads
  0xE4  timed_work_load_timer
  0xEA  thermal_throttle_status  (pct + count)
  0xF4  nand_bytes_written
  0xF5  host_bytes_written

Usage: python3 solidigm_smart_log_mock_test.py <nvme-binary> <mock-lib>
"""

import struct

from tests.cli.nvme_mock import (OPC_GET_LOG_PAGE, SC_INVALID_FIELD,
                                 MockTestCase, main)

# Log page identifier for the Solidigm vendor-specific SMART log.
_LID_VU_SMART = 0xCA

_ITEM_SIZE = 12         # struct nvme_additional_smart_log_item is 12 bytes
_MAX_ITEMS = 42         # 512 / 12
_PAGE_SIZE = 512        # bytes


def _make_smart_page(*items):
    """Build a 512-byte smart log page from a list of (id, normalized, raw)
    tuples.  raw may be an int (48-bit little-endian) or bytes (up to 6)."""
    buf = bytearray(_PAGE_SIZE)
    for idx, (attr_id, normalized, raw) in enumerate(items):
        off = idx * _ITEM_SIZE
        buf[off] = attr_id & 0xFF
        buf[off + 1] = 0        # _kp[0]
        buf[off + 2] = 0        # _kp[1]
        buf[off + 3] = normalized & 0xFF
        buf[off + 4] = 0        # _np
        if isinstance(raw, int):
            raw_bytes = struct.pack('<Q', raw & 0xFFFFFFFFFFFF)[:6]
        else:
            raw_bytes = bytes(raw)[:6]
        buf[off + 5:off + 5 + len(raw_bytes)] = raw_bytes
        buf[off + 11] = 0       # _rp
    return bytes(buf)


def _make_wear_level_raw(min_wl, max_wl, avg_wl):
    """Pack wear-level min/max/avg as three little-endian u16 values."""
    return struct.pack('<HHH', min_wl, max_wl, avg_wl)


def _make_thermal_throttle_raw(pct, count):
    """Pack thermal throttle pct (u8) + count (u32le)."""
    return struct.pack('<BI', pct, count)


class TestSolidigmSmartLog(MockTestCase):
    """Run solidigm smart-log-add against a simulated controller."""

    def run_smart_log(self, *args):
        return self.nvme('solidigm', 'smart-log-add', self.ctrl, *args)

    def assertOkSmartLog(self, *args):
        return self.assertOk(self.run_smart_log(*args))

    def test_empty_log_succeeds(self):
        """An all-zero payload (no attributes) must succeed without crashing."""
        self.server.logs[_LID_VU_SMART] = bytes(_PAGE_SIZE)
        result = self.assertOkSmartLog()
        # Header line should still be present
        self.assertIn('Additional Smart Log', result.stdout)

    def test_log_page_failure_is_reported(self):
        """A Get Log Page error must exit non-zero."""
        self.server.logs[_LID_VU_SMART] = SC_INVALID_FIELD
        result = self.run_smart_log()
        self.assertNotEqual(result.returncode, 0)

    def test_header_includes_device_name(self):
        """The output header must reference the device path."""
        self.server.logs[_LID_VU_SMART] = bytes(_PAGE_SIZE)
        result = self.assertOkSmartLog()
        # ctrl is something like /dev/nvme0 - just check some prefix
        self.assertIn('nvme0', result.stdout)

    def test_program_fail_count_reported(self):
        """Attribute 0xAB (program_fail_count) name and raw value appear."""
        raw = 7
        page = _make_smart_page((0xAB, 95, raw))
        self.server.logs[_LID_VU_SMART] = page
        result = self.assertOkSmartLog()
        self.assertIn('program_fail_count', result.stdout)
        self.assertIn('7', result.stdout)

    def test_erase_fail_count_reported(self):
        """Attribute 0xAC (erase_fail_count) is printed."""
        page = _make_smart_page((0xAC, 100, 0))
        self.server.logs[_LID_VU_SMART] = page
        result = self.assertOkSmartLog()
        self.assertIn('erase_fail_count', result.stdout)

    def test_unexpected_power_loss_reported(self):
        """Attribute 0xAE (unexpected_power_loss) is printed."""
        page = _make_smart_page((0xAE, 100, 3))
        self.server.logs[_LID_VU_SMART] = page
        result = self.assertOkSmartLog()
        self.assertIn('unexpected_power_loss', result.stdout)
        self.assertIn('3', result.stdout)

    def test_nand_bytes_written_reported(self):
        """Attribute 0xF4 (nand_bytes_written) name appears."""
        page = _make_smart_page((0xF4, 100, 0x123456))
        self.server.logs[_LID_VU_SMART] = page
        result = self.assertOkSmartLog()
        self.assertIn('nand_bytes_written', result.stdout)

    def test_host_bytes_written_reported(self):
        """Attribute 0xF5 (host_bytes_written) name appears."""
        page = _make_smart_page((0xF5, 100, 0xABCDEF))
        self.server.logs[_LID_VU_SMART] = page
        result = self.assertOkSmartLog()
        self.assertIn('host_bytes_written', result.stdout)

    def test_media_wear_percentage_reported(self):
        """Attribute 0xE2 (media_wear_percentage) name appears."""
        page = _make_smart_page((0xE2, 95, 1000))
        self.server.logs[_LID_VU_SMART] = page
        result = self.assertOkSmartLog()
        self.assertIn('media_wear_percentage', result.stdout)

    def test_zero_id_slot_is_skipped(self):
        """Items with id==0 must not produce output lines."""
        page = _make_smart_page((0, 0, 0))
        self.server.logs[_LID_VU_SMART] = page
        result = self.assertOkSmartLog()
        # Only the header line should be present, nothing else
        self.assertIn('Additional Smart Log', result.stdout)
        self.assertNotIn('unknown', result.stdout)

    def test_unknown_id_reported_as_unknown(self):
        """An unrecognised attribute ID falls through to 'unknown'."""
        page = _make_smart_page((0x42, 50, 99))
        self.server.logs[_LID_VU_SMART] = page
        result = self.assertOkSmartLog()
        self.assertIn('unknown', result.stdout)

    def test_wear_leveling_min_max_avg_printed(self):
        """Attribute 0xAD prints min, max, avg sub-fields."""
        raw = _make_wear_level_raw(min_wl=10, max_wl=90, avg_wl=50)
        page = _make_smart_page((0xAD, 85, raw))
        self.server.logs[_LID_VU_SMART] = page
        result = self.assertOkSmartLog()
        self.assertIn('wear_leveling_count', result.stdout)
        self.assertIn('min: 10', result.stdout)
        self.assertIn('max: 90', result.stdout)
        self.assertIn('avg: 50', result.stdout)

    def test_thermal_throttle_pct_and_count_printed(self):
        """Attribute 0xEA prints throttle percentage and event count."""
        raw = _make_thermal_throttle_raw(pct=15, count=42)
        page = _make_smart_page((0xEA, 75, raw))
        self.server.logs[_LID_VU_SMART] = page
        result = self.assertOkSmartLog()
        self.assertIn('thermal_throttle_status', result.stdout)
        self.assertIn('15%', result.stdout)
        self.assertIn('cnt: 42', result.stdout)

    def test_thermal_throttle_zero_count(self):
        """Zero pct and zero count still prints both values."""
        raw = _make_thermal_throttle_raw(pct=0, count=0)
        page = _make_smart_page((0xEA, 100, raw))
        self.server.logs[_LID_VU_SMART] = page
        result = self.assertOkSmartLog()
        self.assertIn('0%', result.stdout)
        self.assertIn('cnt: 0', result.stdout)

    def test_c7_without_e7_e8_is_crc_error_count(self):
        """Without E7 or E8, attribute 0xC7 is labelled crc_error_count."""
        page = _make_smart_page((0xC7, 100, 5))
        self.server.logs[_LID_VU_SMART] = page
        result = self.assertOkSmartLog()
        self.assertIn('crc_error_count', result.stdout)
        self.assertNotIn('bad_tlp_error_count', result.stdout)

    def test_c7_with_e7_is_bad_tlp_error_count(self):
        """When E7 is present, 0xC7 is labelled bad_tlp_error_count."""
        page = _make_smart_page((0xC7, 100, 5), (0xE7, 100, 1))
        self.server.logs[_LID_VU_SMART] = page
        result = self.assertOkSmartLog()
        self.assertIn('bad_tlp_error_count', result.stdout)
        self.assertNotIn('crc_error_count', result.stdout)

    def test_c7_with_e8_is_bad_tlp_error_count(self):
        """When E8 is present, 0xC7 is labelled bad_tlp_error_count."""
        page = _make_smart_page((0xC7, 100, 2), (0xE8, 100, 1))
        self.server.logs[_LID_VU_SMART] = page
        result = self.assertOkSmartLog()
        self.assertIn('bad_tlp_error_count', result.stdout)

    def test_multiple_attributes_all_reported(self):
        """All non-zero attributes in the page are printed."""
        page = _make_smart_page(
            (0xAB, 100, 0),
            (0xAE, 100, 3),
            (0xF4, 100, 0x200),
            (0xF5, 100, 0x100),
        )
        self.server.logs[_LID_VU_SMART] = page
        result = self.assertOkSmartLog()
        for name in ('program_fail_count', 'unexpected_power_loss',
                     'nand_bytes_written', 'host_bytes_written'):
            self.assertIn(name, result.stdout)

    def test_get_log_page_uses_correct_lid(self):
        """The command must issue Get Log Page with LID 0xCA."""
        self.server.logs[_LID_VU_SMART] = bytes(_PAGE_SIZE)
        self.assertOkSmartLog()

        log_cmds = [c for c in self.server.commands
                    if c.admin and c.opcode == OPC_GET_LOG_PAGE
                    and c.lid == _LID_VU_SMART]
        self.assertGreaterEqual(len(log_cmds), 1,
                                'No Get Log Page 0xCA command recorded')


if __name__ == '__main__':
    main()
