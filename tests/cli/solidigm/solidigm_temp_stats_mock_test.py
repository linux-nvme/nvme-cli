#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Hardware-free tests for the Solidigm temp-stats command.

The Solidigm 'solidigm temp-stats' command retrieves a temperature statistics
log page.  It first tries log page ID 0xD5 (SLDGM_TEMP_STATS_LID), and falls
back to 0xC5 (SLDGM_LEGACY_TEMP_STATS_LID) if the first attempt fails.

The 88-byte struct temp_stats payload layout (from solidigm-temp-stats.c):

  Offset  Field               Type    Label
  0       curr                le64    "Current temperature"
  8       last_overtemp       le64    "Last critical overtemp flag"
  16      life_overtemp       le64    "Life critical overtemp flag"
  24      highest_temp        le64    "Highest temperature"
  32      lowest_temp         le64    "Lowest temperature"
  40..79  rsvd                40 bytes
  80      max_operating_temp  le64    "Max operating temperature"
  88      min_operating_temp  le64    "Min operating temperature"
  96      est_offset          le64    "Estimated offset"

The page is read into a 4096-byte buffer, so the mock page must be at least
88 bytes.

Usage: python3 solidigm_temp_stats_mock_test.py <nvme-binary> <mock-lib>
"""

import struct

from tests.cli.nvme_mock import (OPC_GET_LOG_PAGE, SC_INVALID_FIELD,
                                 SC_INVALID_LOG_PAGE, MockTestCase, main)

# Log page identifiers.
_LID_TEMP_STATS        = 0xD5   # primary (SLDGM_TEMP_STATS_LID)
_LID_LEGACY_TEMP_STATS = 0xC5   # fallback (SLDGM_LEGACY_TEMP_STATS_LID)

# GUID that marks the legacy page as OCP-unsupported (causes -EBADMSG).
# From solidigm-temp-stats.c:
# guid[1]==0xC7BB98B7D0324863, guid[0]==0xBB2C23990E9C722F
_OCP_BAD_GUID_HIGH = 0xC7BB98B7D0324863
_OCP_BAD_GUID_LOW  = 0xBB2C23990E9C722F

# struct temp_stats field offsets (all le64, 8 bytes each).
_OFF_CURR         = 0
_OFF_LAST_OT      = 8
_OFF_LIFE_OT      = 16
_OFF_HIGHEST      = 24
_OFF_LOWEST       = 32
_OFF_RSVD         = 40   # 40 bytes reserved
_OFF_MAX_OP       = 80
_OFF_MIN_OP       = 88
_OFF_EST_OFFSET   = 96

_PAGE_SIZE = 4096        # buffer the driver reads into


def _make_temp_stats_page(curr=0, last_overtemp=0, life_overtemp=0,
                           highest=0, lowest=0,
                           max_operating=0, min_operating=0, est_offset=0):
    """Build a 4096-byte temp stats page."""
    buf = bytearray(_PAGE_SIZE)
    for off, val in (
        (_OFF_CURR,     curr),
        (_OFF_LAST_OT,  last_overtemp),
        (_OFF_LIFE_OT,  life_overtemp),
        (_OFF_HIGHEST,  highest),
        (_OFF_LOWEST,   lowest),
        (_OFF_MAX_OP,   max_operating),
        (_OFF_MIN_OP,   min_operating),
        (_OFF_EST_OFFSET, est_offset),
    ):
        struct.pack_into('<Q', buf, off, val & 0xFFFFFFFFFFFFFFFF)
    return bytes(buf)


def _make_legacy_page_with_guid(guid_high, guid_low, **kwargs):
    """Build a legacy temp-stats page with a specific GUID at offset 4080."""
    buf = bytearray(_make_temp_stats_page(**kwargs))
    # guid[0] at offset 4080, guid[1] at offset 4088 (two u64 LE words).
    struct.pack_into('<Q', buf, 4080, guid_low)
    struct.pack_into('<Q', buf, 4088, guid_high)
    return bytes(buf)


class TestSolidigmTempStats(MockTestCase):
    """Run solidigm temp-stats against a simulated controller."""

    def run_temp_stats(self, *args):
        return self.nvme('solidigm', 'temp-stats', self.ctrl, *args)

    def assertOkTempStats(self, *args):
        return self.assertOk(self.run_temp_stats(*args))

    def test_primary_page_succeeds(self):
        """When log page 0xD5 succeeds, all labels must appear."""
        self.server.logs[_LID_TEMP_STATS] = _make_temp_stats_page(
            curr=305, highest=320, lowest=295,
            max_operating=358, min_operating=273)
        result = self.assertOkTempStats()
        for label in ('Current temperature', 'Last critical overtemp flag',
                      'Life critical overtemp flag', 'Highest temperature',
                      'Lowest temperature', 'Max operating temperature',
                      'Min operating temperature', 'Estimated offset'):
            self.assertIn(label, result.stdout,
                          f'Expected label {label!r} in temp-stats output')

    def test_primary_page_reports_current_temperature(self):
        """The current temperature value from the page is printed."""
        self.server.logs[_LID_TEMP_STATS] = _make_temp_stats_page(curr=305)
        result = self.assertOkTempStats()
        self.assertIn('305', result.stdout)

    def test_primary_page_reports_highest_and_lowest(self):
        """Highest and lowest temperature values are both printed."""
        self.server.logs[_LID_TEMP_STATS] = _make_temp_stats_page(
            highest=350, lowest=270)
        result = self.assertOkTempStats()
        self.assertIn('350', result.stdout)
        self.assertIn('270', result.stdout)

    def test_primary_page_reports_max_and_min_operating(self):
        """Max and min operating temperatures from the struct are printed."""
        self.server.logs[_LID_TEMP_STATS] = _make_temp_stats_page(
            max_operating=358, min_operating=253)
        result = self.assertOkTempStats()
        self.assertIn('358', result.stdout)
        self.assertIn('253', result.stdout)

    def test_estimated_offset_reported(self):
        """The estimated offset field value appears in the output."""
        self.server.logs[_LID_TEMP_STATS] = _make_temp_stats_page(
            est_offset=5)
        result = self.assertOkTempStats()
        self.assertIn('Estimated offset', result.stdout)
        self.assertIn('5', result.stdout)

    def test_primary_page_failure_falls_back_to_legacy(self):
        """When 0xD5 returns an error, 0xC5 is tried instead."""
        # 0xD5 fails; 0xC5 succeeds with valid data.
        self.server.logs[_LID_TEMP_STATS] = SC_INVALID_LOG_PAGE
        self.server.logs[_LID_LEGACY_TEMP_STATS] = _make_temp_stats_page(
            curr=310)
        result = self.assertOkTempStats()
        self.assertIn('310', result.stdout)

    def test_legacy_page_with_ocp_bad_guid_fails(self):
        """The OCP unsupported GUID at offset 4080 must cause failure."""
        self.server.logs[_LID_TEMP_STATS] = SC_INVALID_LOG_PAGE
        self.server.logs[_LID_LEGACY_TEMP_STATS] = \
            _make_legacy_page_with_guid(_OCP_BAD_GUID_HIGH, _OCP_BAD_GUID_LOW,
                                        curr=300)
        result = self.run_temp_stats()
        self.assertNotEqual(result.returncode, 0)

    def test_legacy_page_with_different_guid_succeeds(self):
        """A legacy page whose GUID does not match the OCP sentinel is valid."""
        self.server.logs[_LID_TEMP_STATS] = SC_INVALID_LOG_PAGE
        # Use a different GUID (not the OCP sentinel).
        self.server.logs[_LID_LEGACY_TEMP_STATS] = \
            _make_legacy_page_with_guid(0xDEADBEEFDEADBEEF, 0x0102030405060708,
                                        curr=295)
        result = self.assertOkTempStats()
        self.assertIn('295', result.stdout)

    def test_both_pages_failing_exits_error(self):
        """When both 0xD5 and 0xC5 fail, the command exits non-zero."""
        self.server.logs[_LID_TEMP_STATS] = SC_INVALID_LOG_PAGE
        self.server.logs[_LID_LEGACY_TEMP_STATS] = SC_INVALID_FIELD
        result = self.run_temp_stats()
        self.assertNotEqual(result.returncode, 0)

    def test_primary_page_fatal_error_exits_error(self):
        """When 0xD5 fails and fallback 0xC5 also fails, command exits error."""
        self.server.logs[_LID_TEMP_STATS] = SC_INVALID_FIELD
        self.server.logs[_LID_LEGACY_TEMP_STATS] = SC_INVALID_FIELD
        result = self.run_temp_stats()
        self.assertNotEqual(result.returncode, 0)

    def test_all_zero_page_prints_zeros(self):
        """An all-zero page succeeds and prints zeros for each field."""
        self.server.logs[_LID_TEMP_STATS] = bytes(_PAGE_SIZE)
        result = self.assertOkTempStats()
        self.assertIn('Current temperature', result.stdout)
        # At least one '0' in output for the zero values.
        self.assertIn('0', result.stdout)

    def test_get_log_page_uses_correct_primary_lid(self):
        """The primary command must use log page ID 0xD5."""
        self.server.logs[_LID_TEMP_STATS] = _make_temp_stats_page()
        self.assertOkTempStats()

        cmds = [c for c in self.server.commands
                if c.admin and c.opcode == OPC_GET_LOG_PAGE
                and c.lid == _LID_TEMP_STATS]
        self.assertGreaterEqual(len(cmds), 1,
                                'No Get Log Page 0xD5 command recorded')

    def test_fallback_issues_legacy_lid(self):
        """On primary failure, a Get Log Page 0xC5 must be issued."""
        self.server.logs[_LID_TEMP_STATS] = SC_INVALID_LOG_PAGE
        self.server.logs[_LID_LEGACY_TEMP_STATS] = _make_temp_stats_page()
        self.assertOkTempStats()

        cmds = [c for c in self.server.commands
                if c.admin and c.opcode == OPC_GET_LOG_PAGE
                and c.lid == _LID_LEGACY_TEMP_STATS]
        self.assertGreaterEqual(len(cmds), 1,
                                'No fallback Get Log Page 0xC5 '
                                'command recorded')


if __name__ == '__main__':
    main()
