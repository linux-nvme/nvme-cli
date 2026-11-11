#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Hardware-free tests for the Transcend healthvalue command.

Tests health percentage computation (100 - percent_used) based on the
standard NVMe SMART / Health Information log page (LID 0x02).

Usage: python3 transcend_healthvalue_mock_test.py <nvme-binary> <mock-lib>
"""

from tests.cli.nvme_mock import MockTestCase, SC_INVALID_LOG_PAGE, main

_LID_SMART = 0x02


def make_smart_log(percent_used=0):
    """Return a 512-byte SMART/Health log page with the given percent_used."""
    buf = bytearray(512)
    buf[5] = percent_used
    return bytes(buf)


class TestTranscendHealthValue(MockTestCase):
    """Run transcend healthvalue against a simulated controller."""

    def test_healthvalue_normal(self):
        """percent_used=15 reports 85% health value."""
        self.server.logs[_LID_SMART] = make_smart_log(percent_used=15)
        result = self.assertOk(self.nvme('transcend', 'healthvalue', self.ctrl))
        self.assertIn('Transcend NVME heath value: 85%', result.stdout)

    def test_healthvalue_brand_new(self):
        """percent_used=0 reports 100% health value."""
        self.server.logs[_LID_SMART] = make_smart_log(percent_used=0)
        result = self.assertOk(self.nvme('transcend', 'healthvalue', self.ctrl))
        self.assertIn('Transcend NVME heath value: 100%', result.stdout)

    def test_healthvalue_completely_used(self):
        """percent_used=100 reports 0% health value."""
        self.server.logs[_LID_SMART] = make_smart_log(percent_used=100)
        result = self.assertOk(self.nvme('transcend', 'healthvalue', self.ctrl))
        self.assertIn('Transcend NVME heath value: 0%', result.stdout)

    def test_healthvalue_exceeded(self):
        """percent_used > 100 clamped to 0%."""
        self.server.logs[_LID_SMART] = make_smart_log(percent_used=105)
        result = self.assertOk(self.nvme('transcend', 'healthvalue', self.ctrl))
        self.assertIn('Transcend NVME heath value: 0%', result.stdout)

    def test_healthvalue_log_failure(self):
        """Failing SMART log read exits non-zero."""
        self.server.logs[_LID_SMART] = SC_INVALID_LOG_PAGE
        result = self.nvme('transcend', 'healthvalue', self.ctrl)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    main()
