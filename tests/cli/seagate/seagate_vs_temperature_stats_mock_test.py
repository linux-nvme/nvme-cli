#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for "nvme seagate vs-temperature-stats" against a mocked controller.

The command converts the temperatures of the SMART log from Kelvin to
degrees Celsius, so a drive below 0 C reports negative values, in text
and in JSON.

Usage: python3 seagate_vs_temperature_stats_mock_test.py <nvme-binary> <mock-lib>
"""
import json
import struct

from tests.cli.nvme_mock import (CNS_CTRL, LID_SMART, MockTestCase, id_ctrl,
                                 main, smart_log)

# Temperature Sensors 1 and 2 of the SMART log, in Kelvin
_TEMP_SENSORS_OFFSET = 200


class SeagateVsTemperatureStatsTest(MockTestCase):
    """A controller below 0 C: a composite temperature of 263 K, and
    sensors at 268 K and 253 K."""

    def setUp(self):
        super().setUp()
        self.server.identify[CNS_CTRL] = id_ctrl(mn='ST800FM0173')
        log = bytearray(smart_log(temperature=263))
        struct.pack_into('<HH', log, _TEMP_SENSORS_OFFSET, 268, 253)
        self.server.logs[LID_SMART] = bytes(log)

    def _run(self, *args):
        return self.assertOk(self.nvme('seagate', 'vs-temperature-stats',
                                       self.ctrl, *args)).stdout

    def test_normal_output_below_zero(self):
        out = self._run()
        self.assertRegex(out, r'Current Temperature +: -10 C')
        self.assertRegex(out, r'Current PCB Temperature +: -5 C')
        self.assertRegex(out, r'Current SOC Temperature +: -20 C')

    def test_json_output_below_zero(self):
        doc = json.loads(self._run('--output-format=json'))
        self.assertEqual(doc['Current temperature'], -10)
        self.assertEqual(doc['Current PCB temperature'], -5)
        self.assertEqual(doc['Current SOC temperature'], -20)


if __name__ == '__main__':
    main()
