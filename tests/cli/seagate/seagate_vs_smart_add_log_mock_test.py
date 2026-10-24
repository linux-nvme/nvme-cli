#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for "nvme seagate vs-smart-add-log" against a mocked controller.

The command reads the extended SMART log 0xC4 and the DRAM SMART log 0xCF
of a legacy (Jaguar or Panther) drive, and the log 0xC0 of any other.
Each must be printed once, in text and in JSON.

Usage: python3 seagate_vs_smart_add_log_mock_test.py <nvme-binary> <mock-lib>
"""
import json

from tests.cli.nvme_mock import CNS_CTRL, MockTestCase, id_ctrl, main

_JAGUAR_MN = 'ST1000KN0002'


class SeagateVsSmartAddLogTest(MockTestCase):
    """A controller whose model number is ST800FM0173, unless a test
    sets another, with zeroed log pages."""

    def setUp(self):
        super().setUp()
        self._model('ST800FM0173')

    def _model(self, mn):
        self.server.identify[CNS_CTRL] = id_ctrl(mn=mn)

    def _run(self, *args):
        return self.assertOk(self.nvme('seagate', 'vs-smart-add-log',
                                       self.ctrl, *args)).stdout

    def _lids(self):
        return [c.lid for c in self.server.log_reads()]

    @staticmethod
    def _json(out):
        # the JSON follows a heading line
        return json.loads(out.split('\n', 1)[1])

    def test_jaguar_logs_read_and_printed_once(self):
        self._model(_JAGUAR_MN)
        out = self._run()
        self.assertEqual(self._lids(), [0xc4, 0xcf])
        self.assertEqual(out.count('Ext-Smart-Id'), 1)

    def test_jaguar_json_printed_once(self):
        self._model(_JAGUAR_MN)
        out = self._json(self._run('-o', 'json'))
        self.assertEqual(self._lids(), [0xc4, 0xcf])
        self.assertEqual(len(out['SMART-Attributes']), 2)

    def test_log_c0_read_and_printed_once(self):
        self._run()
        self.assertEqual(self._lids(), [0xc0])

    def test_log_c0_json(self):
        out = self._json(self._run('-o', 'json'))
        self.assertEqual(self._lids(), [0xc0])
        self.assertEqual(len(out['SMART-Attributes']), 1)


if __name__ == '__main__':
    main()
