#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp set-latency-monitor-feature" against a mocked
controller.

The Set Features data is checked against the Latency Monitor Data
Structure as the OCP specification lays it out (LMDS-1..11), not against
nvme-cli's struct.

Tests in this module verify:
  * Set Features for FID C5h carries the 4096-byte structure, every field
    at its LMDS offset with its default value.
  * Each option changes its own field and nothing else.
  * A value too large for its field is refused before anything is sent.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_latency_monitor_feature_mock_test.py <nvme-binary> <mock-lib>
"""
import struct

from tests.cli.nvme_mock import OPC_SET_FEATURES, main
from tests.cli.ocp.ocp_mock_test import OCPMockTestBase

FID_LATENCY_MONITOR = 0xC5
DATA_SIZE = 4096

# (option, offset, struct format, default) per LMDS field.
FIELDS = [
    ('--active_bucket_timer_threshold', 0, '<H', 0x7E0),   # LMDS-1
    ('--active_threshold_a', 2, '<B', 0x05),               # LMDS-2
    ('--active_threshold_b', 3, '<B', 0x13),               # LMDS-3
    ('--active_threshold_c', 4, '<B', 0x1E),               # LMDS-4
    ('--active_threshold_d', 5, '<B', 0x2E),               # LMDS-5
    ('--active_latency_config', 6, '<H', 0xFFF),           # LMDS-6
    ('--active_latency_minimum_window', 8, '<B', 0x0A),    # LMDS-7
    ('--debug_log_trigger_enable', 9, '<H', 0),            # LMDS-8
    ('--discard_debug_log', 11, '<B', 0),                  # LMDS-9
    ('--latency_monitor_feature_enable', 12, '<B', 0x01),  # LMDS-10
]


def expected_data(values=None):
    """The structure with every field at its default, except those in
    @values, a dict of offset to value."""
    values = values or {}
    data = bytearray(DATA_SIZE)
    for _, offset, fmt, default in FIELDS:
        struct.pack_into(fmt, data, offset, values.get(offset, default))
    return bytes(data)


class TestSetLatencyMonitorFeature(OCPMockTestBase):

    def set_ok(self, *args):
        return self.assertOk(self.run_ocp('set-latency-monitor-feature',
                                          *args))

    def sent(self):
        sets = [c for c in self.server.admin_cmds(OPC_SET_FEATURES)
                if c.fid == FID_LATENCY_MONITOR]
        self.assertEqual(len(sets), 1, sets)
        return sets[0].data

    def test_defaults_are_at_their_offsets(self):
        self.set_ok()
        self.assertEqual(self.sent(), expected_data())

    def test_each_option_sets_only_its_field(self):
        for option, offset, fmt, _ in FIELDS:
            value = 0xABCD if fmt == '<H' else 0xAB
            with self.subTest(option=option):
                self.server.commands.clear()
                result = self.set_ok(option, hex(value))
                self.assertEqual(self.sent(), expected_data({offset: value}))
                self.assertIn(f': {hex(value)}', result.stdout)

    def test_values_too_large_for_their_field_are_refused(self):
        for option, _, fmt, _ in FIELDS:
            too_large = 1 << (16 if fmt == '<H' else 8)
            with self.subTest(option=option):
                self.server.commands.clear()
                result = self.run_ocp('set-latency-monitor-feature', option,
                                      str(too_large))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(
                    self.server.admin_cmds(OPC_SET_FEATURES), [])


if __name__ == '__main__':
    main()
