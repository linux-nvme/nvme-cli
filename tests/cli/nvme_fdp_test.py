#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the printers of the fdp plugin: they decode in the sandbox, and
get-log -v uses them for the FDP log pages (NVM Express Base Specification
2.4, sections 5.2.13.1.29 to 5.2.13.1.32).

Usage: python3 nvme_fdp_test.py <path-to-nvme-binary> <mock-lib>
"""
import struct

from tests.cli.nvme_mock import (HAVE_GET_LOG, HAVE_JSON, NVME_IOCTL_ID,
                                 MockTestCase, Reply, main)

LID_FDP_CONFIGS = 0x20
LID_FDP_RUH_USAGE = 0x21
LID_FDP_STATS = 0x22
LID_FDP_EVENTS = 0x23


def _configs_log():
    # one configuration (n is zero based) with one reclaim unit handle
    desc = struct.pack('<HBBIHHIQI36x', 68, 0x80, 0, 1, 1, 1, 1, 4096, 0)
    ruh = struct.pack('<B3x', 1)
    return struct.pack('<HHI8x', 0, 0, 16 + len(desc) + len(ruh)) + \
        desc + ruh


def _usage_log():
    return struct.pack('<H6x', 1) + struct.pack('<B7x', 1)


def _stats_log():
    return (5).to_bytes(16, 'little') + bytes(48)


def _events_log():
    return struct.pack('<I60x', 1) + bytes(64)


# log page ID -> (log page, expected stdout line, expected JSON key)
_LOGS = {
    LID_FDP_CONFIGS: (_configs_log(), 'Number of Reclaim Unit Handles',
                      '"configs"'),
    LID_FDP_RUH_USAGE: (_usage_log(), 'Reclaim Unit Handle 0 Attributes',
                        '"ruhus"'),
    LID_FDP_STATS: (_stats_log(), 'Host Bytes with Metadata Written',
                    '"hbmw"'),
    LID_FDP_EVENTS: (_events_log(), 'Reclaim Unit Not Fully Written',
                     '"events"'),
}


class FdpTestCase(MockTestCase):
    """Serves the FDP log pages of _LOGS, and namespace 1."""

    def setUp(self):
        super().setUp()
        for lid, (log, _, _) in _LOGS.items():
            self.server.logs[lid] = log
        self.server.ioctls[NVME_IOCTL_ID] = Reply(status=1)


class FdpGetLogTest(FdpTestCase):

    def setUp(self):
        super().setUp()
        if not HAVE_GET_LOG:
            self.skipTest('built without the log plugin')

    def get_log(self, lid, *args):
        log = _LOGS[lid][0]
        result = self.nvme('get-log', self.ctrl, f'--log-id={lid:#x}',
                           f'--log-len={len(log)}', '-v', *args)
        self.assertOk(result)
        return result

    def test_decoded(self):
        for lid, (_, line, _) in _LOGS.items():
            with self.subTest(lid=lid):
                self.assertIn(line, self.get_log(lid).stdout)

    def test_decoded_json(self):
        if not HAVE_JSON:
            self.skipTest('built without json-c')
        for lid, (_, _, key) in _LOGS.items():
            with self.subTest(lid=lid):
                self.assertIn(key, self.get_log(lid, '-o', 'json').stdout)


class FdpPrintTest(FdpTestCase):

    def test_decoded_in_sandbox(self):
        for cmd in ('configs', 'usage', 'stats', 'events'):
            with self.subTest(cmd=cmd):
                self.assertDecodedInSandbox('fdp', cmd, self.ctrl,
                                            '-e', '1')

    def test_status_decoded_in_sandbox(self):
        self.assertDecodedInSandbox('fdp', 'status', self.ns)


if __name__ == '__main__':
    main()
