#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the LBA data size zns zone-append takes from Identify Namespace:
a shift count from the device, which must not shift past the type it
shifts.

Usage: python3 nvme_zns_append_test.py <path-to-nvme-binary> <mock-lib>
"""
from tests.cli.nvme_mock import CNS_NS, MockTestCase, id_ns, main


class ZnsAppendCLITest(MockTestCase):
    """A namespace whose LBA format 0 has the data size of a test."""

    def _append(self, lbads):
        self.server.identify[CNS_NS] = id_ns(lbaf=[(0, lbads, 0)])
        return self.nvme('zns', 'zone-append', self.ns, '--namespace-id=1',
                         '--data-size=4096')

    def test_lbads_too_large(self):
        result = self._append(40)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('invalid LBA data size 40', result.stderr)
        self.assertNotIn('runtime error', result.stderr)

    def test_unaligned(self):
        # 4096 bytes are no multiple of an 8 KiB LBA
        result = self._append(13)
        self.assertIn('not aligned to lba size:0x2000', result.stderr)


if __name__ == '__main__':
    main()
