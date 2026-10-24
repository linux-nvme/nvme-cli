#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the LBA formats format takes from Identify Namespace: an LBA data
size (LBADS) the device reports is a shift count, which must not shift
past the type it shifts.

Usage: python3 nvme_format_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""

from tests.cli.nvme_mock import CNS_NS, MockTestCase, id_ns, main


class FormatCLITest(MockTestCase):
    """A namespace with the LBA data sizes of a test, which answers the
    other commands with success and zeroed data."""

    def _format(self, lbads, *args):
        self.server.identify[CNS_NS] = id_ns(lbaf=[(0, ds, 0)
                                                   for ds in lbads])
        return self.nvme('format', *args, '--force')

    def test_block_size_lbads_too_large(self):
        # 1ULL << 64 is no block size, and no shift
        result = self._format([9, 64], '/dev/nvme0', '--namespace-id=1',
                              '--block-size=4096')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('LBAF corresponding to given block size 4096 not '
                      'found', result.stderr)
        self.assertNotIn('runtime error', result.stderr)

    def test_block_size_found(self):
        result = self._format([9, 12], '/dev/nvme0', '--namespace-id=1',
                              '--block-size=4096')
        self.assertNotIn('not found', result.stderr)

    def test_new_block_size_lbads_too_large(self):
        # The block size of the namespace block device after the format
        result = self._format([9, 40], '/dev/nvme0n1', '--namespace-id=1',
                              '--lbaf=1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('invalid LBA data size 40', result.stderr)
        self.assertNotIn('runtime error', result.stderr)


if __name__ == '__main__':
    main()
