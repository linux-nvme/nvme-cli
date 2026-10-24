#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests format: the Format NVM command it sends (NVM Express Base
Specification 2.4, section 5.2.10), the LBA format it picks from Identify
Namespace, and the namespace rescan or controller reset after it.

An LBA data size (LBADS) the device reports is a shift count, which must
not shift past the type it shifts.

Usage: python3 nvme_format_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""

from tests.cli.nvme_mock import (CNS_CTRL, CNS_NS, NSID_ALL, NVME_IOCTL_ID,
                                 NVME_IOCTL_RESCAN, NVME_IOCTL_RESET,
                                 MockTestCase, id_ctrl, id_ns, main)

OPC_FORMAT_NVM = 0x80
# FNA: a format of any namespace formats all of them
FNA_FMT_ALL_NAMESPACES = 1 << 0
DEFAULT_TIMEOUT_MS = 600000


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


class FormatCommandTest(MockTestCase):
    """A namespace with the LBA formats 512, 512 + 8, 4096 and 4096 + 8,
    of which the second is in use"""

    def setUp(self):
        super().setUp()
        self.server.identify[CNS_NS] = id_ns(
            flbas=1, lbaf=[(0, 9, 0), (8, 9, 0), (0, 12, 0), (8, 12, 0)])
        for nr in (NVME_IOCTL_RESCAN, NVME_IOCTL_RESET):
            self.server.ioctls[nr] = 0

    def format(self, *args):
        """Run format, which sends one Format NVM. Returns it."""
        self.assertOk(self.nvme('format', *args, '--force'))
        cmd, = self.server.admin_cmds(OPC_FORMAT_NVM)
        return cmd

    def assertRefused(self, args, message):
        result = self.nvme('format', *args, '--force')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)
        self.assertEqual(self.server.admin_cmds(OPC_FORMAT_NVM), [])

    def test_fields(self):
        cmd = self.format(self.ctrl, '--namespace-id=1', '--lbaf=3',
                          '--ses=1', '--pi=1', '--pil=1', '--ms=1')
        # LBAFL, MSET, PI, PIL, SES
        self.assertEqual((cmd.nsid, cmd.cdw10),
                         (1, 3 | 1 << 4 | 1 << 5 | 1 << 8 | 1 << 9))
        self.assertEqual(cmd.timeout_ms, DEFAULT_TIMEOUT_MS)

    def test_timeout(self):
        cmd = self.format(self.ctrl, '--namespace-id=1', '--timeout=1000')
        self.assertEqual(cmd.timeout_ms, 1000)

    def test_lba_format_upper_bits(self):
        self.server.identify[CNS_NS] = id_ns(
            lbaf={i: (0, 9 if i < 63 else 12, 0) for i in range(64)})
        cmd = self.format(self.ctrl, '--namespace-id=1', '--lbaf=0x2b')
        # LBAFL 3:0, LBAFU 13:12
        self.assertEqual(cmd.cdw10, 0xb | 2 << 12)

    def test_lba_format_in_use(self):
        """Without --lbaf, the LBA format in use"""
        cmd = self.format(self.ctrl, '--namespace-id=1')
        self.assertEqual(cmd.cdw10, 1)

    def test_block_size(self):
        """The LBA format of the block size, without metadata"""
        cmd = self.format(self.ctrl, '--namespace-id=1', '--block-size=4096')
        self.assertEqual(cmd.cdw10, 2)

    def test_nsid_of_the_device(self):
        self.server.ioctls[NVME_IOCTL_ID] = 2
        cmd = self.format(self.ns, '--lbaf=1')
        self.assertEqual(cmd.nsid, 2)

    def test_all_namespaces(self):
        """A controller which formats all namespaces at once gets all
        namespaces, and the first LBA format unless given"""
        self.server.identify[CNS_CTRL] = id_ctrl(fna=FNA_FMT_ALL_NAMESPACES)
        cmd = self.format(self.ctrl, '--namespace-id=1')
        self.assertEqual((cmd.nsid, cmd.cdw10), (NSID_ALL, 0))
        self.assertEqual(self.server.identifies(CNS_NS), [])

    def test_no_namespace(self):
        self.assertRefused([self.ctrl], 'Invalid namespace ID')
        self.server.ioctls[NVME_IOCTL_ID] = 0     # no namespace
        self.assertRefused([self.ns], 'Invalid namespace ID')

    def test_rescan_after_lba_format_change(self):
        """The controller rescans the namespaces when the LBA format
        changes"""
        self.format(self.ctrl, '--namespace-id=1', '--lbaf=1')
        self.assertEqual(self.server.raw_ioctls, [])
        self.server.commands.clear()
        self.format(self.ctrl, '--namespace-id=1', '--lbaf=2')
        self.assertEqual([i.nr for i in self.server.raw_ioctls],
                         [NVME_IOCTL_RESCAN])

    def test_reset(self):
        self.format(self.ctrl, '--namespace-id=1', '--reset')
        self.assertEqual([i.nr for i in self.server.raw_ioctls],
                         [NVME_IOCTL_RESET])

    def test_invalid_options(self):
        cases = [
            (['--lbaf=1', '--block-size=512'],
             'Invalid specification of both LBAF and Block Size'),
            (['--block-size=1000'], 'must be a power of two'),
            (['--block-size=1024'], 'LBAF corresponding to given block'),
            (['--lbaf=64'], 'invalid lbaf:64'),
            (['--ses=8'], 'invalid secure erase settings:8'),
            (['--pi=8'], 'invalid pi:8'),
            (['--pil=2'], 'invalid pil:2'),
            (['--ms=2'], 'invalid mset:2'),
        ]
        for args, message in cases:
            with self.subTest(args=args):
                self.assertRefused([self.ctrl, '--namespace-id=1', *args],
                                   message)


if __name__ == '__main__':
    main()
