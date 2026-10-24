#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the reservation commands of the resv plugin: register, acquire,
release and report. Checks the fields and data of the commands against
the NVM Express NVM Command Set Specification 1.3.

Usage: python3 nvme_resv_test.py <path-to-nvme-binary> <mock-lib>
"""
import struct

from tests.cli.nvme_mock import (CNS_CTRL, NVME_IOCTL_ID, SC_INVALID_FIELD,
                                 MockTestCase, Reply, main)

OPC_RESV_REGISTER = 0x0d
OPC_RESV_REPORT = 0x0e
OPC_RESV_ACQUIRE = 0x11
OPC_RESV_RELEASE = 0x15

IEKEY = 1 << 3

# the sizes of the Reservation Status data structure header and of a
# Registered Controller data structure
RESV_HDR_SIZE = 24
RESV_REGCTL_SIZE = 24
RESV_EXT_HDR_SIZE = 64


class ResvTestBase(MockTestCase):

    def setUp(self):
        super().setUp()
        self.server.ioctls[NVME_IOCTL_ID] = Reply(status=1)

    def resv(self, opcode, *args):
        """Run the resv command @args. Returns the I/O commands @opcode
        it sends."""
        result = self.nvme('resv', *args)
        if 'invalid sub-command' in result.stderr:
            self.skipTest('resv plugin not built')
        self.assertOk(result)
        return self.server.io_cmds(opcode)

    def assertRefused(self, args, message, opcode):
        result = self.nvme('resv', *args)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)
        self.assertEqual(self.server.io_cmds(opcode), [])


class RegisterTest(ResvTestBase):

    def test_fields(self):
        cmd, = self.resv(OPC_RESV_REGISTER, 'register', self.ns,
                         '--crkey=0x1122334455667788', '--nrkey=0x99',
                         '--rrega=2', '--cptpl=3', '--iekey')
        # RREGA 2:0, IEKEY, CPTPL 31:30
        self.assertEqual((cmd.nsid, cmd.cdw10), (1, 3 << 30 | IEKEY | 2))
        # current and new reservation key
        self.assertEqual(cmd.data,
                         struct.pack('<QQ', 0x1122334455667788, 0x99))

    def test_namespace_id(self):
        cmd, = self.resv(OPC_RESV_REGISTER, 'register', self.ctrl,
                         '--namespace-id=2', '--nrkey=1')
        self.assertEqual((cmd.nsid, cmd.cdw10), (2, 0))

    def test_invalid(self):
        for arg, message in (('--rrega=8', 'invalid rrega:8'),
                             ('--cptpl=4', 'invalid cptpl:4')):
            with self.subTest(arg=arg):
                self.assertRefused(['register', self.ns, arg], message,
                                   OPC_RESV_REGISTER)


class AcquireTest(ResvTestBase):

    def test_fields(self):
        cmd, = self.resv(OPC_RESV_ACQUIRE, 'acquire', self.ns,
                         '--crkey=0x1234', '--prkey=0x5678', '--rtype=3',
                         '--racqa=1', '--iekey')
        # RACQA 2:0, IEKEY, RTYPE 15:8
        self.assertEqual((cmd.nsid, cmd.cdw10), (1, 3 << 8 | IEKEY | 1))
        # current and preempt reservation key
        self.assertEqual(cmd.data, struct.pack('<QQ', 0x1234, 0x5678))

    def test_invalid(self):
        self.assertRefused(['acquire', self.ns, '--racqa=8'],
                           'invalid racqa:8', OPC_RESV_ACQUIRE)


class ReleaseTest(ResvTestBase):

    def test_fields(self):
        cmd, = self.resv(OPC_RESV_RELEASE, 'release', self.ns,
                         '--crkey=0xabcdef', '--rtype=5', '--rrela=1',
                         '--iekey')
        # RRELA 2:0, IEKEY, RTYPE 15:8
        self.assertEqual((cmd.nsid, cmd.cdw10), (1, 5 << 8 | IEKEY | 1))
        self.assertEqual(cmd.data, struct.pack('<Q', 0xabcdef))

    def test_invalid(self):
        self.assertRefused(['release', self.ns, '--rrela=8'],
                           'invalid rrela:8', OPC_RESV_RELEASE)


def resv_status(regstrnt, size=RESV_HDR_SIZE):
    """A Reservation Status data structure header with Number of
    Registered Controllers @regstrnt"""
    return struct.pack('<IBH', 7, 1, regstrnt).ljust(size, b'\0')


class ReportTest(ResvTestBase):

    def test_registrants(self):
        """The report reads the header first, then the registered
        controllers the header reports"""
        self.server.io[OPC_RESV_REPORT] = resv_status(2)
        cmds = self.resv(OPC_RESV_REPORT, 'report', self.ns)
        # NUMD is 0's based; EDS is bit 0 of CDW11
        self.assertEqual([(c.nsid, c.cdw10, c.cdw11, c.data_len)
                          for c in cmds],
                         [(1, RESV_HDR_SIZE // 4 - 1, 0, RESV_HDR_SIZE),
                          (1, (RESV_HDR_SIZE + 2 * RESV_REGCTL_SIZE) // 4 - 1,
                           0, RESV_HDR_SIZE + 2 * RESV_REGCTL_SIZE)])

    def test_no_registrants(self):
        cmd, = self.resv(OPC_RESV_REPORT, 'report', self.ns)
        self.assertEqual(cmd.data_len, RESV_HDR_SIZE)

    def test_eds(self):
        cmd, = self.resv(OPC_RESV_REPORT, 'report', self.ns, '--eds')
        self.assertEqual((cmd.cdw10, cmd.cdw11, cmd.data_len),
                         (RESV_EXT_HDR_SIZE // 4 - 1, 1, RESV_EXT_HDR_SIZE))

    def test_identify_fails(self):
        """The report fails with the status of Identify Controller"""
        self.server.identify[CNS_CTRL] = SC_INVALID_FIELD
        result = self.nvme('resv', 'report', self.ns)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Invalid Field in Command', result.stderr)
        self.assertEqual(self.server.io_cmds(OPC_RESV_REPORT), [])

    def test_numd(self):
        """An explicit --numd is taken as given, in one command"""
        self.server.io[OPC_RESV_REPORT] = resv_status(2)
        cmd, = self.resv(OPC_RESV_REPORT, 'report', self.ns, '--numd=11')
        self.assertEqual((cmd.cdw10, cmd.data_len), (11, 48))


if __name__ == '__main__':
    main()
