#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the NVM command set I/O commands: flush, dsm, write-zeroes,
write-uncor, verify, read, write, compare and copy, and the admin command
get-lba-status. Checks the fields and data of the commands against the
NVM Express NVM Command Set Specification 1.3.

Usage: python3 nvme_io_test.py <path-to-nvme-binary> <mock-lib>
"""
import os
import struct

from tests.cli.nvme_mock import (CNS_NS, NVME_IOCTL_ID, OPC_NVM_READ,
                                 OPC_NVM_WRITE, MockTestCase, Reply, id_ns,
                                 main)

OPC_NVM_FLUSH = 0x00
OPC_NVM_COMPARE = 0x05
OPC_NVM_WRITE_UNCOR = 0x04
OPC_NVM_WRITE_ZEROES = 0x08
OPC_NVM_DSM = 0x09
OPC_NVM_VERIFY = 0x0c
OPC_NVM_COPY = 0x19
OPC_GET_LBA_STATUS = 0x86

# Command Dword 12
LR = 1 << 31
FUA = 1 << 30
PRACT = 1 << 29
DEAC = 1 << 25
STC = 1 << 24
NSZ = 1 << 23

# the size of a Source Range entry of the Copy descriptor formats 0h to 3h
COPY_RANGE_SIZE = {0: 32, 1: 40, 2: 32, 3: 40}


class IoTestBase(MockTestCase):
    """Namespace 1, with 512 byte logical blocks and no protection
    information"""

    def setUp(self):
        super().setUp()
        self.server.ioctls[NVME_IOCTL_ID] = Reply(status=1)
        self.server.identify[CNS_NS] = id_ns(lbaf=[(0, 9, 0)])

    def send(self, opcode, *args, **kwargs):
        """Run @args, which sends one I/O command @opcode. Returns it."""
        self.assertOk(self.nvme(*args, **kwargs))
        cmd, = self.server.io_cmds(opcode)
        return cmd

    def assertRefused(self, args, message, opcode):
        result = self.nvme(*args)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)
        self.assertEqual(self.server.io_cmds(opcode), [])

    def file(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, 'wb') as f:
            f.write(data)
        return path


class FlushTest(IoTestBase):

    def test_flush(self):
        for device, args, nsid in ((self.ns, [], 1),
                                   (self.ctrl, ['--namespace-id=2'], 2)):
            with self.subTest(device=device):
                self.server.commands.clear()
                cmd = self.send(OPC_NVM_FLUSH, 'flush', device, *args)
                self.assertEqual((cmd.nsid, cmd.data_len), (nsid, 0))

    def test_controller_without_namespace(self):
        self.assertRefused(['flush', self.ctrl],
                           'controller device not supported without',
                           OPC_NVM_FLUSH)


class DsmTest(IoTestBase):

    def test_ranges(self):
        cmd = self.send(OPC_NVM_DSM, 'dsm', self.ns, '--slbs=0,0x123456789',
                        '--blocks=8,16', '--ctx-attrs=1,2', '--ad', '--idw')
        # NR is 0's based; IDR bit 0, IDW bit 1, AD bit 2
        self.assertEqual((cmd.nsid, cmd.cdw10, cmd.cdw11), (1, 1, 6))
        # context attributes, length in logical blocks, starting LBA
        self.assertEqual(cmd.data, struct.pack('<IIQIIQ', 1, 8, 0,
                                               2, 16, 0x123456789))

    def test_cdw11(self):
        cmd = self.send(OPC_NVM_DSM, 'dsm', self.ns, '--slbs=0', '--blocks=1',
                        '--cdw11=7')
        self.assertEqual((cmd.cdw10, cmd.cdw11), (0, 7))

    def test_invalid_ranges(self):
        cases = [
            (['--slbs=0,1', '--blocks=1'], 'No valid range definition'),
            (['--slbs=0', '--blocks=1', '--ctx-attrs=1,2'],
             'No valid range definition'),
            ([], 'No range definition provided'),
        ]
        for args, message in cases:
            with self.subTest(args=args):
                self.assertRefused(['dsm', self.ns, *args], message,
                                   OPC_NVM_DSM)


class WriteZeroesTest(IoTestBase):

    def test_fields(self):
        cmd = self.send(OPC_NVM_WRITE_ZEROES, 'write-zeroes', self.ns,
                        '--start-block=0x123456789', '--block-count=7',
                        '--deac', '--limited-retry', '--force-unit-access',
                        '--prinfo=8', '--dir-type=1', '--dir-spec=5',
                        '--namespace-zeroes')
        self.assertEqual((cmd.nsid, cmd.cdw10, cmd.cdw11),
                         (1, 0x23456789, 0x1))
        # LR, FUA, PRINFO, DEAC, NSZ, DTYPE 22:20, NLB
        self.assertEqual(cmd.cdw12,
                         LR | FUA | PRACT | DEAC | NSZ | 1 << 20 | 7)
        self.assertEqual(cmd.cdw13, 5 << 16)
        self.assertIsNone(cmd.data)

    def test_storage_tag_check(self):
        cmd = self.send(OPC_NVM_WRITE_ZEROES, 'write-zeroes', self.ns,
                        '--storage-tag-check')
        self.assertEqual(cmd.cdw12, STC)

    def test_directive_type(self):
        """DTYPE is 3 bits in Write Zeroes"""
        self.assertRefused(['write-zeroes', self.ns, '--dir-type=8'],
                           'Invalid directive type, 8', OPC_NVM_WRITE_ZEROES)


class WriteUncorTest(IoTestBase):

    def test_fields(self):
        cmd = self.send(OPC_NVM_WRITE_UNCOR, 'write-uncor', self.ns,
                        '--start-block=0x100000001', '--block-count=3',
                        '--dir-type=0xf', '--dir-spec=9')
        # DTYPE 23:20, NLB; DSPEC
        self.assertEqual((cmd.nsid, cmd.cdw10, cmd.cdw11, cmd.cdw12,
                          cmd.cdw13), (1, 1, 1, 0xf << 20 | 3, 9 << 16))

    def test_directive_type(self):
        self.assertRefused(['write-uncor', self.ns, '--dir-type=16'],
                           'Invalid directive type, 10', OPC_NVM_WRITE_UNCOR)


class VerifyTest(IoTestBase):

    def test_fields(self):
        cmd = self.send(OPC_NVM_VERIFY, 'verify', self.ns, '--start-block=8',
                        '--block-count=15', '--limited-retry',
                        '--force-unit-access', '--prinfo=8',
                        '--storage-tag-check')
        self.assertEqual((cmd.nsid, cmd.cdw10, cmd.cdw11), (1, 8, 0))
        self.assertEqual(cmd.cdw12, LR | FUA | PRACT | STC | 15)


class SubmitIoTest(IoTestBase):
    """read, write and compare"""

    def test_write(self):
        data = bytes(range(256)) * 4
        cmd = self.send(OPC_NVM_WRITE, 'write', self.ns, '--start-block=4',
                        '--data-size=1024', f'--data={self.file("d", data)}',
                        '--limited-retry', '--force-unit-access',
                        '--dir-type=2', '--dir-spec=3', '--dsm=0x5')
        # 2 blocks of 512 bytes; NLB is 0's based
        self.assertEqual((cmd.nsid, cmd.cdw10, cmd.cdw12),
                         (1, 4, LR | FUA | 2 << 20 | 1))
        # DSPEC 31:16, DSM 7:0
        self.assertEqual(cmd.cdw13, 3 << 16 | 0x5)
        self.assertEqual(cmd.data, data)

    def test_block_count(self):
        """A block count takes more than the data size"""
        data = b'\xaa' * 512
        cmd = self.send(OPC_NVM_WRITE, 'write', self.ns, '--data-size=512',
                        '--block-count=1', f'--data={self.file("d", data)}')
        self.assertEqual((cmd.cdw12, cmd.data_len), (1, 1024))
        self.assertEqual(cmd.data[:512], data)

    def test_read(self):
        self.server.io[OPC_NVM_READ] = b'R' * 1024
        path = os.path.join(self.tmp, 'out')
        cmd = self.send(OPC_NVM_READ, 'read', self.ns, '--start-block=2',
                        '--data-size=1024', f'--data={path}')
        self.assertEqual((cmd.cdw10, cmd.cdw12, cmd.data_len, cmd.data),
                         (2, 1, 1024, None))
        with open(path, 'rb') as f:
            self.assertEqual(f.read(), b'R' * 1024)

    def test_compare(self):
        data = b'C' * 512
        cmd = self.send(OPC_NVM_COMPARE, 'compare', self.ns,
                        '--data-size=512', f'--data={self.file("d", data)}')
        self.assertEqual((cmd.cdw12, cmd.data), (0, data))

    def test_data_size_required(self):
        self.assertRefused(['read', self.ns], 'data size not provided',
                           OPC_NVM_READ)


class CopyTest(IoTestBase):

    def copy(self, *args):
        return self.send(OPC_NVM_COPY, 'copy', self.ns, '--sdlba=0x123456789',
                         *args)

    def ranges(self, cmd, fmt):
        size = COPY_RANGE_SIZE[fmt]
        self.assertEqual(cmd.data_len % size, 0)
        return [cmd.data[i:i + size] for i in range(0, cmd.data_len, size)]

    def test_fields(self):
        cmd = self.copy('--slbs=0,100', '--blocks=7,15', '--limited-retry',
                        '--force-unit-access', '--prinfor=4', '--prinfow=8',
                        '--dir-type=2', '--dir-spec=5')
        self.assertEqual((cmd.nsid, cmd.cdw10, cmd.cdw11),
                         (1, 0x23456789, 1))
        # LR, FUA, PRINFOW 29:26, DTYPE 23:20, PRINFOR 15:12, DESFMT 11:8,
        # NR 7:0 (0's based)
        self.assertEqual(cmd.cdw12, LR | FUA | 8 << 26 | 2 << 20 | 4 << 12 | 1)
        self.assertEqual(cmd.cdw13, 5 << 16)

    def test_formats(self):
        """The starting LBA, the number of logical blocks (0's based) and,
        for formats 2h and 3h, the source namespace and options of each
        range"""
        for fmt in (0, 1, 2, 3):
            with self.subTest(format=fmt):
                self.server.commands.clear()
                args = ['--slbs=0x10,0x123456789', '--blocks=7,15',
                        f'--format={fmt}']
                if fmt >= 2:
                    args += ['--snsids=1,2', '--sopts=0x8000,0']
                cmd = self.copy(*args)
                self.assertEqual((cmd.cdw12 >> 8) & 0xf, fmt)
                ranges = self.ranges(cmd, fmt)
                self.assertEqual(len(ranges), 2)
                self.assertEqual([struct.unpack_from('<QH', r, 8)
                                  for r in ranges],
                                 [(0x10, 7), (0x123456789, 15)])
                if fmt >= 2:
                    self.assertEqual(
                        [(struct.unpack_from('<I', r)[0],
                          struct.unpack_from('<H', r, 22)[0])
                         for r in ranges], [(1, 0x8000), (2, 0)])

    def test_invalid(self):
        cases = [
            (['--slbs=0', '--blocks=1', '--format=4'], 'invalid format'),
            (['--slbs=0', '--blocks=1', '--format=2'],
             'formats 2 and 3 require source namespace ids'),
            (['--slbs=0', '--blocks=1', '--snsids=1'],
             'formats 0 and 1 do not support cross-namespace copy'),
            ([], 'invalid range'),
        ]
        for args, message in cases:
            with self.subTest(args=args):
                self.assertRefused(['copy', self.ns, *args], message,
                                   OPC_NVM_COPY)


class GetLbaStatusTest(IoTestBase):

    def test_fields(self):
        self.assertOk(self.nvme('get-lba-status', self.ns,
                                '--namespace-id=1',
                                '--start-lba=0x123456789', '--max-dw=7',
                                '--action=2', '--range-len=8'))
        cmd, = self.server.admin_cmds(OPC_GET_LBA_STATUS)
        # SLBA; MNDW (0's based dwords); ATYPE 31:24, RL 15:0
        self.assertEqual((cmd.nsid, cmd.cdw10, cmd.cdw11, cmd.cdw12,
                          cmd.cdw13, cmd.data_len),
                         (1, 0x23456789, 1, 7, 2 << 24 | 8, 32))

    def test_namespace_of_device(self):
        self.assertOk(self.nvme('get-lba-status', self.ns, '--action=2'))
        cmd, = self.server.admin_cmds(OPC_GET_LBA_STATUS)
        self.assertEqual(cmd.nsid, 1)

    def test_action_required(self):
        result = self.nvme('get-lba-status', self.ns, '--namespace-id=1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('action type (--action) has to be given', result.stderr)
        self.assertEqual(self.server.admin_cmds(OPC_GET_LBA_STATUS), [])


if __name__ == '__main__':
    main()
