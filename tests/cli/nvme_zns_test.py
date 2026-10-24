#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the Zone Management Send, Zone Management Receive and Zone
Append commands of the zns plugin against the NVM Express Zoned
Namespace Command Set Specification 1.5.

Usage: python3 nvme_zns_test.py <path-to-nvme-binary> <mock-lib>
"""
import os

from tests.cli.nvme_mock import (CNS_CSI_NS, CNS_NS, NVME_IOCTL_ID,
                                 MockTestCase, Reply, id_ns, main)

OPC_ZONE_MGMT_SEND = 0x79
OPC_ZONE_MGMT_RECV = 0x7a
OPC_ZONE_APPEND = 0x7d

# Zone Send Actions
ZSA_CLOSE = 0x01
ZSA_FINISH = 0x02
ZSA_OPEN = 0x03
ZSA_RESET = 0x04
ZSA_OFFLINE = 0x05
ZSA_SET_DESC_EXT = 0x10
ZSA_ZRWA_FLUSH = 0x11

# Command Dword 13 of Zone Management Send
SELECT_ALL = 1 << 8
ZSASO = 1 << 9

# Zone Receive Actions
ZRA_REPORT_ZONES = 0x00
ZRA_EXT_REPORT_ZONES = 0x01

# the LBA Format Extension Data Structures of the Identify Namespace
# data structure of the Zoned Namespace Command Set
ZNS_ID_NS_LBAFE = 2816
ZNS_ID_NS_LBAFE_SIZE = 16
ZNS_ID_NS_SIZE = 4096


def zns_id_ns(zdes=0):
    """A ZNS Identify Namespace data structure whose LBA format 0 has a
    Zone Descriptor Extension Size of @zdes (in 64 byte units)"""
    data = bytearray(ZNS_ID_NS_SIZE)
    data[ZNS_ID_NS_LBAFE + 8] = zdes
    return bytes(data)


class ZnsTestBase(MockTestCase):
    """Namespace 1, with 512 byte logical blocks"""

    def setUp(self):
        super().setUp()
        self.server.ioctls[NVME_IOCTL_ID] = Reply(status=1)
        self.server.identify[CNS_NS] = id_ns(lbaf=[(0, 9, 0)])
        self.server.identify[CNS_CSI_NS] = zns_id_ns()

    def zns_cmds(self, opcode):
        return [c for c in self.server.commands if c.opcode == opcode]

    def zns(self, opcode, *args):
        """Run the zns command @args, which sends one command @opcode.
        Returns it."""
        result = self.nvme('zns', *args)
        if 'invalid sub-command' in result.stderr:
            self.skipTest('zns plugin not built')
        self.assertOk(result)
        self.assertEqual(self.server.admin_cmds(opcode), [])
        cmd, = self.server.io_cmds(opcode)
        return cmd

    def assertRefused(self, args, message, opcode):
        result = self.nvme('zns', *args)
        if 'invalid sub-command' in result.stderr:
            self.skipTest('zns plugin not built')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)
        self.assertEqual(self.zns_cmds(opcode), [])

    def file(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, 'wb') as f:
            f.write(data)
        return path


class ZoneMgmtSendTest(ZnsTestBase):

    def test_actions(self):
        """The zone send action commands: SLBA, Select All and the Zone
        Send Action"""
        for name, zsa in (('close-zone', ZSA_CLOSE),
                          ('finish-zone', ZSA_FINISH),
                          ('reset-zone', ZSA_RESET),
                          ('offline-zone', ZSA_OFFLINE)):
            for select_all in (False, True):
                with self.subTest(name=name, select_all=select_all):
                    self.server.commands.clear()
                    args = ['--start-lba=0x123456789']
                    if select_all:
                        args.append('--select-all')
                    cmd = self.zns(OPC_ZONE_MGMT_SEND, name, self.ns, *args)
                    self.assertEqual((cmd.nsid, cmd.cdw10, cmd.cdw11),
                                     (1, 0x23456789, 1))
                    self.assertEqual(cmd.cdw13,
                                     (SELECT_ALL if select_all else 0) | zsa)
                    self.assertEqual(cmd.data_len, 0)

    def test_namespace_id(self):
        cmd = self.zns(OPC_ZONE_MGMT_SEND, 'reset-zone', self.ctrl,
                       '--namespace-id=2')
        self.assertEqual((cmd.nsid, cmd.cdw13), (2, ZSA_RESET))

    def test_open_zrwaa(self):
        """Open Zone: ZSASO is Zone Random Write Area Allocation"""
        cmd = self.zns(OPC_ZONE_MGMT_SEND, 'open-zone', self.ns,
                       '--start-lba=0x1000', '--zrwaa')
        self.assertEqual((cmd.cdw10, cmd.cdw13), (0x1000, ZSASO | ZSA_OPEN))

    def test_zrwa_flush(self):
        cmd = self.zns(OPC_ZONE_MGMT_SEND, 'zrwa-flush-zone', self.ns,
                       '--lba=0x1007')
        self.assertEqual((cmd.cdw10, cmd.cdw13), (0x1007, ZSA_ZRWA_FLUSH))

    def test_set_zone_desc(self):
        """The Zone Descriptor Extension takes its size from the LBA
        format in use"""
        self.server.identify[CNS_CSI_NS] = zns_id_ns(zdes=2)
        data = bytes(range(128))
        cmd = self.zns(OPC_ZONE_MGMT_SEND, 'set-zone-desc', self.ns,
                       '--start-lba=0x2000', '--zrwaa',
                       f'--data={self.file("desc", data)}')
        self.assertEqual((cmd.cdw10, cmd.cdw13),
                         (0x2000, ZSASO | ZSA_SET_DESC_EXT))
        self.assertEqual(cmd.data, data)

    def test_set_zone_desc_unsupported(self):
        self.assertRefused(['set-zone-desc', self.ns],
                           'zone format does not provide descriptor',
                           OPC_ZONE_MGMT_SEND)

    def test_zone_mgmt_send(self):
        cmd = self.zns(OPC_ZONE_MGMT_SEND, 'zone-mgmt-send', self.ns,
                       f'--zsa={ZSA_FINISH}', '--start-lba=0x3000',
                       '--select-all', '--zsaso')
        self.assertEqual((cmd.cdw10, cmd.cdw13),
                         (0x3000, ZSASO | SELECT_ALL | ZSA_FINISH))

    def test_zone_mgmt_send_desc(self):
        self.server.identify[CNS_CSI_NS] = zns_id_ns(zdes=1)
        data = b'\x5a' * 64
        cmd = self.zns(OPC_ZONE_MGMT_SEND, 'zone-mgmt-send', self.ns,
                       f'--zsa={ZSA_SET_DESC_EXT}',
                       f'--data={self.file("desc", data)}')
        self.assertEqual((cmd.cdw13, cmd.data), (ZSA_SET_DESC_EXT, data))

    def test_zone_mgmt_send_invalid(self):
        cases = [
            ([], 'zone send action must be specified'),
            ([f'--zsa={ZSA_CLOSE}', '--data-len=64'],
             'data, data_len only valid with set extended descriptor'),
            ([f'--zsa={ZSA_SET_DESC_EXT}'],
             'Zone Descriptor Extensions are not supported'),
        ]
        for args, message in cases:
            with self.subTest(args=args):
                self.assertRefused(['zone-mgmt-send', self.ns, *args],
                                   message, OPC_ZONE_MGMT_SEND)


class ZoneMgmtRecvTest(ZnsTestBase):

    def test_fields(self):
        cmd = self.zns(OPC_ZONE_MGMT_RECV, 'zone-mgmt-recv', self.ns,
                       '--start-lba=0x123456789', '--data-len=4096',
                       f'--zra={ZRA_EXT_REPORT_ZONES}', '--zrasf=2',
                       '--partial')
        # NUMD, 0's based; ZRA 7:0, ZRASF 15:8, Partial Report 16
        self.assertEqual((cmd.nsid, cmd.cdw10, cmd.cdw11, cmd.cdw12,
                          cmd.data_len), (1, 0x23456789, 1, 1023, 4096))
        self.assertEqual(cmd.cdw13, 1 << 16 | 2 << 8 | ZRA_EXT_REPORT_ZONES)

    def test_data_len(self):
        """Each Zone Receive Action returns data, NUMD dwords of it (0's
        based)"""
        for zra in (ZRA_REPORT_ZONES, ZRA_EXT_REPORT_ZONES):
            for args in ([], ['--data-len=1'], ['--data-len=2'],
                         ['--data-len=3'], ['--data-len=6']):
                with self.subTest(zra=zra, args=args):
                    self.assertRefused(['zone-mgmt-recv', self.ns,
                                        f'--zra={zra}', *args],
                                       '--data-len must be a non-zero '
                                       'multiple of 4',
                                       OPC_ZONE_MGMT_RECV)


class ZoneAppendTest(ZnsTestBase):

    def test_fields(self):
        data = bytes(range(256)) * 4
        cmd = self.zns(OPC_ZONE_APPEND, 'zone-append', self.ns,
                       '--zslba=0x123456789', '--data-size=1024',
                       f'--data={self.file("d", data)}', '--limited-retry',
                       '--force-unit-access', '--prinfo=8', '--piremap')
        self.assertEqual((cmd.nsid, cmd.cdw10, cmd.cdw11), (1, 0x23456789, 1))
        # LR 31, FUA 30, PRINFO 29:26, PIREMAP 25, NLB 15:0 (0's based)
        self.assertEqual(cmd.cdw12, 1 << 31 | 1 << 30 | 8 << 26 | 1 << 25 | 1)
        self.assertEqual(cmd.data, data)

    def test_metadata(self):
        """The metadata of 1024 blocks, larger than a page"""
        self.server.identify[CNS_NS] = id_ns(lbaf=[(8, 9, 0)])
        data = b'\xa5' * (1024 * 512)
        metadata = bytes(range(256)) * 32
        cmd = self.zns(OPC_ZONE_APPEND, 'zone-append', self.ns,
                       f'--data-size={len(data)}',
                       f'--metadata-size={len(metadata)}',
                       f'--data={self.file("d", data)}',
                       f'--metadata={self.file("m", metadata)}')
        self.assertEqual((cmd.cdw12, cmd.data_len), (1023, len(data)))
        self.assertEqual(cmd.metadata, metadata)

    def test_size_required(self):
        self.assertRefused(['zone-append', self.ns],
                           'Append size not provided', OPC_ZONE_APPEND)

    def test_too_many_blocks(self):
        """NLB counts at most 65536 blocks"""
        self.assertRefused(['zone-append', self.ns,
                            f'--data-size={65537 * 512}'],
                           'exceeds 65536 logical blocks', OPC_ZONE_APPEND)

    def test_invalid_prinfo(self):
        self.assertRefused(['zone-append', self.ns, '--data-size=512',
                            '--prinfo=16'],
                           'Invalid value for prinfo:0x10', OPC_ZONE_APPEND)


if __name__ == '__main__':
    main()
