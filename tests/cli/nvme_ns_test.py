#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the ns plugin: the Namespace Management and Namespace Attachment
commands it sends (NVM Express Base Specification 2.4, sections 5.2.20
and 5.2.21, and the Host Specified Fields of the NVM Command Set
Specification 1.3), and how ns create computes sizes from SI units.

Usage: python3 nvme_ns_test.py <path-to-nvme-binary> <mock-lib>
"""
import struct

from tests.cli.nvme_mock import (CNS_CTRL, CNS_NS, NSID_ALL, NVME_IOCTL_ID,
                                 MockTestCase, Reply, id_ctrl, id_ns, main)

OPC_NS_MGMT = 0x0d
OPC_NS_ATTACH = 0x15
CSI_ZNS = 0x02


def host_specified(data, offset, fmt):
    return struct.unpack_from(fmt, data, offset)[0]


class NsCreateTest(MockTestCase):
    """A controller whose namespaces have the LBA formats 512, 512 + 8,
    4096 and 4096 + 8"""

    def setUp(self):
        super().setUp()
        self.server.identify[CNS_NS] = id_ns(
            lbaf=[(0, 9, 0), (8, 9, 0), (0, 12, 0), (8, 12, 0)])
        self.server.admin[OPC_NS_MGMT] = Reply(result=7)

    def create(self, *args):
        """Run ns create, which sends one Namespace Management. Returns
        it and the nvme run."""
        result = self.assertOk(self.nvme('ns', 'create', self.ctrl,
                                         *args, '--verbose'))
        cmd, = self.server.admin_cmds(OPC_NS_MGMT)
        return cmd, result

    def assertRefused(self, args, message):
        result = self.nvme('ns', 'create', self.ctrl, *args)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)
        self.assertEqual(self.server.admin_cmds(OPC_NS_MGMT), [])

    def test_fields(self):
        cmd, result = self.create(
            '--nsze=0x10000', '--ncap=0x8000', '--flbas=1', '--dps=1',
            '--nmic=1', '--anagrp-id=2', '--nvmset-id=3', '--endg-id=4',
            '--lbstm=0xff00', '--nphndls=2', '--phndls=5,6')
        # SEL 0h: create; CSI in Command Dword 11
        self.assertEqual((cmd.nsid, cmd.cdw10, cmd.cdw11), (0, 0, 0))
        fields = [(0, '<Q', 0x10000), (8, '<Q', 0x8000), (26, 'B', 1),
                  (29, 'B', 1), (30, 'B', 1), (92, '<I', 2),
                  (100, '<H', 3), (102, '<H', 4), (384, '<Q', 0xff00),
                  (392, '<H', 2), (512, '<H', 5), (514, '<H', 6)]
        self.assertEqual(
            [host_specified(cmd.data, o, f) for o, f, _ in fields],
            [v for _, _, v in fields])
        # the namespace ID of the completion
        self.assertIn('nsid', result.stdout)
        self.assertIn('7', result.stdout)

    def test_zoned(self):
        cmd, _ = self.create('--nsze=0x10000', '--ncap=0x10000',
                             '--flbas=0', f'--csi={CSI_ZNS}', '--azr',
                             '--rar=10', '--ror=20', '--rnumzrwa=30')
        self.assertEqual(cmd.cdw11, CSI_ZNS << 24)
        # ZNS Command Set Specification: ZNSCO, RAR, ROR, RNUMZRWA
        self.assertEqual(struct.unpack_from('<BIII', cmd.data, 499),
                         (1, 10, 20, 30))

    def test_zoned_options_need_zns(self):
        self.assertRefused(['--nsze=1', '--ncap=1', '--flbas=0', '--rar=1'],
                           'Invalid ZNS argument')

    def test_placement_handles_mismatch(self):
        self.assertRefused(['--nsze=1', '--ncap=1', '--flbas=0',
                            '--nphndls=2', '--phndls=1'],
                           'Invalid Placement handle list')

    def test_block_size(self):
        """The LBA format of the block size without metadata, from the
        common namespace capabilities"""
        cmd, _ = self.create('--nsze=1', '--ncap=1', '--block-size=4096')
        self.assertEqual(cmd.data[26], 2)
        self.assertEqual([c.nsid for c in self.server.identifies(CNS_NS)],
                         [NSID_ALL])

    def test_lba_format_required(self):
        self.assertRefused(['--nsze=1', '--ncap=1'],
                           'FLBAS corresponding to block size 0 not found')
        self.assertRefused(['--nsze=1', '--ncap=1', '--flbas=0',
                            '--block-size=512'],
                           'Invalid specification of both FLBAS and Block')
        self.assertRefused(['--nsze=1', '--ncap=1', '--block-size=1000'],
                           'Block size must be a power of two')

    def test_si_units_and_logical_blocks(self):
        self.assertRefused(['--nsze=1', '--nsze-si=1G', '--ncap=1',
                            '--flbas=0'],
                           'Invalid specification of both nsze and its SI')


class NsDeleteTest(MockTestCase):

    def test_namespace_id(self):
        for args, nsid in ((['--namespace-id=5'], 5),
                           ([f'--namespace-id={NSID_ALL:#x}'], NSID_ALL)):
            with self.subTest(args=args):
                self.server.commands.clear()
                self.assertOk(self.nvme('ns', 'delete', self.ctrl, *args))
                cmd, = self.server.admin_cmds(OPC_NS_MGMT)
                # SEL 1h: delete
                self.assertEqual((cmd.nsid, cmd.cdw10, cmd.data),
                                 (nsid, 1, None))

    def test_namespace_of_the_device(self):
        self.server.ioctls[NVME_IOCTL_ID] = Reply(status=3)
        self.assertOk(self.nvme('ns', 'delete', self.ns))
        cmd, = self.server.admin_cmds(OPC_NS_MGMT)
        self.assertEqual(cmd.nsid, 3)


class NsAttachTest(MockTestCase):

    def attachments(self):
        return self.server.admin_cmds(OPC_NS_ATTACH)

    def assertControllerList(self, cmd, ids):
        self.assertEqual(cmd.data_len, 4096)
        self.assertEqual(struct.unpack_from(f'<{len(ids) + 1}H', cmd.data),
                         (len(ids), *ids))

    def test_attach_and_detach(self):
        """Without a controller list, the controller of the device"""
        self.server.identify[CNS_CTRL] = id_ctrl(cntlid=0x21)
        for command, sel in (('attach', 0), ('detach', 1)):
            with self.subTest(command=command):
                self.server.commands.clear()
                self.assertOk(self.nvme('ns', command, self.ctrl,
                                        '--namespace-id=2'))
                cmd, = self.attachments()
                self.assertEqual((cmd.nsid, cmd.cdw10), (2, sel))
                self.assertControllerList(cmd, [0x21])

    def test_controller_list(self):
        self.assertOk(self.nvme('ns', 'attach', self.ctrl,
                                '--namespace-id=2', '--controllers=1,2,0x30'))
        cmd, = self.attachments()
        self.assertControllerList(cmd, [1, 2, 0x30])
        self.assertEqual(self.server.identifies(), [])

    def test_invalid(self):
        cases = [
            (self.ctrl, [], 'namespace-id parameter required'),
            (self.ns, ['--namespace-id=1'], 'a namespace device opened'),
            (self.ctrl, ['--namespace-id=1', '--controllers=1,x'],
             'controller id list is malformed'),
        ]
        self.server.ioctls[NVME_IOCTL_ID] = Reply(status=1)
        for device, args, message in cases:
            with self.subTest(args=args):
                result = self.nvme('ns', 'attach', device, *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
        self.assertEqual(self.attachments(), [])


class NsGetIdTest(MockTestCase):

    def test_get_id(self):
        self.server.ioctls[NVME_IOCTL_ID] = Reply(status=3)
        result = self.assertOk(self.nvme('ns', 'get-id', self.ns))
        self.assertIn('namespace-id:3', result.stdout)

    def test_controller(self):
        result = self.nvme('ns', 'get-id', self.ctrl)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('get namespace ID', result.stderr)


if __name__ == '__main__':
    main()
