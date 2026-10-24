#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests virt-mgmt, capacity-mgmt and lockdown: the Virtualization
Management, Capacity Management and Lockdown commands they send (NVM
Express Base Specification 2.4, sections 5.2.31, 5.2.2 and 5.2.15).

Usage: python3 nvme_mgmt_test.py <path-to-nvme-binary> <mock-lib>
"""
from tests.cli.nvme_mock import MockTestCase, Reply, main

OPC_VIRTUAL_MGMT = 0x1c
OPC_CAPACITY_MGMT = 0x20
OPC_LOCKDOWN = 0x24


class MgmtTestBase(MockTestCase):

    def send(self, opcode, *args):
        """Run @args, which sends one command @opcode. Returns it and the
        nvme run."""
        result = self.assertOk(self.nvme(*args))
        cmd, = self.server.admin_cmds(opcode)
        return cmd, result

    def assertRefused(self, opcode, args, message):
        result = self.nvme(*args)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)
        self.assertEqual(self.server.admin_cmds(opcode), [])


class VirtMgmtTest(MgmtTestBase):

    def test_fields(self):
        cmd, _ = self.send(OPC_VIRTUAL_MGMT, 'virt-mgmt', self.ctrl,
                           '--cntlid=0x21', '--rt=1', '--act=8', '--nr=4')
        # ACT 3:0, RT 10:8, CNTLID 31:16; NR 15:0
        self.assertEqual((cmd.cdw10, cmd.cdw11), (8 | 1 << 8 | 0x21 << 16, 4))


class CapacityMgmtTest(MgmtTestBase):

    def test_fields(self):
        cmd, _ = self.send(OPC_CAPACITY_MGMT, 'capacity-mgmt', self.ctrl,
                           '--operation=2', '--element-id=0x12',
                           '--cap-lower=0x89abcdef', '--cap-upper=0x1234')
        # OPER 3:0, ELID 31:16; capacity in CDW11 and CDW12
        self.assertEqual((cmd.cdw10, cmd.cdw11, cmd.cdw12),
                         (2 | 0x12 << 16, 0x89abcdef, 0x1234))

    def test_created_element(self):
        self.server.admin[OPC_CAPACITY_MGMT] = Reply(result=5)
        for operation, element in ((1, 'Endurance Group'), (3, 'NVM Set')):
            with self.subTest(operation=operation):
                self.server.commands.clear()
                _, result = self.send(OPC_CAPACITY_MGMT, 'capacity-mgmt',
                                      self.ctrl, f'--operation={operation}',
                                      '--element-id=1')
                self.assertIn(f'Created Element Identifier for {element} '
                              'is: 5', result.stdout)

    def test_operation(self):
        self.assertRefused(OPC_CAPACITY_MGMT,
                           ['capacity-mgmt', self.ctrl, '--operation=16'],
                           'invalid operation field: 16')
        # required
        self.assertRefused(OPC_CAPACITY_MGMT, ['capacity-mgmt', self.ctrl],
                           'invalid operation field: 255')


class LockdownTest(MgmtTestBase):

    def test_fields(self):
        cmd, _ = self.send(OPC_LOCKDOWN, 'lockdown', self.ctrl, '--ofi=0x10',
                           '--ifc=2', '--prhbt=1', '--scp=2', '--uuid=3',
                           '--csel=1', '--css=0x21')
        # CSEL 19:16, OFI 15:8, IFC 6:5, PRHBT 4, SCP 3:0; CSS 31:16, UIDX
        self.assertEqual((cmd.cdw10, cmd.cdw14),
                         (1 << 16 | 0x10 << 8 | 2 << 5 | 1 << 4 | 2,
                          0x21 << 16 | 3))

    def test_invalid_options(self):
        cases = [
            (['--ifc=4'], 'invalid interface settings:4'),
            (['--prhbt=2'], 'invalid prohibit settings:2'),
            (['--scp=16'], 'invalid scope settings:16'),
            (['--uuid=128'], 'invalid UUID index settings:128'),
            (['--csel=3'], 'invalid controller select settings:3'),
        ]
        for args, message in cases:
            with self.subTest(args=args):
                self.assertRefused(OPC_LOCKDOWN,
                                   ['lockdown', self.ctrl, *args], message)


if __name__ == '__main__':
    main()
