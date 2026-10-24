#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests show-regs, get-reg, set-reg, get-property and set-property.

On a PCIe controller they map the registers from resource0 of the PCI
device, a regular file in the fake sysfs tree here. On a fabrics
controller they send Property Get and Property Set commands, checked
against the NVM Express Base Specification 2.3.

Usage: python3 nvme_registers_test.py <path-to-nvme-binary> <mock-lib>
"""
import json
import os
import re
import struct

from tests.cli.nvme_mock import (CTRL_REGS_FIELDS, HAVE_JSON, MockTestCase,
                                 Reply, ctrl_regs, main, write_sysfs_ctrl)

OPC_FABRICS = 0x7f
FCTYPE_PROPERTY_SET = 0x00
FCTYPE_PROPERTY_GET = 0x04
SC_INVALID_FIELD = 0x02
SC_INTERNAL = 0x06

REGS = {
    'cap': 0x0000002028030fff,
    'vs': 0x00020000,
    'cc': 0x00460001,
    'csts': 0x00000001,
    'aqa': 0x001f001f,
    'asq': 0x12345000,
    'acq': 0x6789a000,
    'crto': 0x00040002,
    'pmrcap': 0x00000008,
}

# the names show-regs prints, where they differ from CTRL_REGS_FIELDS
SHOW_NAMES = {'vs': 'version'}

ONLY_CTRL = 'Only controller device is allowed'


def value_str(value):
    return f'{value:#x}' if value else '0'


class PcieRegsTest(MockTestCase):
    """A PCIe controller with the registers REGS"""

    def setUp(self):
        super().setUp()
        if os.environ.get('NVME_PRIVSEP_TEST_HELPER'):
            # It maps resource0 of the real sysfs tree, not of the fake one.
            self.skipTest('the privsep helper maps the registers')
        self.resource0 = self.write_sysfs_pci_ctrl(
            resource0=ctrl_regs(**REGS))

    def regs(self):
        """The registers in resource0"""
        data = self.resource0.read_bytes()
        return {name: struct.unpack_from(fmt, data, offset)[0]
                for name, (fmt, offset) in CTRL_REGS_FIELDS.items()}

    def expected(self, **changes):
        """REGS, with @changes"""
        regs = {name: REGS.get(name, 0) for name in CTRL_REGS_FIELDS}
        return {**regs, **changes}

    def assertNoCommands(self):
        self.assertEqual(self.server.commands, [])

    def test_show_regs(self):
        result = self.assertOk(self.nvme('show-regs', self.ctrl))
        for name in CTRL_REGS_FIELDS:
            with self.subTest(name=name):
                show = SHOW_NAMES.get(name, name)
                value = value_str(REGS.get(name, 0))
                self.assertRegex(result.stdout,
                                 rf'(?m)^{show}\s*: {value}$')
        self.assertNoCommands()

    def test_show_regs_json(self):
        if not HAVE_JSON:
            self.skipTest('built without json-c')
        result = self.assertOk(self.nvme('show-regs', self.ctrl,
                                         '--output-format=json'))
        expected = {name: REGS.get(name, 0) for name in CTRL_REGS_FIELDS}
        self.assertEqual(json.loads(result.stdout), expected)

    def test_show_regs_verbose(self):
        """The fields of the registers, decoded"""
        result = self.assertOk(self.nvme('show-regs', self.ctrl,
                                         '--verbose'))
        for field, value in (
                ('Maximum Queue Entries Supported (MQES)', '4096'),
                ('Timeout (TO)', '20000 ms'),
                ('Doorbell Stride (DSTRD)', '4 bytes'),
                ('Command Sets Supported (CSS)',
                 'NVM command set is Supported'),
                ('', 'NVMe specification 2.0.0'),
                ('I/O Completion Queue Entry Size (IOCQES)', '16 bytes'),
                ('I/O Submission Queue Entry Size (IOSQES)', '64 bytes'),
                ('Enable (EN)', 'Yes'),
                ('Ready (RDY)', 'Yes'),
                ('Admin Completion Queue Size (ACQS)', '32'),
                ('Admin Submission Queue Size (ASQS)', '32'),
                ('CRIMT', '2 secs'),
                ('CRWMT', '1 secs'),
                ('Read Data Support (RDS)',
                 'Read data from the PMR is supported')):
            with self.subTest(field=field):
                self.assertRegex(result.stdout,
                                 rf'(?m)^{re.escape(field)}\s*: '
                                 rf'{re.escape(value)}$')

    def test_namespace_refused(self):
        for args in (['show-regs'], ['get-reg', '--cap'],
                     ['set-reg', '--cc=0']):
            with self.subTest(args=args):
                result = self.nvme(args[0], self.ns, *args[1:])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(ONLY_CTRL, result.stderr)
        self.assertEqual(self.regs()['cc'], REGS['cc'])

    def test_get_reg(self):
        result = self.assertOk(self.nvme('get-reg', self.ctrl,
                                         '--offset=0x14'))
        self.assertEqual(result.stdout.strip(),
                         'register : 0x14 (Controller Configuration), '
                         'value: 0x460001')
        self.assertNoCommands()

    def test_get_reg_names(self):
        """The registers of the named options, in register order"""
        result = self.assertOk(self.nvme('get-reg', self.ctrl, '--pmrcap',
                                         '--csts', '--cap'))
        self.assertEqual(re.findall(r'register : (\w+) .*value: (\w+)',
                                    result.stdout),
                         [('0000', '0x2028030fff'), ('0x1c', '0x1'),
                          ('0xe00', '0x8')])

    def test_get_reg_invalid_offset(self):
        """Only the offset of a register, which is in the page read"""
        for offset in ('0x2', '0x18', '0x70', '0xffc', '0x1000', '0x2000'):
            with self.subTest(offset=offset):
                result = self.nvme('get-reg', self.ctrl,
                                   f'--offset={offset}')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'invalid register offset: {offset}',
                              result.stderr)
                self.assertNotIn('AddressSanitizer', result.stderr)

    def test_get_reg_offset_required(self):
        result = self.nvme('get-reg', self.ctrl)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('offset required param', result.stderr)

    def test_set_reg(self):
        result = self.assertOk(self.nvme('set-reg', self.ctrl,
                                         '--offset=0x14',
                                         '--value=0x460000'))
        self.assertIn('set-register: 0x14 (Controller Configuration), '
                      'value: 0x460000', result.stdout)
        self.assertEqual(self.regs(), self.expected(cc=0x460000))
        self.assertNoCommands()

    def test_set_reg_names(self):
        self.assertOk(self.nvme('set-reg', self.ctrl, '--intms=5',
                                '--cc=0x460000', '--aqa=0x70007',
                                '--pmrctl=1'))
        self.assertEqual(self.regs(),
                         self.expected(intms=5, cc=0x460000, aqa=0x70007,
                                       pmrctl=1))
        self.assertNoCommands()

    def test_set_reg_64bit(self):
        """A 64 bit register, written as one or as two 32 bit accesses"""
        for args in ([], ['--mmio32']):
            with self.subTest(args=args):
                self.assertOk(self.nvme('set-reg', self.ctrl,
                                        '--offset=0x28',
                                        '--value=0x1122334455667000',
                                        *args))
                self.assertOk(self.nvme('set-reg', self.ctrl,
                                        '--acq=0x8877665544332000', *args))
                self.assertEqual(self.regs(),
                                 self.expected(asq=0x1122334455667000,
                                               acq=0x8877665544332000))
                self.resource0.write_bytes(ctrl_regs(**REGS))
        self.assertNoCommands()

    def test_set_reg_invalid(self):
        for args, message in ((['--offset=0x14'], 'value required param'),
                              (['--offset=0x14', '--value=1', '--cc=2'],
                               'offset duplicated param')):
            with self.subTest(args=args):
                result = self.nvme('set-reg', self.ctrl, *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
        self.assertEqual(self.regs()['cc'], REGS['cc'])


class FabricsRegsTest(MockTestCase):
    """A fabrics controller, whose properties are REGS"""

    def setUp(self):
        super().setUp()
        write_sysfs_ctrl(self.sysfs_dir, 0, 'tcp',
                         'traddr=192.168.1.1,trsvcid=4420')
        self.props = {CTRL_REGS_FIELDS[name][1]: value
                      for name, value in REGS.items()}
        self.server.admin[OPC_FABRICS] = self.property_cmd

    def property_cmd(self, cmd):
        if cmd.nsid == FCTYPE_PROPERTY_GET:
            if cmd.cdw11 not in self.props:
                return SC_INVALID_FIELD
            return Reply(result=self.props[cmd.cdw11])
        return Reply()

    def property_cmds(self, fctype):
        return [cmd for cmd in self.server.admin_cmds(OPC_FABRICS)
                if cmd.nsid == fctype]

    def test_show_regs(self):
        """The properties of a fabrics controller: CAP, VS, CC, CSTS and
        the optional NSSR, which the controller doesn't implement"""
        result = self.assertOk(self.nvme('show-regs', self.ctrl))
        # ATTRIB (size: 0 for 4 bytes, 1 for 8 bytes); OFST
        self.assertEqual([(c.cdw10, c.cdw11) for c in
                          self.property_cmds(FCTYPE_PROPERTY_GET)],
                         [(1, 0x00), (0, 0x08), (0, 0x14), (0, 0x1c),
                          (0, 0x20)])
        for name in ('cap', 'vs', 'cc', 'csts'):
            with self.subTest(name=name):
                show = SHOW_NAMES.get(name, name)
                self.assertRegex(result.stdout,
                                 rf'(?m)^{show}\s*: {value_str(REGS[name])}$')

    def test_get_property(self):
        result = self.assertOk(self.nvme('get-property', self.ctrl,
                                         '--offset=0'))
        cmd, = self.property_cmds(FCTYPE_PROPERTY_GET)
        self.assertEqual((cmd.cdw10, cmd.cdw11), (1, 0))
        self.assertEqual(result.stdout.strip(),
                         'property : 0000 (Controller Capabilities), '
                         'value: 0x2028030fff')

    def test_get_property_offset_required(self):
        result = self.nvme('get-property', self.ctrl)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('offset required param', result.stderr)
        self.assertEqual(self.server.commands, [])

    def test_get_reg(self):
        result = self.assertOk(self.nvme('get-reg', self.ctrl, '--cap',
                                         '--cc'))
        self.assertEqual([(c.cdw10, c.cdw11) for c in
                          self.property_cmds(FCTYPE_PROPERTY_GET)],
                         [(1, 0x00), (0, 0x14)])
        self.assertEqual(re.findall(r'register : (\w+) .*value: (\w+)',
                                    result.stdout),
                         [('0000', '0x2028030fff'), ('0x14', '0x460001')])

    def test_get_reg_not_property(self):
        """A register which is no property of a fabrics controller fails
        get-reg, after the properties"""
        for args in (['--offset=0xe00'], ['--cap', '--pmrcap']):
            with self.subTest(args=args):
                result = self.nvme('get-reg', self.ctrl, *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('register: 0xe00 (Persistent Memory Region '
                              'Capabilities) not fabrics', result.stderr)
                if '--cap' in args:
                    self.assertIn('value: 0x2028030fff', result.stdout)

    def test_get_reg_error(self):
        """A failed Property Get with its status"""
        self.server.admin[OPC_FABRICS] = (
            lambda cmd: SC_INTERNAL if cmd.cdw11 == 0 else
            self.property_cmd(cmd))
        result = self.nvme('get-reg', self.ctrl, '--cap')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Internal Error', result.stderr)

    def test_set_property(self):
        """ATTRIB gives the size of the property at OFST, the value is in
        Command Dwords 12 and 13"""
        for offset, value, attrib in ((0x14, 0x460000, 0),
                                      (0x28, 0x1122334455667000, 1)):
            with self.subTest(offset=offset):
                self.server.commands.clear()
                result = self.assertOk(self.nvme('set-property', self.ctrl,
                                                 f'--offset={offset:#x}',
                                                 f'--value={value:#x}'))
                self.assertIn(f'value: {value:#x}', result.stdout)
                cmd, = self.property_cmds(FCTYPE_PROPERTY_SET)
                self.assertEqual((cmd.cdw10, cmd.cdw11, cmd.cdw12,
                                  cmd.cdw13),
                                 (attrib, offset, value & 0xffffffff,
                                  value >> 32))

    def test_set_property_invalid(self):
        for args, message in (([], 'offset required param'),
                              (['--offset=0x14'], 'value required param')):
            with self.subTest(args=args):
                result = self.nvme('set-property', self.ctrl, *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
        self.assertEqual(self.server.commands, [])

    def test_set_reg(self):
        """Without resource0, set-reg sets the property"""
        self.assertOk(self.nvme('set-reg', self.ctrl, '--cc=0x460000'))
        cmd, = self.property_cmds(FCTYPE_PROPERTY_SET)
        self.assertEqual((cmd.cdw10, cmd.cdw11, cmd.cdw12, cmd.cdw13),
                         (0, 0x14, 0x460000, 0))


if __name__ == '__main__':
    main()
