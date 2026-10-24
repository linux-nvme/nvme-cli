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
against the NVM Express Base Specification 2.4.

Usage: python3 nvme_registers_test.py <path-to-nvme-binary> <mock-lib>
"""
import json
import os
import random
import re
import struct

from tests.cli.nvme_mock import (CTRL_REGS_FIELDS, HAVE_JSON, MockTestCase,
                                 Reply, ctrl_regs, main, write_sysfs_ctrl)

OPC_FABRICS = 0x7f
FCTYPE_PROPERTY_SET = 0x00
FCTYPE_PROPERTY_GET = 0x04
SC_INVALID_FIELD = 0x02
# with the More and Do Not Retry bits, as the Linux target answers
SC_INVALID_FIELD_DNR = 0x6002
SC_INTERNAL = 0x06

REGS = {
    'cap': 0x0000002028030fff,
    'vs': 0x00020000,
    'cc': 0x00460001,
    'csts': 0x00000001,
    'aqa': 0x001f001f,
    'asq': 0x12345000,
    'acq': 0x6789a000,
    'crto': 0x00050003,
    'pmrcap': 0x00000008,
}

ONLY_CTRL = 'Only controller device is allowed'
REG_REQUIRED = 'a register has to be given'

# The fields of the registers, from the figures of section 3.1.4 of the
# specification: (name, low bit, width, format, argument), see
# decode_field(). The C table has to decode the same.
UNITS = ['Bytes', '1 KiB', '1 MiB', '1 GiB']
UNITS_SEC = [u + '/second' for u in UNITS]
RBB = ['May bypass', 'Shall bypass']
ENFORCED = ['Enforced', 'Not Enforced']
SPEC_FIELDS = {
    'cap': [
        ('Maximum Queue Entries Supported (MQES)', 0, 16, 'dec1'),
        ('Contiguous Queues Required (CQR)', 16, 1, 'yesno'),
        ('Weighted Round Robin with Urgent Priority Class (AMS.WRRUPC)',
         17, 1, 'supported'),
        ('Vendor Specific Arbitration (AMS.VS)', 18, 1, 'supported'),
        ('Timeout (TO)', 24, 8, 'ms500'),
        ('Doorbell Stride (DSTRD)', 32, 4, 'pow2', 2),
        ('NVM Subsystem Reset Supported (NSSRS)', 36, 1, 'yesno'),
        ('NVM Command Set Supported (CSS.NCSS)', 37, 1, 'yesno'),
        ('I/O Command Sets Supported (CSS.IOCSS)', 43, 1, 'yesno'),
        ('No I/O Command Set Supported (CSS.NOIOCSS)', 44, 1, 'yesno'),
        ('Boot Partition Support (BPS)', 45, 1, 'yesno'),
        ('Controller Power Scope (CPS)', 46, 2, 'str',
         ['Not Reported', 'Controller scope', 'Domain scope',
          'NVM subsystem scope']),
        ('Memory Page Size Minimum (MPSMIN)', 48, 4, 'pow2', 12),
        ('Memory Page Size Maximum (MPSMAX)', 52, 4, 'pow2', 12),
        ('Persistent Memory Region Supported (PMRS)', 56, 1, 'supported'),
        ('Controller Memory Buffer Supported (CMBS)', 57, 1, 'supported'),
        ('NVM Subsystem Shutdown Supported (NSSS)', 58, 1, 'supported'),
        ('Controller Ready With Media Support (CRWMS)', 59, 1,
         'supported'),
        ('Controller Ready Independent of Media Support (CRIMS)', 60, 1,
         'supported'),
        ('NVM Subsystem Shutdown Enhancements Supported (NSSES)', 61, 1,
         'supported'),
    ],
    'vs': [
        ('Tertiary Version Number (TER)', 0, 8, 'dec'),
        ('Minor Version Number (MNR)', 8, 8, 'dec'),
        ('Major Version Number (MJR)', 16, 16, 'dec'),
    ],
    'intms': [('Interrupt Vector Mask Set (IVMS)', 0, 32, 'hex')],
    'intmc': [('Interrupt Vector Mask Clear (IVMC)', 0, 32, 'hex')],
    'cc': [
        ('Enable (EN)', 0, 1, 'yesno'),
        ('I/O Command Set Selected (CSS)', 4, 3, 'str',
         {0: 'NVM Command Set', 6: 'All supported I/O Command Sets',
          7: 'Admin Command Set only'}),
        ('Memory Page Size (MPS)', 7, 4, 'pow2', 12),
        ('Arbitration Mechanism Selected (AMS)', 11, 3, 'str',
         {0: 'Round Robin',
          1: 'Weighted Round Robin with Urgent Priority Class',
          7: 'Vendor Specific'}),
        ('Shutdown Notification (SHN)', 14, 2, 'str',
         ['No notification; no effect', 'Normal shutdown notification',
          'Abrupt shutdown notification']),
        ('I/O Submission Queue Entry Size (IOSQES)', 16, 4, 'pow2', 0),
        ('I/O Completion Queue Entry Size (IOCQES)', 20, 4, 'pow2', 0),
        ('Controller Ready Independent of Media Enable (CRIME)', 24, 1,
         'enabled'),
    ],
    'csts': [
        ('Ready (RDY)', 0, 1, 'yesno'),
        ('Controller Fatal Status (CFS)', 1, 1, 'yesno'),
        ('Shutdown Status (SHST)', 2, 2, 'str',
         ['Normal operation (no shutdown has been requested)',
          'Shutdown processing occurring', 'Shutdown processing complete']),
        ('NVM Subsystem Reset Occurred (NSSRO)', 4, 1, 'yesno'),
        ('Processing Paused (PP)', 5, 1, 'yesno'),
        ('Shutdown Type (ST)', 6, 1, 'str', ['Controller', 'NVM Subsystem']),
    ],
    'nssr': [('NVM Subsystem Reset Control (NSSRC)', 0, 32, 'hex')],
    'aqa': [
        ('Admin Submission Queue Size (ASQS)', 0, 12, 'dec1'),
        ('Admin Completion Queue Size (ACQS)', 16, 12, 'dec1'),
    ],
    'asq': [('Admin Submission Queue Base (ASQB)', 12, 52, 'addr')],
    'acq': [('Admin Completion Queue Base (ACQB)', 12, 52, 'addr')],
    'cmbloc': [
        ('Base Indicator Register (BIR)', 0, 3, 'hex'),
        ('CMB Queue Mixed Memory Support (CQMMS)', 3, 1, 'str', ENFORCED),
        ('CMB Queue Physically Discontiguous Support (CQPDS)', 4, 1, 'str',
         ENFORCED),
        ('CMB Data Pointer Mixed Locations Support (CDPMLS)', 5, 1, 'str',
         ENFORCED),
        ('CMB Data Pointer and Command Independent Locations Support '
         '(CDPCILS)', 6, 1, 'str', ENFORCED),
        ('CMB Data Metadata Mixed Memory Support (CDMMMS)', 7, 1, 'str',
         ENFORCED),
        ('CMB Queue Dword Alignment (CQDA)', 8, 1, 'yesno'),
        ('Offset (OFST)', 12, 20, 'hex'),
    ],
    'cmbsz': [
        ('Submission Queue Support (SQS)', 0, 1, 'supported'),
        ('Completion Queue Support (CQS)', 1, 1, 'supported'),
        ('PRP SGL List Support (LISTS)', 2, 1, 'supported'),
        ('Read Data Support (RDS)', 3, 1, 'supported'),
        ('Write Data Support (WDS)', 4, 1, 'supported'),
        ('Size Units (SZU)', 8, 4, 'str',
         ['4 KiB', '64 KiB', '1 MiB', '16 MiB', '256 MiB', '4 GiB',
          '64 GiB']),
        ('Size (SZ)', 12, 20, 'dec'),
    ],
    'bpinfo': [
        ('Boot Partition Size (BPSZ)', 0, 15, 'dec'),
        ('Boot Read Status (BRS)', 24, 2, 'str',
         ['No Boot Partition read operation requested',
          'Boot Partition read in progress',
          'Boot Partition read completed successfully',
          'Error completing Boot Partition read']),
        ('Active Boot Partition ID (ABPID)', 31, 1, 'dec'),
    ],
    'bprsel': [
        ('Boot Partition Read Size (BPRSZ)', 0, 10, 'hex'),
        ('Boot Partition Read Offset (BPROF)', 10, 20, 'hex'),
        ('Boot Partition Identifier (BPID)', 31, 1, 'dec'),
    ],
    'bpmbl': [('Boot Partition Memory Buffer Base Address (BMBBA)', 12, 52,
               'addr')],
    'cmbmsc': [
        ('Capabilities Registers Enabled (CRE)', 0, 1, 'enabled'),
        ('Controller Memory Space Enable (CMSE)', 1, 1, 'enabled'),
        ('Controller Base Address (CBA)', 12, 52, 'addr'),
    ],
    'cmbsts': [('Controller Base Address Invalid (CBAI)', 0, 1, 'yesno')],
    'cmbebs': [
        ('CMB Elasticity Buffer Size Units (CMBSZU)', 0, 4, 'str', UNITS),
        ('CMB Read Bypass Behavior (CMBRBB)', 4, 1, 'str', RBB),
        ('CMB Elasticity Buffer Size Base (CMBWBZ)', 8, 24, 'dec'),
    ],
    'cmbswtp': [
        ('CMB Sustained Write Throughput Units (CMBSWTU)', 0, 4, 'str',
         UNITS_SEC),
        ('CMB Sustained Write Throughput (CMBSWTV)', 8, 24, 'dec'),
    ],
    'nssd': [('NVM Subsystem Shutdown Control (NSSC)', 0, 32, 'hex')],
    'crto': [
        ('Controller Ready With Media Timeout (CRWMT)', 0, 16, 'ms500'),
        ('Controller Ready Independent of Media Timeout (CRIMT)', 16, 16,
         'ms500'),
    ],
    'pmrcap': [
        ('Read Data Support (RDS)', 3, 1, 'supported'),
        ('Write Data Support (WDS)', 4, 1, 'supported'),
        ('Base Indicator Register (BIR)', 5, 3, 'hex'),
        ('Persistent Memory Region Time Units (PMRTU)', 8, 2, 'str',
         ['500 milliseconds', 'minutes']),
        ('Persistent Memory Region Write Barrier Mechanisms (PMRWBM)', 10, 4,
         'hex'),
        ('Persistent Memory Region Timeout (PMRTO)', 16, 8, 'dec'),
        ('Controller Memory Space Supported (CMSS)', 24, 1, 'supported'),
    ],
    'pmrctl': [('Enable (EN)', 0, 1, 'enabled')],
    'pmrsts': [
        ('Error (ERR)', 0, 8, 'hex'),
        ('Not Ready (NRDY)', 8, 1, 'yesno'),
        ('Health Status (HSTS)', 9, 3, 'str',
         ['Normal Operation', 'Restore Error', 'Read Only', 'Unreliable']),
        ('Controller Base Address Invalid (CBAI)', 12, 1, 'yesno'),
    ],
    'pmrebs': [
        ('PMR Elasticity Buffer Size Units (PMRSZU)', 0, 4, 'str', UNITS),
        ('PMR Read Bypass Behavior (PMRRBB)', 4, 1, 'str', RBB),
        ('PMR Elasticity Buffer Size Base (PMRWBZ)', 8, 24, 'dec'),
    ],
    'pmrswtp': [
        ('PMR Sustained Write Throughput Units (PMRSWTU)', 0, 4, 'str',
         UNITS_SEC),
        ('PMR Sustained Write Throughput (PMRSWTV)', 8, 24, 'dec'),
    ],
    'pmrmscl': [
        ('Controller Memory Space Enable (CMSE)', 1, 1, 'enabled'),
        ('Controller Base Address (CBA)', 12, 20, 'addr'),
    ],
    'pmrmscu': [('Controller Base Address, upper 32 bits (CBA)', 0, 32,
                 'hex')],
}


def hex_str(value):
    return f'{value:#x}' if value else '0'


def decode_field(field, reg_value):
    """The text of @field of the register value @reg_value"""
    name, low, width, fmt, *arg = field
    v = (reg_value >> low) & ((1 << width) - 1)
    if fmt == 'dec':
        return str(v)
    if fmt == 'dec1':
        return str(v + 1)
    if fmt == 'hex':
        return hex_str(v)
    if fmt == 'addr':
        return hex_str(v << low)
    if fmt == 'yesno':
        return 'Yes' if v else 'No'
    if fmt == 'supported':
        return 'Supported' if v else 'Not Supported'
    if fmt == 'enabled':
        return 'Enabled' if v else 'Disabled'
    if fmt == 'pow2':
        return f'{1 << (arg[0] + v)} bytes'
    if fmt == 'ms500':
        return f'{v * 500} ms'
    if fmt == 'str':
        names = arg[0]
        if isinstance(names, dict):
            return names.get(v, 'Reserved')
        return names[v] if v < len(names) else 'Reserved'
    raise ValueError(fmt)


def value_str(value):
    return hex_str(value)


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

    def assertFails(self, args, message, device=None):
        result = self.nvme(args[0], device or self.ctrl, *args[1:])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)
        return result

    def test_show_regs(self):
        result = self.assertOk(self.nvme('show-regs', self.ctrl))
        for name in CTRL_REGS_FIELDS:
            with self.subTest(name=name):
                value = value_str(REGS.get(name, 0))
                self.assertRegex(result.stdout,
                                 rf'(?m)^{name}\s*: {value}$')
        self.assertNoCommands()

    def test_show_regs_json(self):
        if not HAVE_JSON:
            self.skipTest('built without json-c')
        result = self.assertOk(self.nvme('show-regs', self.ctrl,
                                         '--output-format=json'))
        self.assertEqual(json.loads(result.stdout), self.expected())

    def test_show_regs_json_unsigned(self):
        """Register values are unsigned, also with the top bit set"""
        if not HAVE_JSON:
            self.skipTest('built without json-c')
        regs = {name: (1 << 63 if fmt == '<Q' else 1 << 31) | i
                for i, (name, (fmt, _)) in enumerate(
                    CTRL_REGS_FIELDS.items())}
        self.resource0.write_bytes(ctrl_regs(**regs))
        result = self.assertOk(self.nvme('show-regs', self.ctrl,
                                         '--output-format=json'))
        self.assertEqual(json.loads(result.stdout), regs)

    def test_show_regs_verbose(self):
        """The fields of the registers, decoded"""
        result = self.assertOk(self.nvme('show-regs', self.ctrl,
                                         '--verbose'))
        for field, value in (
                ('Maximum Queue Entries Supported (MQES)', '4096'),
                ('Timeout (TO)', '20000 ms'),
                ('Doorbell Stride (DSTRD)', '4 bytes'),
                ('NVM Command Set Supported (CSS.NCSS)', 'Yes'),
                ('Major Version Number (MJR)', '2'),
                ('Minor Version Number (MNR)', '0'),
                ('I/O Completion Queue Entry Size (IOCQES)', '16 bytes'),
                ('I/O Submission Queue Entry Size (IOSQES)', '64 bytes'),
                ('Enable (EN)', 'Yes'),
                ('Ready (RDY)', 'Yes'),
                ('Admin Completion Queue Size (ACQS)', '32'),
                ('Admin Submission Queue Size (ASQS)', '32'),
                ('Admin Submission Queue Base (ASQB)', '0x12345000'),
                ('Controller Ready Independent of Media Timeout (CRIMT)',
                 '2500 ms'),
                ('Controller Ready With Media Timeout (CRWMT)', '1500 ms'),
                ('Read Data Support (RDS)', 'Supported')):
            with self.subTest(field=field):
                self.assertRegex(result.stdout,
                                 rf'(?m)^{re.escape(field)}\s*: '
                                 rf'{re.escape(value)}$')

    def test_fields(self):
        """Each field of each register, against the fields of the
        specification, for random values"""
        if not HAVE_JSON:
            self.skipTest('built without json-c')
        rng = random.Random(4096)
        for round in range(4):
            regs = {}
            for name, (fmt, _) in CTRL_REGS_FIELDS.items():
                bits = 64 if fmt == '<Q' else 32
                regs[name] = (0 if round == 0 else
                              (1 << bits) - 1 if round == 1 else
                              rng.getrandbits(bits))
            self.resource0.write_bytes(ctrl_regs(**regs))
            result = self.assertOk(self.nvme('show-regs', self.ctrl,
                                             '--verbose',
                                             '--output-format=json'))
            doc = json.loads(result.stdout)
            for name, value in regs.items():
                expected = {'value': value}
                for field in SPEC_FIELDS[name]:
                    expected[field[0]] = decode_field(field, value)
                with self.subTest(round=round, name=name):
                    self.assertEqual(doc[name], expected)

    def test_namespace_refused(self):
        for args in (['show-regs'], ['get-reg', '--cap'],
                     ['set-reg', '--cc=0']):
            with self.subTest(args=args):
                self.assertFails(args, ONLY_CTRL, device=self.ns)
        self.assertEqual(self.regs()['cc'], REGS['cc'])

    def test_get_reg(self):
        for args in (['--offset=0x14'], ['--cc']):
            with self.subTest(args=args):
                result = self.assertOk(self.nvme('get-reg', self.ctrl,
                                                 *args))
                self.assertEqual(result.stdout.strip(),
                                 'register : 0x14 (Controller Configuration), '
                                 'value: 0x460001')
        self.assertNoCommands()

    def test_get_reg_names(self):
        """The registers of the options, in register order"""
        for args in (['--pmrcap', '--csts', '--cap'],
                     ['--pmrcap', '--csts', '--offset=0']):
            with self.subTest(args=args):
                result = self.assertOk(self.nvme('get-reg', self.ctrl,
                                                 *args))
                self.assertEqual(
                    re.findall(r'register : (\w+) .*value: (\w+)',
                               result.stdout),
                    [('0000', '0x2028030fff'), ('0x1c', '0x1'),
                     ('0xe00', '0x8')])

    def test_get_reg_json(self):
        """The same as show-regs, for the registers asked for"""
        if not HAVE_JSON:
            self.skipTest('built without json-c')
        result = self.assertOk(self.nvme('get-reg', self.ctrl,
                                         '--cc', '--csts',
                                         '--output-format=json'))
        self.assertEqual(json.loads(result.stdout),
                         {'cc': REGS['cc'], 'csts': REGS['csts']})
        result = self.assertOk(self.nvme('get-reg', self.ctrl,
                                         '--crto', '--verbose',
                                         '--output-format=json'))
        self.assertEqual(json.loads(result.stdout), {'crto': {
            'value': REGS['crto'],
            'Controller Ready Independent of Media Timeout (CRIMT)':
            '2500 ms',
            'Controller Ready With Media Timeout (CRWMT)': '1500 ms'}})

    def test_get_reg_invalid_offset(self):
        """Only the offset of a register, which is in the page read"""
        for offset in ('0x2', '0x18', '0x70', '0xffc', '0x1000', '0x2000'):
            with self.subTest(offset=offset):
                result = self.assertFails(['get-reg', f'--offset={offset}'],
                                          'invalid register offset: '
                                          f'{offset}')
                self.assertNotIn('AddressSanitizer', result.stderr)

    def test_get_reg_required(self):
        self.assertFails(['get-reg'], REG_REQUIRED)

    def test_set_reg(self):
        for args in (['--offset=0x14'],):
            with self.subTest(args=args):
                self.resource0.write_bytes(ctrl_regs(**REGS))
                result = self.assertOk(self.nvme('set-reg', self.ctrl, *args,
                                                 '--value=0x460000'))
                self.assertIn('set-register: 0x14 (Controller '
                              'Configuration), value: 0x460000',
                              result.stdout)
                self.assertEqual(self.regs(), self.expected(cc=0x460000))
        self.assertNoCommands()

    def test_set_reg_names(self):
        """An option with the value for each register the host may
        write"""
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
        for args, message in (
                (['--offset=0x14'], 'value required param'),
                (['--offset=0x14', '--value=1', '--cc=2'],
                 'offset duplicated param'),
                (['--offset=0', '--value=1'], 'register cap is read only'),
                (['--offset=0x18', '--value=1'],
                 'invalid register offset: 0x18'),
                (['--offset=0x14', '--value=0x100000000'],
                 'value 0x100000000 too large for cc'),
                ([], REG_REQUIRED)):
            with self.subTest(args=args):
                self.assertFails(['set-reg', *args], message)
        self.assertEqual(self.regs(), self.expected())


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
                return SC_INVALID_FIELD_DNR
            return Reply(result=self.props[cmd.cdw11])
        return Reply()

    def property_cmds(self, fctype):
        return [cmd for cmd in self.server.admin_cmds(OPC_FABRICS)
                if cmd.nsid == fctype]

    def assertFails(self, args, message):
        result = self.nvme(args[0], self.ctrl, *args[1:])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)
        return result

    def test_show_regs(self):
        """The properties of a fabrics controller: CAP, VS, CC, CSTS, CRTO
        and the optional NSSR and NSSD, which the controller doesn't
        implement"""
        result = self.assertOk(self.nvme('show-regs', self.ctrl))
        # ATTRIB (size: 0 for 4 bytes, 1 for 8 bytes); OFST
        self.assertEqual([(c.cdw10, c.cdw11) for c in
                          self.property_cmds(FCTYPE_PROPERTY_GET)],
                         [(1, 0x00), (0, 0x08), (0, 0x14), (0, 0x1c),
                          (0, 0x20), (0, 0x64), (0, 0x68)])
        for name in ('cap', 'vs', 'cc', 'csts', 'crto'):
            with self.subTest(name=name):
                self.assertRegex(result.stdout,
                                 rf'(?m)^{name}\s*: {value_str(REGS[name])}$')
        self.assertNotRegex(result.stdout, r'(?m)^nss[rd]')

    def test_show_regs_no_crto(self):
        """A Discovery Controller, or one before NVMe 2.0, has no CRTO"""
        del self.props[CTRL_REGS_FIELDS['crto'][1]]
        result = self.assertOk(self.nvme('show-regs', self.ctrl))
        self.assertRegex(result.stdout, r'(?m)^cap\s*: 0x2028030fff$')
        self.assertNotRegex(result.stdout, r'(?m)^crto')

    def test_show_regs_json(self):
        """Only the properties the controller implements"""
        if not HAVE_JSON:
            self.skipTest('built without json-c')
        result = self.assertOk(self.nvme('show-regs', self.ctrl,
                                         '--output-format=json'))
        self.assertEqual(json.loads(result.stdout),
                         {name: REGS[name]
                          for name in ('cap', 'vs', 'cc', 'csts', 'crto')})

    def test_get_property(self):
        for offset in ('0',):
            with self.subTest(offset=offset):
                self.server.commands.clear()
                result = self.assertOk(self.nvme('get-property', self.ctrl,
                                                 f'--offset={offset}'))
                cmd, = self.property_cmds(FCTYPE_PROPERTY_GET)
                self.assertEqual((cmd.cdw10, cmd.cdw11), (1, 0))
                self.assertEqual(result.stdout.strip(),
                                 'property : 0000 (Controller Capabilities), '
                                 'value: 0x2028030fff')

    def test_get_property_json(self):
        """The same as show-regs, for the property asked for, also one
        out of the register table"""
        if not HAVE_JSON:
            self.skipTest('built without json-c')
        result = self.assertOk(self.nvme('get-property', self.ctrl,
                                         '--offset=0x14',
                                         '--output-format=json'))
        self.assertEqual(json.loads(result.stdout), {'cc': REGS['cc']})
        self.props[0x1000] = 0x1234
        result = self.assertOk(self.nvme('get-property', self.ctrl,
                                         '--offset=0x1000',
                                         '--output-format=json'))
        self.assertEqual(json.loads(result.stdout), {'0x1000': 0x1234})

    def test_all_ones(self):
        """All ones is a value as well: a CRTO with both timeouts at
        their maximum"""
        self.props[CTRL_REGS_FIELDS['crto'][1]] = 0xffffffff
        result = self.assertOk(self.nvme('show-regs', self.ctrl))
        self.assertRegex(result.stdout, r'(?m)^crto\s*: 0xffffffff$')
        if HAVE_JSON:
            result = self.assertOk(self.nvme('show-regs', self.ctrl,
                                             '--output-format=json'))
            self.assertEqual(json.loads(result.stdout)['crto'], 0xffffffff)
        result = self.assertOk(self.nvme('get-reg', self.ctrl, '--crto'))
        self.assertIn('value: 0xffffffff', result.stdout)

    def test_show_regs_error(self):
        """Only Invalid Field means a property is not implemented"""
        self.server.admin[OPC_FABRICS] = (
            lambda cmd: SC_INTERNAL if cmd.cdw11 == 0x20 else
            self.property_cmd(cmd))
        self.assertFails(['show-regs'], 'Internal Error')

    def test_not_implemented(self):
        """get-reg and get-property fail for a property the controller
        doesn't implement, with or without the DNR bit"""
        for status in (SC_INVALID_FIELD, SC_INVALID_FIELD_DNR):
            self.server.admin[OPC_FABRICS] = (
                lambda cmd, status=status: status if cmd.cdw11 == 0x68 else
                self.property_cmd(cmd))
            for args, message in (
                    (['get-reg', '--cap', '--crto'],
                     'register: 0x68 (Controller Ready Timeouts) not '
                     'implemented'),
                    (['get-property', '--offset=0x68'],
                     'Invalid Field in Command')):
                with self.subTest(status=status, args=args):
                    result = self.assertFails(args, message)
                    self.assertNotIn('0xffffffff', result.stdout)
                    if 'get-reg' in args:
                        self.assertIn('value: 0x2028030fff', result.stdout)

    def test_get_property_offset_required(self):
        self.assertFails(['get-property'], 'offset required param')
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

    def test_get_reg_crto(self):
        result = self.assertOk(self.nvme('get-reg', self.ctrl, '--crto'))
        cmd, = self.property_cmds(FCTYPE_PROPERTY_GET)
        self.assertEqual((cmd.cdw10, cmd.cdw11), (0, 0x68))
        self.assertIn('value: 0x50003', result.stdout)

    def test_get_reg_not_property(self):
        """A register which is no property of a fabrics controller fails
        get-reg, after the properties"""
        for args in (['--offset=0xe00'], ['--cap', '--pmrcap']):
            with self.subTest(args=args):
                result = self.assertFails(['get-reg', *args],
                                          'register: 0xe00 (Persistent '
                                          'Memory Region Capabilities) not '
                                          'fabrics')
                if '--cap' in args:
                    self.assertIn('value: 0x2028030fff', result.stdout)

    def test_get_reg_error(self):
        """A failed Property Get with its status"""
        self.server.admin[OPC_FABRICS] = (
            lambda cmd: SC_INTERNAL if cmd.cdw11 == 0 else
            self.property_cmd(cmd))
        self.assertFails(['get-reg', '--cap'], 'Internal Error')

    def test_set_property(self):
        """ATTRIB gives the size of the property at OFST, the value is in
        Command Dwords 12 and 13"""
        for offset, value, attrib in (('0x14', 0x460000, 0),
                                      ('0x28', 0x1122334455667000, 1)):
            with self.subTest(offset=offset):
                self.server.commands.clear()
                result = self.assertOk(self.nvme('set-property', self.ctrl,
                                                 f'--offset={offset}',
                                                 f'--value={value:#x}'))
                self.assertIn(f'value: {value:#x}', result.stdout)
                cmd, = self.property_cmds(FCTYPE_PROPERTY_SET)
                self.assertEqual((cmd.cdw10, cmd.cdw11, cmd.cdw12,
                                  cmd.cdw13),
                                 (attrib, int(offset, 16), value & 0xffffffff,
                                  value >> 32))

    def test_set_property_invalid(self):
        for args, message in (([], 'offset required param'),
                              (['--offset=0x14'], 'value required param')):
            with self.subTest(args=args):
                self.assertFails(['set-property', *args], message)
        self.assertEqual(self.server.commands, [])

    def test_set_reg(self):
        """Without resource0, set-reg sets the property"""
        for args in (['--offset=0x14', '--value=0x460000'],
                     ['--cc=0x460000']):
            with self.subTest(args=args):
                self.server.commands.clear()
                self.assertOk(self.nvme('set-reg', self.ctrl, *args))
                cmd, = self.property_cmds(FCTYPE_PROPERTY_SET)
                self.assertEqual((cmd.cdw10, cmd.cdw11, cmd.cdw12,
                                  cmd.cdw13), (0, 0x14, 0x460000, 0))

    def test_set_reg_not_property(self):
        """A register which is no property can't be set without
        resource0"""
        self.assertFails(['set-reg', '--offset=0x24', '--value=1'],
                         'register: 0x24 (Admin Queue Attributes) not '
                         'fabrics')
        self.assertEqual(self.property_cmds(FCTYPE_PROPERTY_SET), [])


if __name__ == '__main__':
    main()
