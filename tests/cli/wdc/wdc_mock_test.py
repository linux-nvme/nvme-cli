#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the commands of the wdc plugin against mocked controllers of
several models: each command gets past the checks of the model, the UUID
list and the log pages, and decodes the log it reads.

The mocked controller reports the WDC UUID in its UUID list, all vendor
specific log pages in its Supported Log Pages log, a C2 Device
Management log with the entries the plugin looks up, and each log page
the commands read with the GUID and version the plugin checks. The data
behind those headers is zero or a simple pattern: the tests show that a
command decodes its log, not what it prints.

The runs also seed the fuzz target with valid device data (see
nvme-fuzz seeds), where fuzzed data rarely gets past these checks.

Usage: python3 wdc_mock_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
import struct

from tests.cli.nvme_mock import (CNS_CTRL, CNS_UUID_LIST, CTRATT_UUID_LIST,
                                 HAVE_JSON, MockController, MockTestCase,
                                 id_ctrl, main, uuid_list)

WDC_UUID = bytes.fromhex('2db98c520c4c5a15abe633299a70dfd0')

# The GUIDs the plugin checks the log pages for
GUID_OCP_C0 = bytes.fromhex('c5af1028eabff2a49c4f6f7cc914d5af')
GUID_EXT_SMART_C0 = bytes.fromhex('65438878acd878a166421e0f92d76dc4')
GUID_C1 = bytes.fromhex('44d93121fe3034aeab4dfd3dba83195a')
GUID_FW_ACT_HISTORY_C2 = bytes.fromhex('6d799a76b4daf6a3e24db28aacf31cd1')
GUID_C3 = bytes.fromhex('927ac08cd0846c9c7043e6d4585ed485')
GUID_C4 = bytes.fromhex('9742050dd1e1c9985d49584b913c05b7')
GUID_C5 = bytes.fromhex('2f729c0e99232cbb634832d0b798bbc7')
GUID_HW_REV_C6 = bytes.fromhex('aab005f5135e4815ab8905ba8be2bf3c')

# The entries of the C2 Device Management log the plugin looks up
C2_MARKETING_NAME = 0x07
C2_LOG_PAGES_SUPPORTED = 0x08
C2_CUSTOMER_ID = 0x15
C2_STATUS_ENTRIES = (0x18, 0x19, 0x1a, 0x1c, 0x1d, 0x1e)


def ocp_log(size, guid, version=1):
    """A log page with the version and GUID at its end, as the OCP style
    log pages have them."""
    log = bytearray(size)
    struct.pack_into('<H', log, size - 18, version)
    log[size - 16:] = guid
    return log


def c2_device_management_log():
    entries = [(C2_CUSTOMER_ID, struct.pack('<I', 0x1005)),
               (C2_LOG_PAGES_SUPPORTED, bytes(range(0xc0, 0x100))),
               (C2_MARKETING_NAME, b'WD Mock SSD'.ljust(16))]
    entries += [(e, struct.pack('<I', 0)) for e in C2_STATUS_ENTRIES]
    body = b''
    for entry_id, data in entries:
        payload = struct.pack('<I', len(data)) + data
        body += struct.pack('<II', 8 + len(payload), entry_id) + payload
    return struct.pack('<II', 8 + len(body), 1) + body


def fw_activate_history_log():
    log = ocp_log(4096, GUID_FW_ACT_HISTORY_C2)
    log[0] = 0xc2
    struct.pack_into('<I', log, 4, 2)
    for i in range(2):
        entry = 8 + 64 * i
        struct.pack_into('<BBHHQ', log, entry, 1, 64, 0, i + 1,
                         1000 * (i + 1))
        struct.pack_into('<QQQBBH', log, entry + 22, 10 + i,
                         int.from_bytes(b'FW100'.ljust(8), 'little'),
                         int.from_bytes(b'FW200'.ljust(8), 'little'),
                         1, 1, 0)
    return log


def ocp_c0_log():
    """The C0 log of an OCP drive. The SN861 has the entries of its
    customer unique SMART log, field IDs 0x0 to 0xC, in front."""
    log = ocp_log(512, GUID_OCP_C0, 3)
    for i in range(13):
        struct.pack_into('<B2xB8s', log, 12 * i, i, 100,
                         struct.pack('<Q', (i + 1) << 8))
    return log


def smart_log():
    log = bytearray(512)
    struct.pack_into('<H', log, 1, 310)                 # temperature
    struct.pack_into('<Q', log, 32, 2000)               # data units read
    struct.pack_into('<Q', log, 48, 1000)               # data units written
    return log


def supported_log_pages():
    """Every vendor specific log page is supported"""
    supported = bytearray(1024)
    for vendor_lid in range(0xc0, 0x100):
        struct.pack_into('<I', supported, vendor_lid * 4, 1)
    return supported


def c2_log(cmd):
    """Two logs share the ID: the WDC UUID selects the Device Management
    log"""
    if cmd.uuid_index:
        return c2_device_management_log()[cmd.lpo:]
    return fw_activate_history_log()[cmd.lpo:]


class WdcController(MockController):
    """A WDC controller with the WDC UUID and the vendor specific log
    pages the commands read, but for C0, which depends on the model."""

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.identify[CNS_UUID_LIST] = uuid_list(WDC_UUID)
        self.logs.update({
            0x00: supported_log_pages(),
            0x02: smart_log(),
            0xc1: ocp_log(512, GUID_C1),
            0xc2: c2_log,
            0xc3: ocp_log(512, GUID_C3),
            0xc4: ocp_log(4096, GUID_C4),
            0xc5: ocp_log(4096, GUID_C5),
            0xc6: ocp_log(512, GUID_HW_REV_C6),
        })


class WdcModel:
    """The commands of the wdc plugin on a model which supports them."""

    controller_class = WdcController
    VID = 0
    DID = 0
    COMMANDS: tuple = ()

    def setUp(self):
        super().setUp()
        self.write_sysfs_pci_ctrl(vid=self.VID, did=self.DID)
        self.server.identify[CNS_CTRL] = id_ctrl(vid=self.VID, ssvid=self.VID,
                                                 sn='WDC0123456789',
                                                 mn='WDC Mock SSD', fr='FW100',
                                                 ctratt=CTRATT_UUID_LIST)
        # A C0 log of a client drive (SanDisk vendor ID) has the extended
        # SMART GUID.
        self.server.logs[0xc0] = (ocp_log(512, GUID_EXT_SMART_C0, 3)
                                  if self.VID == 0x15b7 else ocp_c0_log())

    def run_cmd(self, command, *args):
        return self.nvme(*command.split(), self.ctrl, *args)

    def check(self, command, *args):
        result = self.run_cmd(command, *args)
        if 'invalid sub-command' in result.stderr:
            self.skipTest(f'{command.split()[0]} plugin not built')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('ERROR', result.stderr)
        self.assertTrue(result.stdout.strip(), result.stderr)
        return result

    def test_commands(self):
        for command in self.COMMANDS:
            with self.subTest(command=command):
                self.check(command)

    def test_commands_json(self):
        if not HAVE_JSON:
            self.skipTest('nvme built without json-c')
        for command in self.COMMANDS:
            with self.subTest(command=command):
                result = self.run_cmd(command, '--output-format=json')
                if 'invalid sub-command' in result.stderr:
                    continue
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('ERROR', result.stderr)


class SN861Test(WdcModel, MockTestCase):
    VID, DID = 0x1b96, 0x2750
    COMMANDS = (
        'wdc id-ctrl',
        'wdc capabilities',
        'wdc get-drive-status',
        'wdc cloud-SSD-plugin-version',
        'wdc vs-smart-add-log',
        'wdc vs-fw-activate-history',
        'wdc vs-drive-info',
        'wdc get-latency-monitor-log',
        'wdc get-dev-capabilities-log',
        'wdc get-unsupported-reqs-log',
        'wdc cu-smart-log',
        'sndk capabilities',
        'sndk vs-fw-activate-history',
    )

    def test_cu_smart_log_fields(self):
        result = self.check('wdc cu-smart-log')
        # all 13 fields of the CA log, the last one host_bytes_written
        self.assertIn('host_bytes_written', result.stdout)
        self.assertEqual(result.stdout.count('Additional Smart Log'), 1)

    def test_fw_activate_history_entries(self):
        result = self.check('wdc vs-fw-activate-history')
        self.assertIn('FW200', result.stdout)


class SN650Test(WdcModel, MockTestCase):
    VID, DID = 0x1b96, 0x2700
    COMMANDS = (
        'wdc log-page-directory',
        'wdc get-error-recovery-log',
    )


class SN200Test(WdcModel, MockTestCase):
    VID, DID = 0x1c58, 0x0023
    COMMANDS = ('wdc purge-monitor',)


class SN820CLTest(WdcModel, MockTestCase):
    VID, DID = 0x15b7, 0x5037
    COMMANDS = (
        'wdc cloud-boot-SSD-version',
        'wdc vs-nand-stats',
        'wdc vs-temperature-stats',
        'wdc vs-cloud-log',
        'wdc vs-hw-rev-log',
        'wdc vs-device-waf',
    )


class SN730Test(WdcModel, MockTestCase):
    VID, DID = 0x15b7, 0x5006
    COMMANDS = ('wdc vs-pcie-stats',)


if __name__ == '__main__':
    main()
