#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Shared harness for the hardware-free micron plugin tests.

The micron plugin keys almost everything off the drive model, which
GetDriveModel() derives from the PCI vendor/device ID read out of
/sys/class/nvme/<ctrl>/device.  nvme-cli roots those reads at
nvme_sysfs_ctrl_path(), so writing a fake sysfs tree and passing
--set-options test-sysfs-dir= lets a test pick any model it likes -- the
branches no single drive can reach.

Everything else the plugin needs comes from admin commands, which
libmock_nvme.c forwards to MicronMockServer here.

This module is imported by the micron_*_mock_test.py suites; it registers no
tests of its own.
"""
import os
import struct
from pathlib import Path

from tests.cli.nvme_mock import (CNS_CTRL, LID_SMART, LID_TELEMETRY_HOST,
                                 OPC_GET_LOG_PAGE, SC_INVALID_FIELD,
                                 SC_INVALID_LOG_PAGE, MockController,
                                 MockTestCase, id_ctrl, smart_log)
from tests.e2e.plugins.micron.micron_checks import MicronChecksMixin

MICRON_VENDOR_ID = 0x1344

# Device ID -> model, mirroring the switch in GetDriveModel().  A test picks a
# model by name and gets a device ID that maps to it.
MICRON_MODELS = {
    'M51AX': (0x5196, 0x51A0, 0x51A1, 0x51A2),
    'M51BX': (0x51B0, 0x51B1, 0x51B2),
    'M51BY': (0x51B7, 0x51B8, 0x51B9),
    'M51CY': (0x51BB, 0x51BD, 0x51BC, 0x51BE, 0x51BF, 0x51C8, 0x51C9,
              0x51CA, 0x51CB, 0x51CC, 0x51CD, 0x51CE),
    'M51CX': (0x51C0, 0x51C1, 0x51C2, 0x51C3, 0x51C4),
    'M5407': (0x5405, 0x5406, 0x5407),
    'M5410': (0x5410,),
    'M5411': (0x5411,),
    'M6001': (0x6001,),
    'M6003': (0x6003,),
    'M6004': (0x6004,),
}

# A device ID Micron does not ship, so GetDriveModel() returns UNKNOWN_MODEL
# even under the Micron vendor ID.
UNKNOWN_DEVICE_ID = 0x0BAD

# Customer ID marking a Hyperscale boot SSD, at identify vs[536].
CUST_ID_GG = 0x16
CUST_ID_GENERIC = 0x10

_OFF_VS = 3072

# Vendor-specific identify bytes the plugin reads, as offsets into vs[].
_VS_CUST_ID = 536
_VS_HW_VER_MAJOR = 820
_VS_HW_VER_MINOR = 821
_VS_FTL_UNIT_SIZE = 822
# micron_internal_logs() reads these as dwords off the base of the struct:
# puiIDDBuf[1015] is the 0xE6/0xE7 selection mask, puiIDDBuf[1023] their size.
_OFF_E6E7_MASK = 1015 * 4
_OFF_E6E7_SIZE = 1023 * 4

_OFF_SMART_SENSOR = 200

# Micron vendor-specific admin opcodes.
OPC_VENDOR_D6 = 0xD6
OPC_VENDOR_DA = 0xDA

DEFAULT_SERIAL = "MOCKMICRONSN001"
DEFAULT_MODEL = "Micron_Mock_Drive"
DEFAULT_FW_REV = "MOCK1234"


def pack_id_ctrl(serial=DEFAULT_SERIAL, model=DEFAULT_MODEL, fw=DEFAULT_FW_REV,
                 vid=MICRON_VENDOR_ID, lpa=0, ctratt=0, nn=1, elpe=0,
                 cust_id=CUST_ID_GENERIC, hw_ver=(0, 0), ftl_unit_size=0,
                 e6e7_mask=0, e6e7_size=0):
    """Build an identify controller buffer.

    Identify strings are space-padded and not NUL-terminated, so the plugin's
    trimming is exercised by default rather than bypassed.
    """
    buf = id_ctrl(vid=vid, sn=serial[:20], mn=model[:40], fr=fw[:8],
                  ctratt=ctratt, lpa=lpa, elpe=elpe, nn=nn)
    buf[_OFF_VS + _VS_CUST_ID] = cust_id
    buf[_OFF_VS + _VS_HW_VER_MAJOR] = hw_ver[0]
    buf[_OFF_VS + _VS_HW_VER_MINOR] = hw_ver[1]
    buf[_OFF_VS + _VS_FTL_UNIT_SIZE] = ftl_unit_size
    struct.pack_into('<I', buf, _OFF_E6E7_MASK, e6e7_mask)
    struct.pack_into('<I', buf, _OFF_E6E7_SIZE, e6e7_size)
    return bytes(buf)


def pack_smart_log(temperature_kelvin=0, sensors=(), data_units_written=0):
    """Build a SMART log. @sensors maps 1-based sensor number to a Kelvin
    reading; a sensor reading of 0 means the sensor is not present."""
    buf = smart_log(temperature=temperature_kelvin,
                    data_units_written=data_units_written)
    for number, kelvin in dict(sensors).items():
        struct.pack_into('<H', buf, _OFF_SMART_SENSOR + (number - 1) * 2,
                         kelvin)
    return bytes(buf)


def pack_telemetry_log(last_blocks=(2, 4, 0, 0), total_bytes=None,
                       lid=LID_TELEMETRY_HOST):
    """Build a telemetry log. last_blocks is the last block of data areas
    1..4; the plugin sizes area N as (last_block + 1) * 512. Byte 0 is the log
    page identifier, so @lid must match the log this stands in for."""
    if total_bytes is None:
        total_bytes = (max(last_blocks) + 1) * 512
    buf = bytearray(total_bytes)
    buf[0] = lid
    struct.pack_into('<H', buf, 8, last_blocks[0])
    struct.pack_into('<H', buf, 10, last_blocks[1])
    struct.pack_into('<H', buf, 12, last_blocks[2])
    struct.pack_into('<I', buf, 16, last_blocks[3])
    return bytes(buf)


class MicronController(MockController):
    """Answers the admin commands the micron plugin issues.

    Anything not configured fails the way a drive that does not implement
    it would: a log page with @default_log_status, a vendor specific
    command with @default_vendor_status. So a command's unsupported path
    is the default rather than a special case.
    """

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.identify[CNS_CTRL] = pack_id_ctrl()
        self.logs[LID_SMART] = pack_smart_log()
        self.default_log_status = SC_INVALID_LOG_PAGE
        self.default_vendor_status = SC_INVALID_FIELD

    def answer(self, cmd):
        if cmd.admin and cmd.opcode == OPC_GET_LOG_PAGE and \
                cmd.lid not in self.logs:
            return self.default_log_status
        if cmd.admin and cmd.opcode in (OPC_VENDOR_D6, OPC_VENDOR_DA) and \
                cmd.opcode not in self.admin:
            return self.default_vendor_status
        return super().answer(cmd)


class TestMicronMock(MicronChecksMixin, MockTestCase):
    """Base for the micron mock suites.

    Provides the same run_plugin_cmd()/run_plugin_cmd_check() surface as the
    e2e plugin base, so a migrated test body reads the same in both layers.
    """

    plugin_name = "micron"
    controller_class = MicronController

    # Model the fake sysfs tree advertises unless a test calls select_model().
    default_model = 'M51CX'

    def setUp(self):
        super().setUp()
        # Tools the plugin spawns are looked up on PATH, so a test can shadow
        # one to drive its failure path.
        self.tool_dir = os.path.join(self.tmp, 'bin')
        os.makedirs(self.tool_dir)
        self.env['PATH'] = (self.tool_dir + os.pathsep
                            + self.env.get('PATH', os.defpath))

        self.select_model(self.default_model)
        self.chdir_out_dir()

    # -- drive identity ---------------------------------------------- #

    def _write_sysfs(self, vid=MICRON_VENDOR_ID, did=0x51C0):
        self.device_id = did
        self.write_sysfs_pci_ctrl(vid=vid, did=did, model=DEFAULT_MODEL,
                                  serial=DEFAULT_SERIAL,
                                  firmware=DEFAULT_FW_REV)

    def select_model(self, model):
        """Point the fake sysfs tree at a device ID that maps to @model.

        Pass None to advertise a Micron vendor ID with an unrecognised device
        ID, which is what drives the UNKNOWN_MODEL paths.
        """
        self._write_sysfs(did=UNKNOWN_DEVICE_ID if model is None
                          else MICRON_MODELS[model][0])

    def select_device_id(self, did):
        """Advertise an arbitrary PCI device ID."""
        self._write_sysfs(did=did)

    def sysfs_path_ctrl(self):
        """Return the controller directory inside the fake sysfs tree."""
        return Path(self.sysfs_dir) / "sys/class/nvme/nvme0"

    def select_vendor(self, vid, did=0x51C0):
        """Advertise a non-Micron vendor, the other route to UNKNOWN_MODEL."""
        self._write_sysfs(vid=vid, did=did)

    # -- running commands -------------------------------------------- #

    def run_core_cmd(self, command, device=None, args=""):
        """Run a built-in nvme command against the same mocked drive.

        command() resolves the canonical name to whatever this binary
        supports, so a plugin rendering can be compared against the core one.
        """
        if device is None:
            device = self.ctrl
        argv = self.command(command).split()
        return self.nvme(*argv, device, *args.split())

    def run_core_cmd_json(self, command, device=None):
        result = self.run_core_cmd(command, device=device, args="-o json")
        self.assertEqual(
            result.returncode, 0,
            f"core nvme {command} failed: rc={result.returncode}, "
            f"stderr={result.stderr!r}",
        )
        return self.parse_json_output(result.stdout, f"nvme {command} -o json")

    def run_plugin_cmd(self, command, device=None, args=""):
        if device is None:
            device = self.ctrl
        argv = [self.plugin_name, command]
        if device:
            argv.append(device)
        return self.nvme(*argv, *args.split())

    def run_plugin_cmd_check(self, command, device=None, args=""):
        result = self.run_plugin_cmd(command, device=device, args=args)
        self.assertEqual(
            result.returncode, 0,
            f"micron {command} failed: rc={result.returncode}, "
            f"stdout={result.stdout!r}, stderr={result.stderr!r}",
        )
        return result

    def run_plugin_cmd_json(self, command, device=None,
                            args="--output-format=json"):
        result = self.run_plugin_cmd_check(command, device=device, args=args)
        return self.parse_json_output(result.stdout,
                                      f"micron {command} {args}")

    # -- helpers ------------------------------------------------------ #

    def fake_tool(self, name, script="#!/bin/sh\nexit 1\n"):
        """Shadow a tool the plugin spawns with one of our own.

        The default always fails, for the tool-failure paths; pass a script to
        stand in for a tool the test host may not have.
        """
        path = os.path.join(self.tool_dir, name)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(script)
        os.chmod(path, 0o755)
        return path
