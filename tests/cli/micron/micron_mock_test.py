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
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path

from tests.cli.nvme_mock_ipc import (
    MockIPCServer,
    make_mock_env,
    resolve_mock_lib_path,
    run_nvme,
)
from tests.e2e.plugins.micron.micron_checks import MicronChecksMixin
from tests.nvme_test import TestNVMeBase


def _resolve_nvme_path_abs():
    """Meson passes the binary as a path relative to the build directory.
    Ensure it exists and resolve it to an absolute path. With no argument, the
    name is looked up on PATH for a manual run against an installed nvme."""
    raw = (sys.argv[1] if len(sys.argv) > 1
           and not sys.argv[1].startswith('-') else 'nvme')
    path = shutil.which(raw)
    if not path:
        raise SystemExit(f"nvme binary not found: {raw!r}")
    return os.path.abspath(path)


def _resolve_mock_lib_path_abs():
    """If no mock library path is provided, resolve_mock_lib_path uses the
    default, which is relative to the working directory.
    Ensure the path exists and resolve it to an absolute path."""
    path = resolve_mock_lib_path("./libmock_nvme.so")
    if not os.path.exists(path):
        raise SystemExit(f"mock library not found: {path!r}")
    return os.path.abspath(path)


# Some tests chdir into a scratch directory, so use absolute paths.
NVME_BIN = _resolve_nvme_path_abs()
MOCK_LIB = _resolve_mock_lib_path_abs()

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

# struct nvme_id_ctrl field offsets, verified with offsetof().
ID_CTRL_SIZE = 4096
_OFF_VID = 0
_OFF_SN = 4
_OFF_MN = 24
_OFF_FR = 64
_OFF_CTRATT = 96
_OFF_LPA = 261
_OFF_ELPE = 262
_OFF_NN = 516
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

SMART_LOG_SIZE = 512
_OFF_SMART_TEMP = 1
_OFF_SMART_DUW = 48
_OFF_SMART_SENSOR = 200

# LPA bit 3 is telemetry support, which several commands gate on.
LPA_TELEMETRY = 0x8

LID_SMART = 0x02
LID_TELEMETRY_HOST = 0x07
LID_TELEMETRY_CTRL = 0x08

OPC_GET_LOG_PAGE = 0x02
OPC_IDENTIFY = 0x06
OPC_SET_FEATURES = 0x09
OPC_GET_FEATURES = 0x0A
OPC_FW_DOWNLOAD = 0x11
OPC_FW_COMMIT = 0x10

# Micron vendor-specific admin opcodes.
OPC_VENDOR_D6 = 0xD6
OPC_VENDOR_DA = 0xDA

# NVMe completion statuses, as the status-code-type and status code a drive
# reports them: generic statuses have SCT 0, command-specific ones SCT 1.
SC_INVALID_FIELD = 0x02
SC_INVALID_LOG_PAGE = (0x1 << 8) | 0x09

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
    buf = bytearray(ID_CTRL_SIZE)
    struct.pack_into('<H', buf, _OFF_VID, vid)
    buf[_OFF_SN:_OFF_SN + 20] = serial.encode().ljust(20)[:20]
    buf[_OFF_MN:_OFF_MN + 40] = model.encode().ljust(40)[:40]
    buf[_OFF_FR:_OFF_FR + 8] = fw.encode().ljust(8)[:8]
    struct.pack_into('<I', buf, _OFF_CTRATT, ctratt)
    buf[_OFF_LPA] = lpa
    buf[_OFF_ELPE] = elpe
    struct.pack_into('<I', buf, _OFF_NN, nn)
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
    buf = bytearray(SMART_LOG_SIZE)
    struct.pack_into('<H', buf, _OFF_SMART_TEMP, temperature_kelvin)
    for number, kelvin in dict(sensors).items():
        struct.pack_into('<H', buf, _OFF_SMART_SENSOR + (number - 1) * 2,
                         kelvin)
    buf[_OFF_SMART_DUW:_OFF_SMART_DUW + 8] = struct.pack('<Q',
                                                         data_units_written)
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


def write_mock_sysfs(root, instance=0, vid=MICRON_VENDOR_ID, did=0x51C0,
                     bdf="0000:03:00.0", subsysnqn=None):
    """Write the sysfs tree nvme-cli and libnvme read for one controller.

    Mirrors real sysfs closely enough for both consumers: the PCI attributes
    live in a PCI device directory that <ctrl>/device symlinks to, so
    read_pci_attr() finds them through the link and get_pcie_bdf() can also
    recover the BDF from the link target.
    """
    root = Path(root)
    name = f"nvme{instance}"
    ctrl = root / "sys/class/nvme" / name
    ctrl.mkdir(parents=True, exist_ok=True)

    pci = root / "sys/devices/pci0000:00" / bdf
    pci.mkdir(parents=True, exist_ok=True)
    (pci / "vendor").write_text(f"0x{vid:04x}\n")
    (pci / "device").write_text(f"0x{did:04x}\n")
    (pci / "subsystem_vendor").write_text(f"0x{vid:04x}\n")
    (pci / "subsystem_device").write_text(f"0x{did:04x}\n")
    (pci / "class").write_text("0x010802\n")

    link = ctrl / "device"
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(os.path.relpath(pci, ctrl))

    (ctrl / "address").write_text(f"{bdf}\n")
    (ctrl / "transport").write_text("pcie\n")
    (ctrl / "state").write_text("live\n")
    (ctrl / "model").write_text(f"{DEFAULT_MODEL}\n")
    (ctrl / "serial").write_text(f"{DEFAULT_SERIAL}\n")
    (ctrl / "firmware_rev").write_text(f"{DEFAULT_FW_REV}\n")

    nqn = subsysnqn or f"nqn.2014.08.org.nvmexpress:mock:{name}"
    (ctrl / "subsysnqn").write_text(f"{nqn}\n")

    subsys = root / "sys/class/nvme-subsystem" / f"nvme-subsys{instance}"
    subsys.mkdir(parents=True, exist_ok=True)
    (subsys / "subsysnqn").write_text(f"{nqn}\n")
    (subsys / name).mkdir(exist_ok=True)


class MicronMockServer(MockIPCServer):
    """Answers the admin commands the micron plugin issues.

    Tests set the attributes below rather than overriding handlers. Anything
    not configured fails the way a drive that does not implement it would,
    so a command's unsupported path is the default rather than a special
    case.
    """

    def __init__(self, sock_path):
        """Serve the micron plugin's admin commands over @sock_path."""
        super().__init__(sock_path)
        self.identify = pack_id_ctrl()
        # Status to fail identify with, for the paths that handle that.
        self.identify_status = 0
        self.smart = pack_smart_log()
        # lid -> bytes payload, or an int NVMe status to fail the read with.
        self.logs = {}
        # Status for a log page no test configured.
        self.default_log_status = SC_INVALID_LOG_PAGE
        # fid -> result value returned in cdw0 by get/set features.
        self.features = {}
        self.feature_status = {}
        # Vendor admin opcode -> bytes payload, or an int NVMe status.
        self.vendor = {}
        self.default_vendor_status = SC_INVALID_FIELD
        # Statuses for the firmware download/commit pair.
        self.fw_download_status = 0
        self.fw_commit_status = 0
        # Every command seen, so a test can assert which were issued.
        self.commands = []

    # -- observation ------------------------------------------------- #

    def log_reads(self, lid=None):
        """Return the recorded Get Log Page commands, optionally one LID."""
        return [c for c in self.commands
                if c['opcode'] == OPC_GET_LOG_PAGE
                and (lid is None or c['lid'] == lid)]

    def lids_read(self):
        """Return the set of log page IDs the command asked for."""
        return {c['lid'] for c in self.log_reads()}

    def opcodes(self):
        return [c['opcode'] for c in self.commands]

    # -- responses --------------------------------------------------- #

    def _send_slice(self, conn, payload, lpo, req_len):
        """Serve a window of @payload, as a drive does for a paged read."""
        window = payload[lpo:lpo + req_len]
        self.send_response(conn, 0, payload=window.ljust(req_len, b'\0'))

    def _send_entry(self, conn, entry, lpo, req_len, default_status):
        if entry is None:
            self.send_response(conn, 0, sc_status=default_status)
        elif isinstance(entry, int):
            self.send_response(conn, 0, sc_status=entry)
        else:
            self._send_slice(conn, entry, lpo, req_len)

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                     cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        lid = cdw10 & 0xFF
        fid = cdw10 & 0xFF
        self.commands.append({
            'opcode': opcode, 'nsid': nsid, 'lid': lid, 'fid': fid,
            'lsp': (cdw10 >> 8) & 0x7F, 'numd': (cdw10 >> 16) & 0xFFFF,
            'cdw10': cdw10, 'cdw11': cdw11, 'cdw12': cdw12, 'cdw13': cdw13,
            'lpo': lpo, 'len': req_len,
        })

        if opcode == OPC_IDENTIFY:
            self._send_entry(conn, self.identify_status or self.identify, 0,
                             req_len, SC_INVALID_FIELD)
            return

        if opcode == OPC_GET_LOG_PAGE:
            # self.smart backs the SMART log, but an explicit logs[0x02]
            # entry still wins so a test can make that read fail.
            default = self.smart if lid == LID_SMART else None
            self._send_entry(conn, self.logs.get(lid, default), lpo, req_len,
                             self.default_log_status)
            return

        if opcode in (OPC_GET_FEATURES, OPC_SET_FEATURES):
            status = self.feature_status.get(fid)
            if status:
                self.send_response(conn, 0, sc_status=status)
            else:
                self.send_response(conn, 0,
                                   result=self.features.get(fid, 0))
            return

        if opcode == OPC_FW_DOWNLOAD:
            self.send_response(conn, 0, sc_status=self.fw_download_status)
            return

        if opcode == OPC_FW_COMMIT:
            self.send_response(conn, 0, sc_status=self.fw_commit_status)
            return

        if opcode in self.vendor or opcode in (OPC_VENDOR_D6, OPC_VENDOR_DA):
            self._send_entry(conn, self.vendor.get(opcode), 0, req_len,
                             self.default_vendor_status)
            return

        self.send_response(conn, 0, payload=bytes(req_len))


class TestMicronMock(MicronChecksMixin, TestNVMeBase):
    """Base for the micron mock suites.

    Provides the same run_plugin_cmd()/run_plugin_cmd_check() surface as the
    e2e plugin base, so a migrated test body reads the same in both layers.
    """

    plugin_name = "micron"

    # Model the fake sysfs tree advertises unless a test calls select_model().
    default_model = 'M51CX'

    INSTANCE = 0

    def setUp(self):
        super().setUp()
        self.nvme_bin = NVME_BIN
        self.ctrl = f"/dev/nvme{self.INSTANCE}"
        self.ns1 = f"/dev/nvme{self.INSTANCE}n1"

        self.sysfs_dir = self._temp_dir('nvme-micron-sysfs-')
        self.base_dir = self._temp_dir('nvme-micron-base-')
        self.ipc_dir = self._temp_dir('nvme-micron-ipc-')
        self.out_dir = self._temp_dir('nvme-micron-out-')

        self.server = MicronMockServer(os.path.join(self.ipc_dir, "ipc.sock"))
        self.server.start()
        self.addCleanup(self._stop_server)

        self.env = make_mock_env(MOCK_LIB, self.server.sock_path)
        # Tools the plugin spawns are looked up on PATH, so a test can shadow
        # one to drive its failure path.
        self.tool_dir = os.path.join(self.ipc_dir, 'bin')
        os.makedirs(self.tool_dir)
        self.env['PATH'] = (self.tool_dir + os.pathsep
                            + self.env.get('PATH', os.defpath))

        self.select_model(self.default_model)

        self.cwd = os.getcwd()
        os.chdir(self.out_dir)
        self.addCleanup(os.chdir, self.cwd)

    def _stop_server(self):
        self.server.shutdown()
        self.server.join()

    def _temp_dir(self, prefix):
        tmp = tempfile.TemporaryDirectory(prefix=prefix)
        self.addCleanup(tmp.cleanup)
        return tmp.name

    # -- drive identity ---------------------------------------------- #

    def select_model(self, model, instance=None):
        """Point the fake sysfs tree at a device ID that maps to @model.

        Pass None to advertise a Micron vendor ID with an unrecognised device
        ID, which is what drives the UNKNOWN_MODEL paths.
        """
        did = UNKNOWN_DEVICE_ID if model is None else MICRON_MODELS[model][0]
        self.device_id = did
        if instance is None:
            instance = self.INSTANCE
        write_mock_sysfs(self.sysfs_dir, instance=instance, did=did)

    def select_device_id(self, did):
        """Advertise an arbitrary PCI device ID."""
        self.device_id = did
        write_mock_sysfs(self.sysfs_dir, instance=self.INSTANCE, did=did)

    def sysfs_path_ctrl(self):
        """Return the controller directory inside the fake sysfs tree."""
        return (Path(self.sysfs_dir) / "sys/class/nvme"
                / f"nvme{self.INSTANCE}")

    def select_vendor(self, vid, did=0x51C0):
        """Advertise a non-Micron vendor, the other route to UNKNOWN_MODEL."""
        self.device_id = did
        write_mock_sysfs(self.sysfs_dir, instance=self.INSTANCE, vid=vid,
                         did=did)

    # -- running commands -------------------------------------------- #

    def run_nvme(self, *args, encoding='utf-8'):
        """Run the nvme binary under the mock, with the fake sysfs tree.

        Pass encoding=None for a command whose stdout is not text.
        """
        return run_nvme(self.nvme_bin, self.env, self.sysfs_dir,
                        self.base_dir, *args, encoding=encoding)

    def run_core_cmd(self, command, device=None, args=""):
        """Run a built-in nvme command against the same mocked drive.

        command() resolves the canonical name to whatever this binary
        supports, so a plugin rendering can be compared against the core one.
        """
        if device is None:
            device = self.ctrl
        argv = self.command(command).split()
        return self.run_nvme(*argv, device, *args.split())

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
        return self.run_nvme(*argv, *args.split())

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


def main():
    """Entry point for the suites, which are invoked as scripts."""
    unittest.main(argv=[sys.argv[0]], verbosity=2)
