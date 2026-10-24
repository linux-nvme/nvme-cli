#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Shared harness for the tests which run nvme against a mocked
controller (see libmock_nvme.c and nvme_mock_ipc.py).

MockController answers the commands from tables a test fills in:
Identify by CNS, Get Log Page by log page ID, served at the log page
offset, Get/Set Features by feature ID, and any other command by its
opcode. Everything else succeeds with zeroed data. Each command is
recorded, so a test can check the fields of what nvme sent, including
the data of a command which transfers data to the controller.

MockTestCase runs nvme against a MockController, in a fake sysfs tree
of its own. write_sysfs_pci_ctrl() adds a controller with PCI IDs to
the tree, for the code which reads them, like the vendor plugins.

The modules of the tests import this one; it registers no tests.
"""
import collections
import os
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path

from tests.cli.nvme_mock_ipc import (MockIPCServer, make_mock_env,
                                     resolve_mock_lib_path, run_nvme)
from tests.nvme_test import TestNVMeBase


def _resolve_nvme_bin():
    """Meson passes the binary relative to the build directory. A test
    may change the directory, so resolve it to an absolute path. Without
    an argument, use the nvme on PATH."""
    raw = (sys.argv[1] if len(sys.argv) > 1
           and not sys.argv[1].startswith('-') else 'nvme')
    path = shutil.which(raw)
    if not path:
        raise SystemExit(f'nvme binary not found: {raw!r}')
    return os.path.abspath(path)


def _resolve_mock_lib():
    path = resolve_mock_lib_path('./libmock_nvme.so')
    if not os.path.exists(path):
        raise SystemExit(f'mock library not found: {path!r}')
    return os.path.abspath(path)


NVME_BIN = _resolve_nvme_bin()
MOCK_LIB = _resolve_mock_lib()
# Without json-c, some commands ignore '-o json' and print text.
HAVE_JSON = os.environ.get('NVME_TEST_JSON', '1') == '1'

# Admin command opcodes
OPC_GET_LOG_PAGE = 0x02
OPC_IDENTIFY = 0x06
OPC_SET_FEATURES = 0x09
OPC_GET_FEATURES = 0x0a
OPC_FW_COMMIT = 0x10
OPC_FW_DOWNLOAD = 0x11
OPC_DIRECTIVE_RECV = 0x1a
OPC_SECURITY_RECV = 0x82

# NVM command set opcodes
OPC_NVM_WRITE = 0x01
OPC_NVM_READ = 0x02

# Identify CNS values
CNS_NS = 0x00
CNS_CTRL = 0x01
CNS_NS_DESC_LIST = 0x03
CNS_CSI_NS = 0x05
CNS_UUID_LIST = 0x17

# Log page identifiers
LID_SMART = 0x02
LID_TELEMETRY_HOST = 0x07
LID_TELEMETRY_CTRL = 0x08

# Feature identifiers
FID_HOST_BEHAVIOR = 0x16

NSID_ALL = 0xffffffff

# linux/nvme_ioctl.h: the _IO('N', nr) numbers
NVME_IOCTL_ID = 0x40
NVME_IOCTL_RESET = 0x44
NVME_IOCTL_SUBSYS_RESET = 0x45
NVME_IOCTL_RESCAN = 0x46

# Generic command status values
SC_INVALID_FIELD = 0x02
SC_INTERNAL = 0x06
# Command specific status values (status code type 1)
SC_INVALID_LOG_PAGE = 0x109

ID_CTRL_SIZE = 4096
ID_NS_SIZE = 4096
UUID_LIST_SIZE = 4096
SMART_LOG_SIZE = 512

# Field name -> (struct format, offset) of the data structures. Strings
# ('<n>s') are padded with spaces, like the controller does.
ID_CTRL_FIELDS = {
    'vid': ('<H', 0),
    'ssvid': ('<H', 2),
    'sn': ('20s', 4),
    'mn': ('40s', 24),
    'fr': ('8s', 64),
    'ctratt': ('<I', 96),
    'lpa': ('B', 261),
    'elpe': ('B', 262),
    'rpmbs': ('<I', 312),
    'sanicap': ('<I', 328),
    'nanagrpid': ('<I', 348),
    'nn': ('<I', 516),
    'fna': ('B', 524),
    'mnan': ('<I', 540),
}

ID_NS_FIELDS = {
    'nsze': ('<Q', 0),
    'ncap': ('<Q', 8),
    'nuse': ('<Q', 16),
    'nlbaf': ('B', 25),
    'flbas': ('B', 26),
    'mc': ('B', 27),
    'dpc': ('B', 28),
    'dps': ('B', 29),
}
ID_NS_LBAF = 128
FLBAS_META_EXT = 0x10

NVM_ID_NS_FIELDS = {
    'lbstm': ('<Q', 0),
    'pic': ('B', 8),
    'pifa': ('B', 9),
}
NVM_ID_NS_ELBAF = 12
NVM_ID_NS_SIZE = 4096
PIC_QPIFS = 1 << 3

SMART_LOG_FIELDS = {
    'temperature': ('<H', 1),
    'data_units_read': ('<Q', 32),
    'data_units_written': ('<Q', 48),
}

HOST_BEHAVIOR_FIELDS = {
    'acre': ('B', 0),
    'etdas': ('B', 1),
    'lbafee': ('B', 2),
    'hdisns': ('B', 3),
    'cdfe': ('<H', 4),
}
HOST_BEHAVIOR_SIZE = 512

CTRATT_UUID_LIST = 1 << 9
LPA_TELEMETRY = 1 << 3


def pack_fields(fields, size, **values):
    """A data structure of @size bytes, zero but for the @values of the
    @fields table."""
    buf = bytearray(size)
    for name, value in values.items():
        fmt, offset = fields[name]
        if isinstance(value, str):
            value = value.encode('ascii').ljust(struct.calcsize(fmt))
        struct.pack_into(fmt, buf, offset, value)
    return buf


def id_ctrl(**values):
    """An Identify Controller data structure, see ID_CTRL_FIELDS."""
    return pack_fields(ID_CTRL_FIELDS, ID_CTRL_SIZE, **values)


def _formats(table):
    """The (index, format) pairs of a list or an {index: format} dict"""
    return table.items() if isinstance(table, dict) else enumerate(table)


def id_ns(lbaf=(), **values):
    """An Identify Namespace data structure, see ID_NS_FIELDS. @lbaf is
    the LBA format table, (ms, lbads, rp) for each format, as a list or
    an {index: format} dict. Unless given, nlbaf is set from it."""
    if lbaf:
        values.setdefault('nlbaf', max(i for i, _ in _formats(lbaf)))
    buf = pack_fields(ID_NS_FIELDS, ID_NS_SIZE, **values)
    for i, (ms, lbads, rp) in _formats(lbaf):
        struct.pack_into('<HBB', buf, ID_NS_LBAF + 4 * i, ms, lbads, rp)
    return buf


def nvm_id_ns(elbaf=(), **values):
    """An I/O Command Set specific Identify Namespace data structure of
    the NVM command set, see NVM_ID_NS_FIELDS. @elbaf is the extended
    LBA format table, (sts, pif, qpif) for each format, as a list or an
    {index: format} dict."""
    buf = pack_fields(NVM_ID_NS_FIELDS, NVM_ID_NS_SIZE, **values)
    for i, (sts, pif, qpif) in _formats(elbaf):
        struct.pack_into('<I', buf, NVM_ID_NS_ELBAF + 4 * i,
                         (sts & 0x7f) | (pif & 0x3) << 7 | (qpif & 0xf) << 9)
    return buf


def uuid_list(*uuids):
    """An Identify UUID List with the 16 byte @uuids, entry 0 first."""
    buf = bytearray(UUID_LIST_SIZE)
    for i, uuid in enumerate(uuids):
        offset = 32 + 32 * i + 16
        buf[offset:offset + 16] = uuid
    return buf


def smart_log(**values):
    """A SMART / Health Information log page, see SMART_LOG_FIELDS."""
    return pack_fields(SMART_LOG_FIELDS, SMART_LOG_SIZE, **values)


def host_behavior(**values):
    """A Host Behavior Support feature data structure, see
    HOST_BEHAVIOR_FIELDS."""
    return pack_fields(HOST_BEHAVIOR_FIELDS, HOST_BEHAVIOR_SIZE, **values)


def write_sysfs_ctrl(root, instance, transport, address, subsysnqn=None,
                     **attrs):
    """Write the sysfs tree of a controller nvme<@instance> under @root,
    in the subsystem @subsysnqn, with the other attributes @attrs. An
    empty attribute is an empty file."""
    root = Path(root)
    name = f'nvme{instance}'
    ctrl = root / 'sys/class/nvme' / name
    ctrl.mkdir(parents=True, exist_ok=True)

    nqn = subsysnqn or f'nqn.2014.08.org.nvmexpress:mock:{name}'
    attrs = {'transport': transport, 'address': address, 'state': 'live',
             'subsysnqn': nqn, **attrs}
    for attr, value in attrs.items():
        (ctrl / attr).write_text(f'{value}\n' if value != '' else '')

    subsys = root / 'sys/class/nvme-subsystem' / f'nvme-subsys{instance}'
    subsys.mkdir(parents=True, exist_ok=True)
    (subsys / 'subsysnqn').write_text(f'{nqn}\n')
    (subsys / name).mkdir(exist_ok=True)
    return ctrl


def write_sysfs_pci_ctrl(root, instance=0, vid=0x1b36, did=0x0010,
                         ssvid=None, ssdid=None, bdf='0000:03:00.0',
                         subsysnqn=None, model='MOCK NVMe',
                         serial='MOCK0001', firmware='1.0'):
    """Write the sysfs tree of a PCIe controller nvme<@instance> under
    @root, with the PCI IDs @vid/@did and the subsystem IDs @ssvid/
    @ssdid (default: the same).

    The PCI attributes are in a PCI device directory, which <ctrl>/device
    links to, as in the real sysfs: nvme_get_pci_ids() reads them through
    the link, and the BDF can be recovered from its target."""
    ctrl = write_sysfs_ctrl(root, instance, 'pcie', bdf, subsysnqn,
                            model=model, serial=serial,
                            firmware_rev=firmware)

    pci = Path(root) / 'sys/devices/pci0000:00' / bdf
    pci.mkdir(parents=True, exist_ok=True)
    for attr, value in (('vendor', vid), ('device', did),
                        ('subsystem_vendor', vid if ssvid is None else ssvid),
                        ('subsystem_device', did if ssdid is None else ssdid)):
        (pci / attr).write_text(f'0x{value:04x}\n')
    (pci / 'class').write_text('0x010802\n')

    link = ctrl / 'device'
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(os.path.relpath(pci, ctrl))


Reply = collections.namedtuple('Reply', ['data', 'result', 'status', 'errno'],
                               defaults=(b'', 0, 0, 0))
Reply.__doc__ = """The answer to a command: the @data it reads, the
@result dword, an NVMe @status (with the status code type in bits 10:8),
or an @errno the ioctl() fails with."""


class MockController(MockIPCServer):
    """A controller which answers each command from its tables:

    @identify   CNS -> answer
    @logs       log page ID -> answer. Data is the whole log page,
                served at the log page offset of each read; a callable
                returns the data of the read it gets.
    @features   feature ID -> answer, for Get and Set Features. Like a
                controller, a Set Features with data stores it as the
                data of the feature, if that is bytes.
    @admin      admin opcode -> answer, for the other admin commands
    @io         I/O opcode -> answer
    @ioctls     nr -> answer, for the other ioctl()s of type 'N' (see
                linux/nvme_ioctl.h), whose status is the return value

    An answer is a Reply, bytes (the data), an int (an NVMe status) or a
    callable, which gets the Command (or RawIoctl) and returns one of the
    others. A command without an answer gets @default, an ioctl() fails
    with ENOTTY. Data is truncated or zero padded to the length the
    command reads.

    Each Command is appended to @commands, each RawIoctl of type 'N' to
    @raw_ioctls."""

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.identify = {}
        self.logs = {}
        self.features = {}
        self.admin = {}
        self.io = {}
        self.ioctls = {}
        self.default = Reply()
        self.commands = []
        self.raw_ioctls = []

    @staticmethod
    def _reply(answer, req):
        if callable(answer):
            answer = answer(req)
        if isinstance(answer, (bytes, bytearray)):
            return Reply(data=answer)
        if isinstance(answer, int):
            return Reply(status=answer)
        return answer

    def handle_raw_ioctl(self, conn, fd, ioc, payload):
        if ioc.type != ord('N') or ioc.nr not in self.ioctls:
            super().handle_raw_ioctl(conn, fd, ioc, payload)
            return
        self.raw_ioctls.append(ioc)
        reply = self._reply(self.ioctls[ioc.nr], ioc)
        if reply.errno:
            self.send_response(conn, -1, errno_val=reply.errno)
        else:
            self.send_response(conn, 0, sc_status=reply.status,
                               payload=bytes(reply.data))

    def handle_command(self, conn, cmd):
        self.commands.append(cmd)
        reply = self._reply(self.answer(cmd), cmd)
        data = bytes(reply.data)[:cmd.data_len].ljust(cmd.data_len, b'\0')
        if reply.errno:
            self.send_response(conn, -1, errno_val=reply.errno)
        elif reply.status:
            self.send_response(conn, 0, sc_status=reply.status,
                               result=reply.result)
        else:
            self.send_response(conn, 0, result=reply.result, payload=data)

    def answer(self, cmd):
        """The answer to @cmd from the tables. Override to answer
        commands the tables can't."""
        if not cmd.admin:
            return self.io.get(cmd.opcode, self.default)
        if cmd.opcode == OPC_IDENTIFY:
            return self.identify.get(cmd.cns, self.default)
        if cmd.opcode == OPC_GET_LOG_PAGE:
            log = self.logs.get(cmd.lid, self.default)
            if isinstance(log, (bytes, bytearray)):
                return log[cmd.lpo:]
            return log
        if cmd.opcode in (OPC_GET_FEATURES, OPC_SET_FEATURES):
            feature = self.features.get(cmd.fid, self.default)
            if (cmd.opcode == OPC_SET_FEATURES and cmd.data is not None
                    and isinstance(feature, (bytes, bytearray))):
                self.features[cmd.fid] = cmd.data
                return self.default
            return feature
        return self.admin.get(cmd.opcode, self.default)

    def opcodes(self):
        """The opcodes of the recorded commands."""
        return [c.opcode for c in self.commands]

    def admin_cmds(self, opcode):
        """The recorded admin commands with @opcode."""
        return [c for c in self.commands if c.admin and c.opcode == opcode]

    def io_cmds(self, opcode):
        """The recorded I/O commands with @opcode."""
        return [c for c in self.commands
                if not c.admin and c.opcode == opcode]

    def identifies(self, cns=None):
        """The recorded Identify commands, of @cns if given."""
        return [c for c in self.admin_cmds(OPC_IDENTIFY)
                if cns is None or c.cns == cns]

    def log_reads(self, lid=None):
        """The recorded Get Log Page commands, of @lid if given."""
        return [c for c in self.admin_cmds(OPC_GET_LOG_PAGE)
                if lid is None or c.lid == lid]

    def lids_read(self):
        """The log page IDs of the recorded Get Log Page commands."""
        return {c.lid for c in self.log_reads()}


class MockTestCase(TestNVMeBase):
    """Runs nvme against a @controller_class instance, @self.server, in
    a fake sysfs tree, @self.sysfs_dir, which is empty unless the test
    writes to it (see write_sysfs_pci_ctrl()). A failing answer of the
    controller fails the test.

    Everything is released through addCleanup(), so a failure part way
    through setUp() still releases what was set up before it."""

    controller_class = MockController
    ctrl = '/dev/nvme0'
    ns = '/dev/nvme0n1'

    def setUp(self):
        super().setUp()
        self.nvme_bin = NVME_BIN
        tmp = tempfile.TemporaryDirectory(prefix='nvme-mock-', dir='/tmp')
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.sysfs_dir = os.path.join(self.tmp, 'sysfs')
        self.base_dir = os.path.join(self.tmp, 'base')
        for d in ('sys/class/nvme', 'sys/class/nvme-subsystem'):
            os.makedirs(os.path.join(self.sysfs_dir, d))
        os.mkdir(self.base_dir)

        sock_path = os.path.join(self.tmp, 'ipc.sock')
        self.server = self.controller_class(sock_path)
        self.server.start()
        # Cleanups run last-registered-first: the server stops before
        # join() waits for its thread, and before its directory goes.
        self.addCleanup(self._check_server_errors)
        self.addCleanup(self.server.join)
        self.addCleanup(self.server.shutdown)
        self.env = make_mock_env(MOCK_LIB, sock_path)

    def _check_server_errors(self):
        if self.server.errors:
            self.fail('mock controller failed:\n' +
                      '\n'.join(self.server.errors))

    def chdir_out_dir(self):
        """Run in an empty directory, @self.out_dir, for the commands
        which write files to the current directory."""
        self.out_dir = os.path.join(self.tmp, 'out')
        os.mkdir(self.out_dir)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.out_dir)

    def write_sysfs_pci_ctrl(self, **kwargs):
        """Add a PCIe controller to the fake sysfs tree, see
        write_sysfs_pci_ctrl()."""
        write_sysfs_pci_ctrl(self.sysfs_dir, **kwargs)

    def nvme(self, *args, **kwargs):
        """Run `nvme *args`, see run_nvme() for @kwargs."""
        return run_nvme(self.nvme_bin, self.env, self.sysfs_dir,
                        self.base_dir, *args, **kwargs)

    def assertOk(self, result):
        """Fail unless the nvme run @result exited with 0. Returns it."""
        self.assertEqual(
            result.returncode, 0,
            f'nvme failed:\nstdout:\n{result.stdout}\n'
            f'stderr:\n{result.stderr}')
        return result


def main():
    """Entry point of the tests, which run as scripts: <nvme> <mock lib>
    [unittest arguments]."""
    unittest.main(argv=sys.argv[:1] + sys.argv[3:], verbosity=2)
