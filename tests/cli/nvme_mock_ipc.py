#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.com>
"""libmock_nvme.c intercepts open()/write()/ioctl()/close() on
/dev/nvme-fabrics, /dev/nvme<N>, and /dev/nvme<N>n<M>. It forwards every
intercepted write() (fabrics connect args), ioctl() and getpass() over a
Unix socket to a MockIPCServer instance running in this process. This lets
nvme-cli run against a fake target, with no real hardware and no root.
It also forwards the egress route lookup, the NIC h/w queue query and
get_nprocs(), so the test decides the host's network and CPU setup.

Test files subclass MockIPCServer and override handle_write()/
handle_command()/handle_raw_ioctl()/handle_getpass()/handle_route()/
handle_nic_queues()/handle_nprocs() to steer responses for their own
scenario. run_nvme() provides the common subprocess-invocation
mechanics.
"""
import collections
import errno
import json
import os
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import threading
import traceback
from pathlib import Path

IPC_REQUEST_FMT = "<IIII B3x I IIIIII I BBBBI BB2x IIII"
IPC_REQUEST_LEN = struct.calcsize(IPC_REQUEST_FMT)
# status, errno_val, sc_status, result, data_len -- see struct ipc_response.
IPC_RESPONSE_FMT = "<iiiII"

IPC_TYPE_WRITE = 1  # write() on /dev/nvme-fabrics (connect args)
IPC_TYPE_IOCTL = 2  # ioctl() admin or I/O passthru command
IPC_TYPE_RAW_IOCTL = 3  # any other ioctl() on a mocked device
IPC_TYPE_GETPASS = 4  # getpass(), payload is the prompt
IPC_TYPE_ROUTE = 5  # egress route lookup, payload is "daddr\0saddr"
IPC_TYPE_NIC_QUEUES = 6  # ETHTOOL_GCHANNELS, payload is the ifname
IPC_TYPE_NPROCS = 7  # get_nprocs()
# combined_count, tx_count, rx_count -- the handle_nic_queues() payload.
NIC_QUEUES_FMT = "<III"

# enum ipc_cmd_flags: what an IPC_TYPE_IOCTL request carries
IPC_CMD_ADMIN = 1 << 0  # admin, not I/O, queue
IPC_CMD_DATA = 1 << 1  # the payload has the data
IPC_CMD_METADATA = 1 << 2  # the payload has the metadata

IOC_WRITE = 1 << 0  # the caller passes data in
IOC_READ = 1 << 1  # the caller gets data back

RawIoctl = collections.namedtuple(
    'RawIoctl', ['request', 'dir', 'type', 'nr', 'size', 'big_endian'])
RawIoctl.__doc__ = """A raw ioctl() request, decoded by libmock_nvme.c
with the target's _IOC_* macros, so it is the same on every arch.
@big_endian is the byte order of the payload. Use byte_order() to pick
the struct module prefix for it."""
RawIoctl.byte_order = lambda self: '>' if self.big_endian else '<'


class Command(collections.namedtuple('Command', [
        'instance', 'admin', 'opcode', 'flags', 'nsid', 'cdw2', 'cdw3',
        'cdw10', 'cdw11', 'cdw12', 'cdw13', 'cdw14', 'cdw15',
        'data_len', 'metadata_len', 'timeout_ms', 'data', 'metadata'])):
    """An admin or I/O passthru command, as libmock_nvme.c decodes it.
    @instance is the controller instance it goes to (the N of
    /dev/nvmeN), @admin is True for the admin queue. @data_len and
    @metadata_len are the buffer sizes of the command. @data and
    @metadata are what a command which transfers data to the controller
    sends, else None."""
    __slots__ = ()

    @property
    def cdw10_lo(self):
        """CNS of Identify, LID of Get Log Page, FID of Get/Set Features"""
        return self.cdw10 & 0xff

    cns = lid = fid = cdw10_lo

    @property
    def lsp(self):
        """Log specific parameter of Get Log Page"""
        return (self.cdw10 >> 8) & 0x7f

    @property
    def rae(self):
        """Retain Asynchronous Event of Get Log Page"""
        return bool(self.cdw10 & (1 << 15))

    @property
    def uuid_index(self):
        """UUID index of Get Log Page, Get/Set Features and others"""
        return self.cdw14 & 0x7f

    @property
    def sel(self):
        """Select of Get Features"""
        return (self.cdw10 >> 8) & 0x7

    @property
    def lpo(self):
        """Log page offset of Get Log Page"""
        return (self.cdw13 << 32) | self.cdw12


def resolve_mock_lib_path(default="./libmock_nvme.so"):
    """Locates libmock_nvme.so. Reads argv[2], the built shared_library()
    path meson.build passes in. Falls back to a few likely build-directory
    layouts for a standalone/manual run, then to @default."""
    if len(sys.argv) > 2:
        raw_path = sys.argv[2]
        candidates = (
            Path(raw_path),
            Path(raw_path).resolve(),
            Path(os.getcwd()) / ".build" / raw_path,
            Path(__file__).parent.parent.parent / ".build" / raw_path,
        )
        for candidate in candidates:
            if candidate.exists():
                return str(candidate.resolve())
    return default


def built_with_library(nvme_bin, soname_fragment):
    """True if nvme_bin is dynamically linked against a library whose
    soname contains soname_fragment, e.g. "libarchive".

    Some vendor plugin features (archiving) compile to a disabled-feature
    stub when their optional library isn't found at build time, rather
    than failing the build. A test for one of those features checks this,
    not whether some unrelated CLI tool happens to be on PATH: nvme-cli
    links the library directly and no longer spawns a tar/zip process for
    it.

    A statically linked nvme has no shared libraries at all -- ldd reports
    "not a dynamic executable" on stdout and exits non-zero for one -- so
    that case is treated the same as the library not being linked in,
    which matches reality: a static build always builds with every such
    optional library disabled (see scripts/build.sh), so the feature
    really is unavailable.
    """
    try:
        result = subprocess.run(['ldd', nvme_bin], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, encoding='utf-8',
                                check=False)
    except FileNotFoundError:
        return False
    if result.returncode != 0:
        return False
    return soname_fragment in result.stdout


class _FuzzRecorder:
    """With NVME_FUZZ_RECORD=<dir>, each run_nvme() writes what it ran and
    the answers of the device to <dir>, the answers in the input format of
    the fuzz backend of libmock_nvme.c: a control byte, the result dword,
    the NVMe status or the data. scripts/fuzz/nvme-fuzz seeds turns them
    into seeds of the device fuzz target, which then start with the valid
    device data of the tests.

    Like the fuzz backend, only device commands get an answer, and none
    once the data of a run would exceed what it serves."""

    # FUZZ_MAX_TRANSFER and FUZZ_MAX_TOTAL of libmock_nvme.c
    MAX_TRANSFER = 2 * 1024 * 1024
    MAX_TOTAL = 1 * 1024 * 1024

    def __init__(self):
        self.dir = os.environ.get('NVME_FUZZ_RECORD')
        self.answers = None
        self.total = 0
        self.data_len = None
        self.runs = 0

    def start(self):
        if self.dir:
            self.answers = bytearray()
            self.total = 0

    def request(self, data_len):
        """The next answer is to a device command which reads @data_len
        bytes, or with None to no device command."""
        self.data_len = data_len

    def answer(self, status, sc_status, result, payload):
        data_len, self.data_len = self.data_len, None
        if self.answers is None or data_len is None:
            return
        if (data_len > self.MAX_TRANSFER or
                data_len > self.MAX_TOTAL - self.total):
            return
        self.total += data_len
        res = struct.pack('<I', result & 0xffffffff)
        if status == -1:
            self.answers += b'\xff' + res
        elif sc_status:
            self.answers += (b'\xe0' + res +
                             struct.pack('<H', sc_status & 0x7fff))
        else:
            self.answers += (b'\x00' + res +
                             payload[:data_len].ljust(data_len, b'\0'))

    def finish(self, args, sysfs_dir):
        if self.answers is None:
            return
        pci = None
        dev = Path(sysfs_dir) / 'sys/class/nvme/nvme0/device'
        try:
            pci = [int((dev / a).read_text(), 16)
                   for a in ('vendor', 'device')]
        except (OSError, ValueError):
            pass
        self.runs += 1
        name = f'{os.getpid()}-{self.runs}.json'
        with open(Path(self.dir) / name, 'w') as f:
            json.dump({'args': [str(a) for a in args], 'pci': pci,
                       'answers': self.answers.hex()}, f)
        self.answers = None


_fuzz_recorder = _FuzzRecorder()


class MockIPCServer(threading.Thread):
    """Generic Unix-socket IPC server for libmock_nvme.c.

    Subclasses hold their own test-scenario state and override
    handle_write()/handle_command() to fabricate responses for it. Socket
    setup, request framing, and thread lifecycle are shared here.

    An exception in a handler fails only that request, with EIO. The
    traceback is added to @errors, so a test can report it.
    """

    def __init__(self, sock_path):
        super().__init__()
        self.sock_path = sock_path
        self.running = True
        self.errors = []
        self.server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_sock.bind(self.sock_path)
        self.server_sock.listen(5)
        self.server_sock.settimeout(0.5)

    def run(self):
        while self.running:
            try:
                conn, _ = self.server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            self.handle_client(conn)

    @staticmethod
    def send_response(conn, status, errno_val=0, sc_status=0, result=0, payload=b""):
        """@status/@errno_val: a real syscall/errno-level failure (status=-1),
        vs. a normal ioctl() return (status=0). @sc_status: with status=0,
        the raw NVMe completion status ioctl() itself should return."""
        _fuzz_recorder.answer(status, sc_status, result, payload)
        conn.sendall(struct.pack(IPC_RESPONSE_FMT, status, errno_val, sc_status, result, len(payload)))
        if payload:
            conn.sendall(payload)

    def handle_write(self, conn, payload):
        """Override for IPC_TYPE_WRITE. Default: report success."""
        self.send_response(conn, 0)

    def handle_command(self, conn, cmd):
        """Override for IPC_TYPE_IOCTL. @cmd is the Command. Default: hand
        the command to handle_ioctl()."""
        self.handle_ioctl(conn, cmd.instance, None, cmd.opcode, cmd.nsid,
                          cmd.cdw10, cmd.cdw11, cmd.cdw12, cmd.cdw13,
                          cmd.cdw14, cmd.cdw15, cmd.lpo, cmd.data_len)

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                      cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        """Default: report success, result 0, no payload."""
        self.send_response(conn, 0)

    def handle_raw_ioctl(self, conn, fd, ioc, payload):
        """Override for IPC_TYPE_RAW_IOCTL. @fd is the controller instance,
        @ioc the RawIoctl request and @payload the argument bytes the
        caller passed in. For an IOC_READ ioctl, the response payload is
        copied back into the argument. sc_status is the ioctl() return
        value. Default: fail with ENOTTY, like a device that doesn't
        support the ioctl."""
        self.send_response(conn, -1, errno_val=errno.ENOTTY)

    def handle_getpass(self, conn, prompt):
        """Override for IPC_TYPE_GETPASS. The response payload is the
        password getpass() returns. Default: fail with ENOTTY, so
        getpass() returns NULL."""
        self.send_response(conn, -1, errno_val=errno.ENOTTY)

    def handle_route(self, conn, daddr, saddr):
        """Override for IPC_TYPE_ROUTE. @saddr is '' if the caller did
        not pass one. The response payload is the egress interface name.
        Default: fail with ENETUNREACH, so nvme-cli lets the kernel pick
        the number of I/O queues."""
        self.send_response(conn, -1, errno_val=errno.ENETUNREACH)

    def handle_nic_queues(self, conn, ifname):
        """Override for IPC_TYPE_NIC_QUEUES. The response payload is
        packed with NIC_QUEUES_FMT. Default: fail with EOPNOTSUPP, like a
        NIC without ethtool channel support."""
        self.send_response(conn, -1, errno_val=errno.EOPNOTSUPP)

    def handle_nprocs(self, conn):
        """Override for IPC_TYPE_NPROCS. The response result is the
        number of online CPUs. Default: fail, so get_nprocs() returns
        the real value."""
        self.send_response(conn, -1, errno_val=errno.ENOSYS)

    def handle_client(self, conn):
        try:
            req_header = conn.recv(IPC_REQUEST_LEN, socket.MSG_WAITALL)
            if len(req_header) < IPC_REQUEST_LEN:
                return

            req_type, fd, data_len, ioctl_request, opcode, nsid, \
                cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, req_len, \
                ioc_dir, ioc_type, ioc_nr, big_endian, ioc_size, \
                flags, cmd_flags, cdw2, cdw3, metadata_len, timeout_ms = \
                struct.unpack(IPC_REQUEST_FMT, req_header)

            payload = (conn.recv(data_len, socket.MSG_WAITALL)
                       if data_len > 0 else b"")

            if req_type == IPC_TYPE_IOCTL:
                _fuzz_recorder.request(req_len)
            elif req_type == IPC_TYPE_RAW_IOCTL:
                _fuzz_recorder.request(ioc_size if ioc_dir & IOC_READ else 0)
            else:
                _fuzz_recorder.request(None)

            if req_type == IPC_TYPE_WRITE:
                self.handle_write(conn, payload)
            elif req_type == IPC_TYPE_IOCTL:
                data = metadata = None
                if cmd_flags & IPC_CMD_DATA:
                    data, payload = payload[:req_len], payload[req_len:]
                if cmd_flags & IPC_CMD_METADATA:
                    metadata = payload
                # fd is the controller instance, not a real fd (see
                # libmock_nvme.c)
                cmd = Command(fd, bool(cmd_flags & IPC_CMD_ADMIN), opcode,
                              flags, nsid, cdw2, cdw3, cdw10, cdw11, cdw12,
                              cdw13, cdw14, cdw15, req_len, metadata_len,
                              timeout_ms, data, metadata)
                self.handle_command(conn, cmd)
            elif req_type == IPC_TYPE_RAW_IOCTL:
                ioc = RawIoctl(ioctl_request, ioc_dir, ioc_type, ioc_nr,
                               ioc_size, bool(big_endian))
                self.handle_raw_ioctl(conn, fd, ioc, payload)
            elif req_type == IPC_TYPE_GETPASS:
                self.handle_getpass(conn, payload.decode('utf-8', 'replace'))
            elif req_type == IPC_TYPE_ROUTE:
                daddr, _, saddr = payload.decode('utf-8', 'replace').partition('\0')
                self.handle_route(conn, daddr, saddr)
            elif req_type == IPC_TYPE_NIC_QUEUES:
                self.handle_nic_queues(conn, payload.decode('utf-8', 'replace'))
            elif req_type == IPC_TYPE_NPROCS:
                self.handle_nprocs(conn)
        except OSError as e:
            print(f"Exception handling IPC client: {e}", file=sys.stderr)
        except Exception:
            self.errors.append(traceback.format_exc())
            print(self.errors[-1], file=sys.stderr)
            try:
                self.send_response(conn, -1, errno_val=errno.EIO)
            except OSError:
                pass
        finally:
            conn.close()

    def shutdown(self):
        self.running = False
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(self.sock_path)
            client.close()
        except OSError:
            pass
        self.server_sock.close()


def make_mock_env(mock_lib, ipc_sock_path):
    """Builds the environment run_nvme() needs. Appends @mock_lib to
    LD_PRELOAD instead of replacing it, so an existing entry like libasan
    stays first. Sets MOCK_IPC_SOCK. Also tweaks ASAN_OPTIONS, so ASan does
    not warn or abort over libmock_nvme.so not being first in LD_PRELOAD:
    we do not control that order, and it is not a real problem here."""
    env = os.environ.copy()
    existing_preload = env.get("LD_PRELOAD", "")
    env["LD_PRELOAD"] = f"{existing_preload} {mock_lib}".strip()
    existing_asan_options = env.get("ASAN_OPTIONS", "")
    env["ASAN_OPTIONS"] = f"{existing_asan_options}:verify_asan_link_order=0".strip(':')
    env["MOCK_IPC_SOCK"] = ipc_sock_path
    return env


# Limits for one nvme run. Bad data from the mock device can make nvme
# allocate without bound or loop forever. Without a limit, it can use all
# the memory of the machine.
_NVME_MEM_LIMIT_MB = 1024
_NVME_TIMEOUT_S = 60


def _is_asan_binary(nvme_bin):
    """ASan reserves terabytes of address space, so RLIMIT_AS cannot be
    used. Use ASan's own RSS limit instead."""
    path = shutil.which(nvme_bin) or nvme_bin
    try:
        with open(path, 'rb') as f:
            return b'__asan_init' in f.read()
    except OSError:
        return False


def run_nvme(nvme_bin, env, sysfs_dir, base_dir, *args, encoding='utf-8',
             stdin_data=None, stack_limit_kb=None, close_fd=None):
    """Runs `nvme_bin *args` under libmock_nvme.c. Returns the completed
    subprocess.Popen result, with stdout/stderr captured as text. Callers
    check .returncode/.stdout/.stderr themselves.

    Pass encoding=None to capture stdout/stderr as bytes instead, for
    commands whose output is not text ('-o binary'). Pass @stdin_data to
    feed it to stdin, e.g. to answer a confirmation prompt. Otherwise
    stdin is /dev/null. Pass @stack_limit_kb to run nvme with that
    stack size limit. Pass @close_fd to run nvme with that standard
    descriptor closed."""
    cmd = [
        nvme_bin,
        '--set-options', f'test-sysfs-dir={sysfs_dir},test-base-dir={base_dir}',
    ] + list(args)

    # Under 'meson test --setup=valgrind' this script runs under valgrind,
    # but nvme must run natively. Valgrind rewrites LD_PRELOAD on every
    # execve() it traps, to strip its own vgpreload bookkeeping. That wipes
    # out our appended mock lib entry too, since it is part of the same
    # string. So route through a shell: valgrind sees and mangles the
    # exec() below, but the shell's own exec of nvme runs in a process
    # valgrind no longer traces. The LD_PRELOAD set there reaches nvme
    # intact.
    env = dict(env)
    ld_preload = env.pop("LD_PRELOAD", "")
    if os.environ.get('MESON_EXE_WRAPPER'):
        # A cross build runs nvme under qemu-user, which needs the whole
        # guest address space.
        ulimit = ''
    elif _is_asan_binary(nvme_bin):
        env['ASAN_OPTIONS'] = ':'.join(filter(None, [
            env.get('ASAN_OPTIONS'),
            f'hard_rss_limit_mb={_NVME_MEM_LIMIT_MB}']))
        ulimit = ''
    else:
        ulimit = f'ulimit -v {_NVME_MEM_LIMIT_MB * 1024}; '
    # The shell sets the limit: a preexec_fn is unsafe in the child of a
    # process that, like the mock server, runs threads.
    if stack_limit_kb is not None:
        ulimit += f'ulimit -s {int(stack_limit_kb)}; '
    close = f' {int(close_fd)}>&-' if close_fd is not None else ''
    wrapped_cmd = [
        '/bin/sh', '-c',
        f'{ulimit}export LD_PRELOAD={shlex.quote(ld_preload)}; exec "$@"{close}',
        'nvme-mock-wrapper',
    ] + cmd

    stdin_args = ({'input': stdin_data} if stdin_data is not None
                  else {'stdin': subprocess.DEVNULL})
    _fuzz_recorder.start()
    result = subprocess.run(wrapped_cmd, env=env,
                            **stdin_args,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            encoding=encoding,
                            errors='replace' if encoding else None,
                            timeout=_NVME_TIMEOUT_S)
    _fuzz_recorder.finish(args, sysfs_dir)

    # Print outputs to sys.stderr so they are displayed by unittest on
    # failure. With encoding=None these are bytes, so summarise stdout
    # rather than dumping a binary blob into the log.
    print(f"\n--- RUN: {' '.join(cmd)} ---", file=sys.stderr)
    if encoding is None:
        print(f"STDOUT: {len(result.stdout)} bytes", file=sys.stderr)
        print(f"STDERR:\n{result.stderr.decode('utf-8', 'replace')}",
              file=sys.stderr)
    else:
        print(f"STDOUT:\n{result.stdout}", file=sys.stderr)
        print(f"STDERR:\n{result.stderr}", file=sys.stderr)
    print("-----------------------------------", file=sys.stderr)

    return result
