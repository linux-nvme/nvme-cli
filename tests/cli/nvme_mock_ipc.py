#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.com>
"""libmock_nvme.c intercepts open()/write()/ioctl()/close() on
/dev/nvme-fabrics, /dev/nvme<N>, and /dev/nvme<N>n<M>. It forwards every
intercepted write() (fabrics connect args) and ioctl() (admin or I/O
passthru command) over a Unix socket to a MockIPCServer instance running in
this process. This lets nvme-cli run against a fake target, with no real
hardware and no root.

Test files subclass MockIPCServer and override handle_write()/
handle_ioctl() to steer responses for their own scenario. run_nvme()
provides the common subprocess-invocation mechanics.
"""
import os
import shlex
import socket
import struct
import subprocess
import sys
import threading
from pathlib import Path

# IPC wire format shared with libmock_nvme.c -- keep both sides in sync.
IPC_REQUEST_FMT = "=IIII B3x I IIIIII QI"
IPC_REQUEST_LEN = struct.calcsize(IPC_REQUEST_FMT)
IPC_RESPONSE_FMT = "=iiII"

IPC_TYPE_WRITE = 1  # write() on /dev/nvme-fabrics (connect args)
IPC_TYPE_IOCTL = 2  # ioctl() admin or I/O passthru command


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


class MockIPCServer(threading.Thread):
    """Generic Unix-socket IPC server for libmock_nvme.c.

    Subclasses hold their own test-scenario state and override
    handle_write()/handle_ioctl() to fabricate responses for it. Socket
    setup, request framing, and thread lifecycle are shared here.
    """

    def __init__(self, sock_path):
        super().__init__()
        self.sock_path = sock_path
        self.running = True
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
    def send_response(conn, status, errno_val=0, result=0, payload=b""):
        conn.sendall(struct.pack(IPC_RESPONSE_FMT, status, errno_val, result, len(payload)))
        if payload:
            conn.sendall(payload)

    def handle_write(self, conn, payload):
        """Override for IPC_TYPE_WRITE. Default: report success."""
        self.send_response(conn, 0)

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                      cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        """Override for IPC_TYPE_IOCTL. @fd is the controller instance, not
        a real fd (see libmock_nvme.c). Default: report success, result 0,
        no payload."""
        self.send_response(conn, 0)

    def handle_client(self, conn):
        try:
            req_header = conn.recv(IPC_REQUEST_LEN, socket.MSG_WAITALL)
            if len(req_header) < IPC_REQUEST_LEN:
                return

            req_type, fd, data_len, ioctl_request, opcode, nsid, \
                cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len = \
                struct.unpack(IPC_REQUEST_FMT, req_header)

            payload = (conn.recv(data_len, socket.MSG_WAITALL)
                       if data_len > 0 else b"")

            if req_type == IPC_TYPE_WRITE:
                self.handle_write(conn, payload)
            elif req_type == IPC_TYPE_IOCTL:
                self.handle_ioctl(conn, fd, ioctl_request, opcode, nsid,
                                   cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len)
        except OSError as e:
            print(f"Exception handling IPC client: {e}", file=sys.stderr)
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


def run_nvme(nvme_bin, env, sysfs_dir, base_dir, *args):
    """Runs `nvme_bin *args` under libmock_nvme.c. Returns the completed
    subprocess.Popen result, with stdout/stderr captured as text. Callers
    check .returncode/.stdout/.stderr themselves."""
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
    wrapped_cmd = [
        '/bin/sh', '-c', f'export LD_PRELOAD={shlex.quote(ld_preload)}; exec "$@"',
        'nvme-mock-wrapper',
    ] + cmd

    result = subprocess.run(wrapped_cmd, env=env,
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            encoding='utf-8')

    # Print outputs to sys.stderr so they are displayed by unittest on failure.
    print(f"\n--- RUN: {' '.join(cmd)} ---", file=sys.stderr)
    print(f"STDOUT:\n{result.stdout}", file=sys.stderr)
    print(f"STDERR:\n{result.stderr}", file=sys.stderr)
    print("-----------------------------------", file=sys.stderr)

    return result
