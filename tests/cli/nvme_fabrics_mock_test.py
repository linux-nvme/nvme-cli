#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.com>
"""Integration tests for 'nvme discover', 'nvme connect', and 'nvme connect-all'.

Uses LD_PRELOAD mocking (see libmock_fabrics.c), so no real NVMe hardware or
root privileges are required. The mock shim forwards every connect() write
and admin passthru ioctl() over a Unix socket to the MockIPCServer below,
which is steered per-test to fabricate discovery log pages, Identify data,
and simulated errno failures.

Usage: python3 nvme_fabrics_mock_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
import os
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

# Capture the nvme binary path and preload library path from argv before
# unittest.main() strips them.
_NVME_BIN = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else 'nvme'

# NVMe-oF well-known discovery subsystem NQN (NVME_DISC_SUBSYS_NAME).
DISCOVERY_NQN = "nqn.2014-08.org.nvmexpress.discovery"
# Default TCP port used for discovery controller connections (NVME_DISC_IP_PORT).
DISCOVERY_PORT = "8009"

# struct nvmf_disc_log_entry SUBTYPE field (enum nvmf_disc_subtype).
NVME_NQN_DISC = 1   # Referral to another Discovery Controller
NVME_NQN_NVME = 2   # I/O (non-discovery) NVM subsystem
NVME_NQN_CURR = 3   # This Discovery Controller's own port

# struct nvmf_disc_log_entry EFLAGS bit (enum nvmf_disc_eflags).
NVMF_DISC_EFLAGS_EPCSD = 1 << 1

# IPC wire format shared with libmock_fabrics.c -- keep both sides in sync.
_IPC_REQUEST_FMT = "=IIII B3x I IIIIII QI"
_IPC_REQUEST_LEN = struct.calcsize(_IPC_REQUEST_FMT)
_IPC_RESPONSE_FMT = "=iiII"

_NVME_OPCODE_GET_LOG_PAGE = 0x02
_NVME_OPCODE_IDENTIFY = 0x06
_DISCOVERY_LOG_LID = 0x70


def resolve_mock_lib_path():
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
    return "./libmock_fabrics.so"


_MOCK_LIB = resolve_mock_lib_path()


def _pack_disc_log_entry(portid, entry):
    """Packs one 1024-byte struct nvmf_disc_log_entry from a test-supplied dict.

    Recognized keys: transport, traddr, trsvcid, subsysnqn, eflags, subtype.
    'subtype' defaults to NVME_NQN_DISC for referral-looking NQNs (containing
    "discovery" or "dc-") and NVME_NQN_NVME otherwise; 'eflags' defaults to 0.
    """
    transport = entry.get('transport', 'tcp')
    traddr = entry.get('traddr', '')
    trsvcid = entry.get('trsvcid', '4420')
    subsysnqn = entry.get('subsysnqn', '')
    eflags = entry.get('eflags', 0)

    subtype = entry.get('subtype')
    if subtype is None:
        subtype = NVME_NQN_DISC if ('discovery' in subsysnqn or 'dc-' in subsysnqn) else NVME_NQN_NVME

    trtype = {'tcp': 3, 'rdma': 1, 'fc': 2}.get(transport, 254)
    adrfam = 4 if transport == 'fc' else (1 if transport in ('tcp', 'rdma') else 254)

    header = struct.pack("=BBBBHHHH", trtype, adrfam, subtype, 0, portid, 0xffff, 32, eflags)
    rsvd12 = b"\x00" * 20
    trsvcid_bytes = trsvcid.encode('utf-8').ljust(32, b"\x00")
    rsvd64 = b"\x00" * 192
    subnqn_bytes = subsysnqn.encode('utf-8').ljust(256, b"\x00")
    traddr_bytes = traddr.encode('utf-8').ljust(256, b"\x00")
    tsas = b"\x00" * 256

    return header + rsvd12 + trsvcid_bytes + rsvd64 + subnqn_bytes + traddr_bytes + tsas


class MockIPCServer(threading.Thread):
    def __init__(self, sock_path):
        super().__init__()
        self.sock_path = sock_path
        self.running = True
        self.server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_sock.bind(self.sock_path)
        self.server_sock.listen(5)
        self.server_sock.settimeout(0.5)

        # Test-specific state overrides, steered from Python tests.
        self.connect_errno = 0
        self.ioctl_errno = 0
        self.discovery_entries = []  # fallback list of dicts (see _pack_disc_log_entry)
        self.discovery_map = {}      # maps subsysnqn (str) -> list of dicts
        self.model_number = "Mock NVMe Controller"
        self.serial_number = "MOCK_SERIAL_NUM_123"
        self.next_instance = 0
        self.sysfs_dir = None
        self.controllers = {}        # maps instance (int) -> dict of connect options
        self.log_page_fetch_count = {}  # maps subsysnqn (str) -> completed-fetch count

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
    def _send_response(conn, status, errno_val=0, result=0, payload=b""):
        conn.sendall(struct.pack(_IPC_RESPONSE_FMT, status, errno_val, result, len(payload)))
        if payload:
            conn.sendall(payload)

    def _handle_connect(self, conn, payload):
        if self.connect_errno != 0:
            self._send_response(conn, -1, errno_val=self.connect_errno)
            return

        opts = {}
        for part in payload.decode('utf-8', errors='ignore').split(','):
            if '=' in part:
                k, v = part.split('=', 1)
                opts[k.strip()] = v.strip()

        inst = int(opts.get('instance', self.next_instance))
        if 'instance' not in opts:
            self.next_instance += 1

        subsysnqn = opts.get('nqn', opts.get('subsysnqn', ''))
        transport = opts.get('transport', 'tcp')
        traddr = opts.get('traddr', '')
        trsvcid = opts.get('trsvcid', '4420')
        host_traddr = opts.get('host_traddr', 'none')
        host_iface = opts.get('host_iface', 'none')
        hostnqn = opts.get('hostnqn', '')
        hostid = opts.get('hostid', '')

        self.controllers[inst] = {
            'subsysnqn': subsysnqn,
            'transport': transport,
            'traddr': traddr,
            'trsvcid': trsvcid,
        }

        if self.sysfs_dir:
            self._write_sysfs_ctrl(inst, subsysnqn, transport, traddr, trsvcid,
                                    host_traddr, host_iface, hostnqn, hostid)

        resp_payload = f"instance={inst}\n".encode('utf-8')
        self._send_response(conn, 0, payload=resp_payload)

    def _write_sysfs_ctrl(self, inst, subsysnqn, transport, traddr, trsvcid,
                           host_traddr, host_iface, hostnqn, hostid):
        ctrl_path = Path(self.sysfs_dir) / f"sys/class/nvme/nvme{inst}"
        ctrl_path.mkdir(parents=True, exist_ok=True)

        (ctrl_path / "transport").write_text(f"{transport}\n")

        addr_str = f"traddr={traddr},trsvcid={trsvcid}"
        if host_traddr not in ('none', ''):
            addr_str += f",host_traddr={host_traddr}"
        if host_iface not in ('none', ''):
            addr_str += f",host_iface={host_iface}"
        (ctrl_path / "address").write_text(addr_str + "\n")

        (ctrl_path / "subsysnqn").write_text(f"{subsysnqn}\n")
        (ctrl_path / "state").write_text("live\n")
        (ctrl_path / "delete_controller").write_text("")

        if hostnqn:
            (ctrl_path / "hostnqn").write_text(f"{hostnqn}\n")
        if hostid:
            (ctrl_path / "hostid").write_text(f"{hostid}\n")

        sub_path = Path(self.sysfs_dir) / f"sys/class/nvme-subsystem/nvme-subsys{inst}"
        sub_path.mkdir(parents=True, exist_ok=True)
        (sub_path / "subsysnqn").write_text(f"{subsysnqn}\n")
        (sub_path / f"nvme{inst}").mkdir(exist_ok=True)

    def _handle_ioctl(self, conn, fd, opcode, cdw10, lpo, req_len):
        if self.ioctl_errno != 0:
            self._send_response(conn, -1, errno_val=self.ioctl_errno)
            return

        resp_payload = b""

        if opcode == _NVME_OPCODE_GET_LOG_PAGE and (cdw10 & 0xff) == _DISCOVERY_LOG_LID:
            # fd carries the controller instance for IOCTLs (see libmock_fabrics.c).
            ctrl_nqn = self.controllers.get(fd, {}).get('subsysnqn', '')
            entries = self.discovery_map.get(ctrl_nqn, self.discovery_entries)

            log_entries = b"".join(_pack_disc_log_entry(i + 1, e) for i, e in enumerate(entries))
            log_header = struct.pack("<QQH", 1, len(entries), 0) + b"\x00" * 1006
            full_log = log_header + log_entries

            # libnvmf_get_discovery_log() reads the header twice (lpo=0: once
            # to size the entries, once after to re-check genctr) but the
            # entries themselves (lpo != 0) exactly once per completed
            # fetch -- count that one, not the header reads, so a caller can
            # tell "was this DC's DLP walked" from "was it walked twice".
            if lpo != 0:
                self.log_page_fetch_count[ctrl_nqn] = \
                    self.log_page_fetch_count.get(ctrl_nqn, 0) + 1

            if lpo < len(full_log):
                resp_payload = full_log[lpo:lpo + req_len]

        elif opcode == _NVME_OPCODE_IDENTIFY:
            vid = struct.pack("<HH", 0x105b, 0x105b)
            sn_bytes = self.serial_number.encode('utf-8').ljust(20, b" ")[:20]
            mn_bytes = self.model_number.encode('utf-8').ljust(40, b" ")[:40]
            fr_bytes = b"MOCK1234".ljust(8, b" ")[:8]
            rsvd = b"\x00" * (4096 - len(vid) - len(sn_bytes) - len(mn_bytes) - len(fr_bytes))
            resp_payload = (vid + sn_bytes + mn_bytes + fr_bytes + rsvd)[:req_len]

        self._send_response(conn, 0, payload=resp_payload)

    def handle_client(self, conn):
        try:
            req_header = conn.recv(_IPC_REQUEST_LEN)
            if len(req_header) < _IPC_REQUEST_LEN:
                return

            req_type, fd, data_len, _ioctl_request, opcode, _nsid, \
                cdw10, _cdw11, _cdw12, _cdw13, _cdw14, _cdw15, lpo, req_len = \
                struct.unpack(_IPC_REQUEST_FMT, req_header)

            payload = conn.recv(data_len) if data_len > 0 else b""

            if req_type == 1:    # WRITE (connect args)
                self._handle_connect(conn, payload)
            elif req_type == 2:  # IOCTL (admin passthru)
                self._handle_ioctl(conn, fd, opcode, cdw10, lpo, req_len)
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


class FabricsMockCLITest(unittest.TestCase):

    def setUp(self):
        print(f"\n[DIAG] os.getcwd(): {os.getcwd()}", file=sys.stderr)
        print(f"[DIAG] _MOCK_LIB: {_MOCK_LIB}", file=sys.stderr)
        print(f"[DIAG] _MOCK_LIB exists: {Path(_MOCK_LIB).exists()}", file=sys.stderr)

        self.sysfs_dir = tempfile.mkdtemp(prefix='nvme-mock-sysfs-', dir='/tmp')
        self.base_dir = tempfile.mkdtemp(prefix='nvme-mock-base-', dir='/tmp')

        Path(f"{self.sysfs_dir}/sys/class/nvme").mkdir(parents=True, exist_ok=True)
        Path(f"{self.sysfs_dir}/sys/class/nvme-subsystem").mkdir(parents=True, exist_ok=True)

        self.ipc_dir = tempfile.mkdtemp(prefix='nvme-mock-ipc-', dir='/tmp')
        self.ipc_sock_path = os.path.join(self.ipc_dir, "ipc.sock")

        self.server = MockIPCServer(self.ipc_sock_path)
        self.server.sysfs_dir = self.sysfs_dir
        self.server.start()

        self.env = os.environ.copy()
        # Append (don't clobber) LD_PRELOAD so an existing entry, e.g.
        # libasan, is kept. If libasan isn't first in the LD_PRELOAD list,
        # ASan warns/aborts because its interceptors weren't installed
        # first; verify_asan_link_order=0 silences that check, since we
        # can't control the order and it isn't a real problem here.
        existing_preload = self.env.get("LD_PRELOAD", "")
        self.env["LD_PRELOAD"] = f"{existing_preload} {_MOCK_LIB}".strip()
        existing_asan_options = self.env.get("ASAN_OPTIONS", "")
        self.env["ASAN_OPTIONS"] = f"{existing_asan_options}:verify_asan_link_order=0".strip(':')
        self.env["MOCK_IPC_SOCK"] = self.ipc_sock_path

    def tearDown(self):
        self.server.shutdown()
        self.server.join()

        shutil.rmtree(self.sysfs_dir, ignore_errors=True)
        shutil.rmtree(self.base_dir, ignore_errors=True)
        shutil.rmtree(self.ipc_dir, ignore_errors=True)

    def _run(self, *args, expect_fail=False):
        cmd = [
            _NVME_BIN,
            '--set-options', f'test-sysfs-dir={self.sysfs_dir},test-base-dir={self.base_dir}',
        ] + list(args)

        # Under 'meson test --setup=valgrind' this script itself runs under
        # valgrind, but nvme must run natively. Valgrind rewrites LD_PRELOAD
        # on every execve() it traps (to strip its own vgpreload bookkeeping),
        # which wipes out our appended mock lib entry too since it's part of
        # the same string. Route through a shell: the exec() below is what
        # valgrind sees and mangles, but the shell's own subsequent exec of
        # nvme happens in a process valgrind no longer traces, so the
        # LD_PRELOAD it sets there reaches nvme intact.
        env = dict(self.env)
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

        if not expect_fail:
            self.assertEqual(result.returncode, 0,
                             f'Command {cmd} failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}')
        else:
            self.assertNotEqual(result.returncode, 0,
                                f'Command {cmd} was expected to fail but succeeded')
        return result

    def _ctrl_path(self, instance):
        return Path(f"{self.sysfs_dir}/sys/class/nvme/nvme{instance}")

    def _subsysnqn(self, instance):
        return (self._ctrl_path(instance) / "subsysnqn").read_text().strip()

    def _assert_persisted(self, instance, msg=""):
        """delete_controller stays empty as long as libnvmf_disconnect_ctrl()
        (which writes "1" to it) is never called for this controller."""
        content = (self._ctrl_path(instance) / "delete_controller").read_text()
        self.assertEqual(content, "", msg or f"nvme{instance} was disconnected, expected it to persist")

    def _assert_disconnected(self, instance, msg=""):
        content = (self._ctrl_path(instance) / "delete_controller").read_text()
        self.assertEqual(content, "1", msg or f"nvme{instance} was not disconnected")

    # ------------------------------------------------------------------ #
    # Test cases                                                         #
    # ------------------------------------------------------------------ #

    def test_discover_simple(self):
        """Test simple discovery retrieval."""
        self.server.discovery_entries = [
            {
                'transport': 'tcp',
                'traddr': '192.168.1.200',
                'trsvcid': '4420',
                'subsysnqn': 'nqn.2014-08.org.nvmexpress:uuid:mock-target-nvm-subsystem',
            },
        ]
        res = self._run('discover', '-t', 'tcp', '-a', '192.168.1.1')

        # Verify stdout contains our mock subsystem NQN and address.
        self.assertIn("mock-target-nvm-subsystem", res.stdout)
        self.assertIn("192.168.1.200", res.stdout)
        self.assertIn("4420", res.stdout)

    def test_connect_simple(self):
        """Test connecting to a single target."""
        subsysnqn = "nqn.2014-08.org.nvmexpress:uuid:my-io-subsys-1"
        self._run('connect', '-t', 'tcp', '-a', '192.168.1.10', '-s', '4420', '-n', subsysnqn)

        # The command should succeed, and our mock should have created the sysfs entries.
        ctrl_path = self._ctrl_path(0)
        self.assertTrue(ctrl_path.exists(), "Mock controller directory was not created under sysfs")

        self.assertEqual((ctrl_path / "transport").read_text().strip(), "tcp")
        self.assertEqual(self._subsysnqn(0), subsysnqn)
        self.assertIn("traddr=192.168.1.10", (ctrl_path / "address").read_text())

    def test_connect_all_recursive(self):
        """Test connect-all recursive discovery cascade."""
        # Setup pre-configured mock discovery log entries pointing to two standard I/O controllers.
        subsys1 = "nqn.2014-08.org.nvmexpress:uuid:io-subsys-A"
        subsys2 = "nqn.2014-08.org.nvmexpress:uuid:io-subsys-B"
        self.server.discovery_entries = [
            {'transport': 'tcp', 'traddr': '192.168.5.1', 'trsvcid': '4420', 'subsysnqn': subsys1},
            {'transport': 'tcp', 'traddr': '192.168.5.2', 'trsvcid': '4420', 'subsysnqn': subsys2},
        ]

        self._run('connect-all', '-t', 'tcp', '-a', '192.168.1.1')

        # Connecting with connect-all to a discovery controller should first connect to the
        # discovery controller (nvme0), read the discovery log (returning our 2 entries),
        # and then connect to the two listed I/O controllers (nvme2 and nvme3).
        self.assertTrue(self._ctrl_path(0).exists(), "Discovery controller (nvme0) not created")
        self.assertTrue(self._ctrl_path(2).exists(), "First I/O controller (nvme2) not created")
        self.assertTrue(self._ctrl_path(3).exists(), "Second I/O controller (nvme3) not created")

        self.assertEqual(self._subsysnqn(2), subsys1)
        self.assertEqual(self._subsysnqn(3), subsys2)

    def test_connect_already_connected(self):
        """Test how connect handles EALREADY (already connected) error gracefully."""
        self.server.connect_errno = 114  # EALREADY
        subsysnqn = "nqn.2014-08.org.nvmexpress:uuid:my-io-subsys-1"

        # Without --verbose, EALREADY is reported through the exit code alone --
        # no "already connected" text on either stream, so scripts don't have to
        # filter it out of normal output.
        res = self._run('connect', '-t', 'tcp', '-a', '192.168.1.10', '-s', '4420', '-n', subsysnqn,
                        expect_fail=True)
        self.assertNotIn("already connected", res.stdout)
        self.assertNotIn("already connected", res.stderr)

        # -v surfaces the detail. nvme-cli reports it itself (rather than relying
        # on libnvme's own internal logging), so it lands on stdout as info --
        # nvme-cli's own --verbose output is not the same thing as libnvme's
        # internal logging, which is what moved to stderr.
        res = self._run('connect', '-t', 'tcp', '-a', '192.168.1.10', '-s', '4420', '-n', subsysnqn,
                        '-v', expect_fail=True)
        self.assertIn("already connected", res.stdout)

    def test_connect_already_connected_idempotent(self):
        """--idempotent turns EALREADY into success (exit 0) instead of a
        failure, still silent unless --verbose is given."""
        self.server.connect_errno = 114  # EALREADY
        subsysnqn = "nqn.2014-08.org.nvmexpress:uuid:my-io-subsys-1"

        res = self._run('connect', '-t', 'tcp', '-a', '192.168.1.10', '-s', '4420', '-n', subsysnqn,
                        '--idempotent')
        self.assertNotIn("already connected", res.stdout)
        self.assertNotIn("already connected", res.stderr)

        res = self._run('connect', '-t', 'tcp', '-a', '192.168.1.10', '-s', '4420', '-n', subsysnqn,
                        '--idempotent', '-v')
        self.assertIn("already connected", res.stdout)

    def test_custom_identify(self):
        """Test getting custom Identify Controller fields steered by environment."""
        # Create a mock controller nvme0 in sysfs first, so nvme list has something to read.
        subsysnqn = "nqn.2014-08.org.nvmexpress:uuid:my-io-subsys-1"
        inst_dir = self._ctrl_path(0)
        inst_dir.mkdir(parents=True, exist_ok=True)
        (inst_dir / "transport").write_text("tcp\n")
        (inst_dir / "address").write_text("traddr=192.168.1.10,trsvcid=4420\n")
        (inst_dir / "subsysnqn").write_text(f"{subsysnqn}\n")
        (inst_dir / "state").write_text("live\n")

        sub_dir = Path(f"{self.sysfs_dir}/sys/class/nvme-subsystem/nvme-subsys0")
        sub_dir.mkdir(parents=True, exist_ok=True)
        (sub_dir / "subsysnqn").write_text(f"{subsysnqn}\n")
        (sub_dir / "nvme0").mkdir(exist_ok=True)

        custom_sn = "SN_MOCK_XYZ_999"
        custom_mn = "Model_Mock_SuperFast_PRO"
        self.server.serial_number = custom_sn
        self.server.model_number = custom_mn

        # Use admin-passthru to submit an Identify Controller admin command (opcode 0x06, CNS 1)
        # to our mock character device and assert that it receives our customized parameters.
        res = self._run('admin-passthru', '/dev/nvme0', '-O', '0x06', '-4', '1', '-l', '4096', '-r')

        # The output printed contains ASCII interpretation of the hex dump.
        # Since it can be formatted/wrapped, we search for contiguous parts.
        self.assertIn("SN_MOCK_XYZ_", res.stdout)
        self.assertIn("999", res.stdout)
        self.assertIn("Model_Mo", res.stdout)
        self.assertIn("ck_SuperFast", res.stdout)

    def test_connect_all_three_hop_referral_cascade(self):
        """Test connect-all with three Discovery Controllers in a referral chain: DC a -> DC b -> DC c -> IO subsys C."""
        dc_a = "nqn.2014-08.org.nvmexpress:uuid:dc-A"
        dc_b = "nqn.2014-08.org.nvmexpress:uuid:dc-B"
        dc_c = "nqn.2014-08.org.nvmexpress:uuid:dc-C"
        io_c = "nqn.2014-08.org.nvmexpress:uuid:io-subsys-C"

        # Configure our Python mock server to map each subsystem NQN to its specific log entries.
        self.server.discovery_map = {
            dc_a: [{'transport': 'tcp', 'traddr': '192.168.100.2', 'trsvcid': '4420', 'subsysnqn': dc_b}],
            dc_b: [{'transport': 'tcp', 'traddr': '192.168.100.3', 'trsvcid': '4420', 'subsysnqn': dc_c}],
            dc_c: [{'transport': 'tcp', 'traddr': '192.168.100.4', 'trsvcid': '4420', 'subsysnqn': io_c}],
        }

        # Connect to the first discovery controller (DC a), which should trigger the recursive cascade.
        self._run('connect-all', '-t', 'tcp', '-a', '192.168.100.1', '-n', dc_a)

        # Verify that all controllers are successfully connected under sysfs:
        # DC a -> nvme0, DC b -> nvme1, DC c -> nvme2, IO C -> nvme3.
        self.assertTrue(self._ctrl_path(0).exists(), "DC a (nvme0) not created")
        self.assertTrue(self._ctrl_path(1).exists(), "DC b (nvme1) not created")
        self.assertTrue(self._ctrl_path(2).exists(), "DC c (nvme2) not created")
        self.assertTrue(self._ctrl_path(3).exists(), "IO c (nvme3) not created")

        self.assertEqual(self._subsysnqn(0), dc_a)
        self.assertEqual(self._subsysnqn(1), dc_b)
        self.assertEqual(self._subsysnqn(2), dc_c)
        self.assertEqual(self._subsysnqn(3), io_c)

    # ------------------------------------------------------------------ #
    # --persistent=[no|auto|force] and EPCSD corner cases                #
    # ------------------------------------------------------------------ #
    #
    # A discovery controller's own EPCSD (Explicit Persistent Connection
    # Support for Discovery) is only ever reported in the "current discovery
    # subsystem" entry it returns about itself (SUBTYPE=03h, NVME_NQN_CURR).
    # These tests supply that self-entry with traddr/trsvcid matching the
    # connection actually opened by `discover`/`connect-all` (no transport
    # options, default TCP discovery port 8009) so libnvme recognizes it as
    # describing the very connection it's deciding whether to keep.
    #
    # Every `discover` invocation below first does a throwaway probe connect
    # to look up any registered owner (nvme0 -- always torn down regardless
    # of --persistent) before opening the real discovery connection whose
    # persistence is under test (nvme1).
    _PROBE_INSTANCE = 0
    _DISCOVERY_INSTANCE = 1

    def _self_entry(self, addr, eflags=0, trsvcid=DISCOVERY_PORT, subsysnqn=DISCOVERY_NQN):
        return {
            'subtype': NVME_NQN_CURR,
            'transport': 'tcp',
            'traddr': addr,
            'trsvcid': trsvcid,
            'subsysnqn': subsysnqn,
            'eflags': eflags,
        }

    def test_discover_persistent_default_disconnects(self):
        """Without --persistent, the discovery controller is always torn down, EPCSD or not."""
        addr = '192.168.10.1'
        self.server.discovery_entries = [self._self_entry(addr, eflags=NVMF_DISC_EFLAGS_EPCSD)]

        self._run('discover', '-t', 'tcp', '-a', addr)
        self._assert_disconnected(self._DISCOVERY_INSTANCE)

    def test_discover_persistent_no_ignores_epcsd(self):
        """--persistent=no behaves like the default: always disconnect, even with EPCSD set."""
        addr = '192.168.10.2'
        self.server.discovery_entries = [self._self_entry(addr, eflags=NVMF_DISC_EFLAGS_EPCSD)]

        self._run('discover', '-t', 'tcp', '-a', addr, '--persistent=no')
        self._assert_disconnected(self._DISCOVERY_INSTANCE)

    def test_discover_persistent_auto_epcsd_set_persists(self):
        """--persistent (bare => auto) keeps the connection when the entry's own EPCSD is set."""
        addr = '192.168.10.3'
        self.server.discovery_entries = [self._self_entry(addr, eflags=NVMF_DISC_EFLAGS_EPCSD)]

        self._run('discover', '-t', 'tcp', '-a', addr, '--persistent')
        self._assert_persisted(self._DISCOVERY_INSTANCE)

    def test_discover_persistent_auto_epcsd_unset_disconnects(self):
        """--persistent=auto degrades to non-persistent (with a warning) when EPCSD isn't set."""
        addr = '192.168.10.4'
        self.server.discovery_entries = [self._self_entry(addr, eflags=0)]

        # -v raises the log level to WARN so the "not persisting" message shows up.
        # It's libnvme's own internal diagnostic, so it lands on stderr, not stdout.
        res = self._run('discover', '-t', 'tcp', '-a', addr, '--persistent=auto', '-v')
        self._assert_disconnected(self._DISCOVERY_INSTANCE)
        self.assertIn("EPCSD", res.stderr)

    def test_discover_persistent_auto_no_self_entry_disconnects(self):
        """No self-entry (SUBTYPE=03h) at all is defined identically to EPCSD=0."""
        addr = '192.168.10.5'
        self.server.discovery_entries = []

        self._run('discover', '-t', 'tcp', '-a', addr, '--persistent=auto')
        self._assert_disconnected(self._DISCOVERY_INSTANCE)

    def test_discover_persistent_force_ignores_epcsd(self):
        """--persistent=force keeps the connection regardless of what EPCSD reports."""
        addr = '192.168.10.6'
        self.server.discovery_entries = [self._self_entry(addr, eflags=0)]

        self._run('discover', '-t', 'tcp', '-a', addr, '--persistent=force')
        self._assert_persisted(self._DISCOVERY_INSTANCE)

    def test_discover_persistent_separate_value_arg_is_dropped(self):
        """A value given as a separate argv token (not glued with '=') is silently
        dropped; --persistent is treated as bare (mode "auto"), not "force"."""
        addr = '192.168.10.7'
        self.server.discovery_entries = [self._self_entry(addr, eflags=0)]

        # If "force" were actually parsed as the option's value this would persist;
        # since it's dropped and auto degrades on EPCSD=0, it must disconnect.
        self._run('discover', '-t', 'tcp', '-a', addr, '--persistent', 'force')
        self._assert_disconnected(self._DISCOVERY_INSTANCE)

    def test_connect_all_persistent_auto_epcsd_referral_hop(self):
        """Referral (non-self) Discovery Controller entries decide persistence
        from their own EFLAGS directly, without needing a self-entry."""
        dc_a = "nqn.2014-08.org.nvmexpress:uuid:dc-epcsd-A"
        dc_b = "nqn.2014-08.org.nvmexpress:uuid:dc-epcsd-B"  # EPCSD set: should persist
        dc_c = "nqn.2014-08.org.nvmexpress:uuid:dc-epcsd-C"  # EPCSD unset: should disconnect

        self.server.discovery_map = {
            dc_a: [
                {'transport': 'tcp', 'traddr': '192.168.110.2', 'trsvcid': '4420',
                 'subsysnqn': dc_b, 'eflags': NVMF_DISC_EFLAGS_EPCSD},
                {'transport': 'tcp', 'traddr': '192.168.110.3', 'trsvcid': '4420',
                 'subsysnqn': dc_c, 'eflags': 0},
            ],
        }

        self._run('connect-all', '-t', 'tcp', '-a', '192.168.110.1', '-n', dc_a, '--persistent')

        self.assertEqual(self._subsysnqn(1), dc_b)
        self.assertEqual(self._subsysnqn(2), dc_c)
        self._assert_persisted(1, "dc-epcsd-B (EPCSD set) should have stayed connected")
        self._assert_disconnected(2, "dc-epcsd-C (EPCSD unset) should have been disconnected")

    # ------------------------------------------------------------------ #
    # Discovery-walk mechanics: depth cap, visited-set, referral-vs-self #
    # entry precedence, and resuming an already-connected DC's own      #
    # sub-tree. See dc_walk_referral()/dc_visited_*()/dc_decide() in     #
    # libnvme/src/nvme/fabrics.c.                                        #
    # ------------------------------------------------------------------ #

    def test_connect_all_referral_self_entry_overrides_parent_view(self):
        """A referred DC's own self entry (SUBTYPE=03h) decides its own
        persistence -- not the EPCSD its parent's referral entry reported
        for it."""
        dc_a = "nqn.2014-08.org.nvmexpress:uuid:dc-self-override-A"
        dc_b = "nqn.2014-08.org.nvmexpress:uuid:dc-self-override-B"
        dc_b_addr = '192.168.130.2'
        dc_b_trsvcid = '4420'

        self.server.discovery_map = {
            # dc_a's own view of dc_b under-reports EPCSD (0): if this were
            # used, dc_b would disconnect.
            dc_a: [
                {'transport': 'tcp', 'traddr': dc_b_addr, 'trsvcid': dc_b_trsvcid,
                 'subsysnqn': dc_b, 'eflags': 0},
            ],
            # dc_b's own self entry says EPCSD=1 -- its own report must win
            # once dc_b is connected to and its own DLP is fetched.
            dc_b: [
                self._self_entry(dc_b_addr, eflags=NVMF_DISC_EFLAGS_EPCSD,
                                  trsvcid=dc_b_trsvcid, subsysnqn=dc_b),
            ],
        }

        self._run('connect-all', '-t', 'tcp', '-a', '192.168.130.1', '-n', dc_a,
                 '--persistent')

        self.assertEqual(self._subsysnqn(1), dc_b)
        self._assert_persisted(1, "dc_b's own self entry (EPCSD=1) should have "
                                  "overridden its parent's referral view (EPCSD=0)")

    def test_connect_all_already_connected_referral_walks_subtree(self):
        """A referral DC that's already connected before connect-all runs
        must still have its own Discovery Log Page walked, not just
        skipped -- the bug that motivated the discovery-walk rewrite."""
        dc_a = "nqn.2014-08.org.nvmexpress:uuid:dc-resume-A"
        dc_b = "nqn.2014-08.org.nvmexpress:uuid:dc-resume-B"
        io_c = "nqn.2014-08.org.nvmexpress:uuid:io-resume-C"
        dc_b_addr = '192.168.140.2'
        dc_b_trsvcid = '4420'
        # Each invocation of the nvme binary auto-generates its own random
        # hostnqn/hostid unless one is pinned, landing in a different
        # in-memory host object -- lookup_live_ctrl() only ever searches
        # the *current* host's own subsystems, so without a shared identity
        # the second process could never recognize dc_b as already
        # connected, no matter what the fake sysfs tree says.
        hostnqn = "nqn.2014-08.org.nvmexpress:uuid:11111111-1111-1111-1111-111111111111"

        # Pre-connect dc_b directly, as if an earlier session already
        # reached it. Becomes nvme0, tracked in the fake topology tree.
        self._run('connect', '-t', 'tcp', '-a', dc_b_addr, '-s', dc_b_trsvcid,
                 '-n', dc_b, '--hostnqn', hostnqn)
        self.assertEqual(self._subsysnqn(0), dc_b)

        self.server.discovery_map = {
            dc_a: [
                {'transport': 'tcp', 'traddr': dc_b_addr, 'trsvcid': dc_b_trsvcid,
                 'subsysnqn': dc_b},
            ],
            # Only consulted if the walk resumes into the already-connected
            # dc_b -- that resumption is the behavior under test.
            dc_b: [
                {'transport': 'tcp', 'traddr': '192.168.140.3', 'trsvcid': '4420',
                 'subsysnqn': io_c},
            ],
        }

        self._run('connect-all', '-t', 'tcp', '-a', '192.168.140.1', '-n', dc_a,
                 '--hostnqn', hostnqn)

        # instance 0 = dc_b (pre-existing), 1 = dc_a (primary, connected
        # fresh), 2 = io_c (only reachable if dc_b's subtree was walked).
        self.assertEqual(self._subsysnqn(1), dc_a)
        self.assertTrue(self._ctrl_path(2).exists(),
                        "io_c behind the already-connected dc_b was never "
                        "discovered -- its sub-tree wasn't walked")
        self.assertEqual(self._subsysnqn(2), io_c)
        self._assert_persisted(0, "an already-connected (borrowed) DC must "
                                  "never be disconnected by the walk")

    def test_connect_all_referral_depth_cap(self):
        """The walk stops after NVMF_MAX_REFERRAL_DEPTH (8) referral hops:
        the primary is depth 0, dc_1..dc_8 (depths 1-8) connect, dc_9
        (depth 9) does not."""
        n = 10  # dc_0 (primary) .. dc_9
        dcs = [f"nqn.2014-08.org.nvmexpress:uuid:dc-depth-{i}" for i in range(n)]
        self.server.discovery_map = {
            dcs[i]: [{'transport': 'tcp', 'traddr': f'192.168.120.{i + 2}',
                     'trsvcid': '4420', 'subsysnqn': dcs[i + 1]}]
            for i in range(n - 1)
        }

        self._run('connect-all', '-t', 'tcp', '-a', '192.168.120.1', '-n', dcs[0])

        for i in range(9):  # dc_0..dc_8, depths 0-8, all connect
            self.assertTrue(self._ctrl_path(i).exists(),
                            f"dc_{i} (depth {i}) was not connected")
            self.assertEqual(self._subsysnqn(i), dcs[i])

        self.assertFalse(self._ctrl_path(9).exists(),
                         "dc_9 (depth 9) should not have been connected: "
                         "exceeds the referral depth cap")

    def test_connect_all_referral_cycle_visited_once(self):
        """A referral cycle (dc_a -> dc_b -> dc_a) must not be re-walked:
        dc_a's Discovery Log Page is fetched exactly once despite the
        cycle, and a sibling entry alongside the back-reference is still
        discovered."""
        dc_a = "nqn.2014-08.org.nvmexpress:uuid:dc-cycle-A"
        dc_b = "nqn.2014-08.org.nvmexpress:uuid:dc-cycle-B"
        io_c = "nqn.2014-08.org.nvmexpress:uuid:io-cycle-C"

        self.server.discovery_map = {
            dc_a: [
                {'transport': 'tcp', 'traddr': '192.168.150.2', 'trsvcid': '4420',
                 'subsysnqn': dc_b},
            ],
            dc_b: [
                # Back-reference to the primary's own connection params.
                {'transport': 'tcp', 'traddr': '192.168.150.1', 'trsvcid': DISCOVERY_PORT,
                 'subsysnqn': dc_a},
                {'transport': 'tcp', 'traddr': '192.168.150.3', 'trsvcid': '4420',
                 'subsysnqn': io_c},
            ],
        }

        self._run('connect-all', '-t', 'tcp', '-a', '192.168.150.1', '-n', dc_a)

        self.assertEqual(self._subsysnqn(1), dc_b)
        self.assertEqual(self._subsysnqn(2), io_c)
        self.assertEqual(self.server.log_page_fetch_count.get(dc_a, 0), 1,
                         "dc_a's Discovery Log Page was re-fetched via the "
                         "cycle; the visited-set should have short-circuited it")

    def test_connect_all_referral_ring_visited_once(self):
        """A fully bidirectional 3-DC referral ring (dc_a <-> dc_b <-> dc_c
        <-> dc_a, every node referring to both its ring-neighbors) must not
        re-walk any of them: each DC's Discovery Log Page is fetched exactly
        once despite every node having a path back to every other node."""
        dc_a = "nqn.2014-08.org.nvmexpress:uuid:dc-ring-A"
        dc_b = "nqn.2014-08.org.nvmexpress:uuid:dc-ring-B"
        dc_c = "nqn.2014-08.org.nvmexpress:uuid:dc-ring-C"

        self.server.discovery_map = {
            dc_a: [
                {'transport': 'tcp', 'traddr': '192.168.160.2', 'trsvcid': '4420',
                 'subsysnqn': dc_b},
                {'transport': 'tcp', 'traddr': '192.168.160.3', 'trsvcid': '4420',
                 'subsysnqn': dc_c},
            ],
            dc_b: [
                # Back-reference to the primary's own connection params.
                {'transport': 'tcp', 'traddr': '192.168.160.1', 'trsvcid': DISCOVERY_PORT,
                 'subsysnqn': dc_a},
                {'transport': 'tcp', 'traddr': '192.168.160.3', 'trsvcid': '4420',
                 'subsysnqn': dc_c},
            ],
            dc_c: [
                {'transport': 'tcp', 'traddr': '192.168.160.2', 'trsvcid': '4420',
                 'subsysnqn': dc_b},
                # Back-reference to the primary's own connection params.
                {'transport': 'tcp', 'traddr': '192.168.160.1', 'trsvcid': DISCOVERY_PORT,
                 'subsysnqn': dc_a},
            ],
        }

        self._run('connect-all', '-t', 'tcp', '-a', '192.168.160.1', '-n', dc_a)

        self.assertEqual(self._subsysnqn(1), dc_b)
        self.assertEqual(self._subsysnqn(2), dc_c)
        for nqn in (dc_a, dc_b, dc_c):
            self.assertEqual(self.server.log_page_fetch_count.get(nqn, 0), 1,
                             f"{nqn}'s Discovery Log Page was re-fetched via "
                             "the ring; the visited-set should have "
                             "short-circuited every back-reference")


if __name__ == '__main__':
    # If called standalone, strip the arguments parsed by FabricsMockCLITest
    # and run standard unittest main.
    unittest_args = [sys.argv[0]]
    if len(sys.argv) > 3:
        unittest_args.extend(sys.argv[3:])
    unittest.main(argv=unittest_args)
