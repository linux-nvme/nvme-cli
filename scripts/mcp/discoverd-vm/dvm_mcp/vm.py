# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
"""What the server asks of the VM: start it, run commands as root over
ssh, copy the nvme-cli source to it and build it there."""

from __future__ import annotations

import contextlib
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

# The source tree in the VM, configured by vm_create
VM_SRC = '/root/nvme-cli'

# The files in the VM directory
DISK = 'disk.qcow2'
SEED = 'seed.iso'
KEY = 'id_vm'
PIDFILE = 'qemu.pid'
CONSOLE = 'console.log'

# What vm_sync_build records about the copied source, for vm_status
VM_SOURCE_INFO = '/root/nvme-cli.source'

# How long to wait for ssh after a start or a reboot
BOOT_TIMEOUT = 180


class VMError(Exception):
    """The VM could not be reached, or a command failed."""


@dataclass
class Result:
    rc: int
    out: str
    err: str


class VM:
    """The test VM in @vm_dir: qemu with KVM and user networking, ssh
    forwarded to a local port, a user with sudo."""

    def __init__(
        self,
        vm_dir: Path,
        port: int = 2222,
        user: str = 'test',
    ):
        self.vm_dir = vm_dir
        self.port = port
        self.user = user
        self.key = vm_dir / KEY

    def _ssh_opts(self) -> list[str]:
        return [
            '-i', str(self.key),
            '-p', str(self.port),
            '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=ERROR',
            '-o', 'ConnectTimeout=5',
        ]  # fmt: skip

    def running(self) -> bool:
        """Is the qemu process of the VM alive?"""
        try:
            pid = int((self.vm_dir / PIDFILE).read_text())
            os.kill(pid, 0)
        except (OSError, ValueError):
            return False
        return True

    def run(self, script: str, timeout: float = 60) -> Result:
        """Runs @script with bash as root in the VM."""
        cmd = [
            'ssh',
            *self._ssh_opts(),
            f'{self.user}@127.0.0.1',
            'sudo bash -s',
        ]
        try:
            p = subprocess.run(
                cmd,
                input=script,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise VMError(f'no answer from the VM in {timeout} s') from e
        # ssh itself fails with 255
        if p.returncode == 255:
            raise VMError(f'ssh failed: {p.stderr.strip()}')
        return Result(p.returncode, p.stdout, p.stderr)

    def reachable(self) -> bool:
        try:
            return self.run('true', timeout=15).rc == 0
        except VMError:
            return False

    def wait_up(self, timeout: float = BOOT_TIMEOUT) -> float:
        """Waits until ssh answers. Returns the seconds it took."""
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            if self.reachable():
                return time.monotonic() - start
            time.sleep(2)
        raise VMError(f'the VM did not answer ssh in {timeout} s')

    def wait_reboot(
        self, old_boot_id: str, timeout: float = BOOT_TIMEOUT
    ) -> float:
        """Waits until the VM answers ssh with a boot ID other than
        @old_boot_id. Returns the seconds it took."""
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            try:
                r = self.run('cat /proc/sys/kernel/random/boot_id', 15)
                if r.rc == 0 and r.out.strip() not in ('', old_boot_id):
                    return time.monotonic() - start
            except VMError:
                pass
            time.sleep(2)
        raise VMError(f'the VM did not come back in {timeout} s')

    def qemu_cmd(self) -> list[str]:
        d = self.vm_dir
        return [
            'qemu-system-x86_64',
            '-enable-kvm', '-cpu', 'host', '-smp', '4', '-m', '4096',
            '-drive', f'file={d / DISK},if=virtio',
            '-drive', f'file={d / SEED},media=cdrom',
            '-netdev',
            f'user,id=n0,hostfwd=tcp:127.0.0.1:{self.port}-:22',
            '-device', 'virtio-net-pci,netdev=n0',
            '-display', 'none',
            '-serial', f'file:{d / CONSOLE}',
            '-pidfile', str(d / PIDFILE),
            '-daemonize',
        ]  # fmt: skip

    def start(self, timeout: float = BOOT_TIMEOUT) -> float:
        """Starts qemu and waits for ssh. Returns the seconds it took."""
        if not (self.vm_dir / DISK).exists():
            raise VMError(f'no VM in {self.vm_dir}: use vm_create')
        p = subprocess.run(
            self.qemu_cmd(),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if p.returncode:
            raise VMError(f'qemu failed: {p.stderr.strip()}')
        return self.wait_up(timeout)

    def stop(self, timeout: float = 120) -> float:
        """Powers the VM off and waits for qemu to end. Returns the
        seconds it took."""
        start = time.monotonic()
        # the VM may be down already, or hang
        with contextlib.suppress(VMError):
            self.run('systemd-run --quiet --on-active=1 poweroff', 15)
        while time.monotonic() - start < timeout:
            if not self.running():
                return time.monotonic() - start
            time.sleep(1)
        raise VMError(f'the VM did not power off in {timeout} s')

    def sync(self, src: Path) -> None:
        """Copies the source tree @src to the VM. Build directories and
        git metadata stay behind."""
        cmd = [
            'rsync',
            '-a',
            '--delete',
            '--exclude=/.build*',
            '--exclude=/.git',
            '--rsync-path=sudo rsync',
            '-e',
            ' '.join(['ssh', *self._ssh_opts()]),
            f'{src}/',
            f'{self.user}@127.0.0.1:{VM_SRC}/',
        ]
        try:
            p = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300, check=False
            )
        except subprocess.TimeoutExpired as e:
            raise VMError('rsync took longer than 300 s') from e
        if p.returncode:
            raise VMError(f'rsync failed: {p.stderr.strip()}')


def describe(src: Path) -> str:
    """git describe of @src, with -dirty for local changes."""
    p = subprocess.run(
        ['git', '-C', str(src), 'describe', '--always', '--dirty'],
        capture_output=True,
        text=True,
        check=False,
    )
    if p.returncode:
        raise VMError(f'git describe failed: {p.stderr.strip()}')
    return p.stdout.strip()
