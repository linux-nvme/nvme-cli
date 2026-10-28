# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""What nvme-mcp asks of the system: nvme top and the I/O policy."""

from __future__ import annotations

import errno
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

IOPOLICIES = ('numa', 'round-robin', 'queue-depth')

# The longest interval a tool call may sample over
MAX_INTERVAL = 60

# The most kernel log messages a watch reports, the rest are only counted
MAX_KERNEL_LINES = 200

# What tells repeated messages apart: hex values and numbers, but not
# the numbers of device names like nvme3
_VARYING = re.compile(
    r'\b0?x[0-9a-f]+\b|\b(?=[0-9a-f]*[0-9])[0-9a-f]{3,}\b|(?<![a-z0-9])[0-9]+',
    re.IGNORECASE,
)

Snapshot = dict[str, Any]


class NvmeError(Exception):
    """nvme failed, or the system refused a change."""


class KernelLog:
    """The NVMe messages of the kernel log from now on."""

    def __init__(self, kmsg: Path):
        try:
            self.fd = os.open(kmsg, os.O_RDONLY | os.O_NONBLOCK)
        except OSError as e:
            raise NvmeError(f'cannot read the kernel log: {e}') from e
        os.lseek(self.fd, 0, os.SEEK_END)
        self.lines: list[dict[str, Any]] = []
        # the line of each message with its varying parts masked
        self._seen: dict[str, dict[str, Any]] = {}
        self.dropped = 0

    def poll(self, t: float) -> None:
        """Reads the new messages and stamps them with @t, the time they
        were seen. The time stamps of the kernel are no help: they come
        from the clock of the CPU which logged them, and in VMs these
        drift seconds apart from each other and from CLOCK_MONOTONIC."""
        while True:
            try:
                data = os.read(self.fd, 8192)
            except BlockingIOError:
                return
            except OSError as e:
                # older records were overwritten before we read them
                if e.errno == errno.EPIPE:
                    continue
                raise
            if not data:
                return
            for record in data.decode(errors='replace').splitlines():
                self._add(t, record)

    def close(self) -> None:
        os.close(self.fd)

    def _add(self, t: float, record: str) -> None:
        # pri,seq,usec,flags;message; continuation lines start with ' '
        head, sep, msg = record.partition(';')
        fields = head.split(',')
        if not sep or len(fields) < 3 or not fields[2].isdigit():
            return
        if not re.search(r'nvme', msg, re.IGNORECASE):
            return
        # a driver may log the same message for each I/O: once, counted
        shape = _VARYING.sub('#', msg)
        line = self._seen.get(shape)
        if line is not None:
            line['Count'] = line.get('Count', 1) + 1
            line['LastT'] = round(t, 1)
            return
        if len(self.lines) >= MAX_KERNEL_LINES:
            self.dropped += 1
            return
        line = {
            'T': round(t, 1),
            # as dmesg shows it, to find the line there
            'KernelTime': int(fields[2]) / 1e6,
            'Message': msg,
        }
        self._seen[shape] = line
        self.lines.append(line)


class System:
    """The nvme binary and the sysfs of the host."""

    def __init__(
        self,
        nvme: str = 'nvme',
        sysfs: Path = Path('/sys'),
        kmsg: Path = Path('/dev/kmsg'),
    ):
        self.nvme = nvme
        self.sysfs = sysfs
        self.kmsg = kmsg

    def kernel_log(self) -> KernelLog:
        """The kernel log from now on."""
        return KernelLog(self.kmsg)

    def snapshot(self, interval: int) -> Snapshot:
        """The rates of nvme top over @interval seconds."""
        if not 1 <= interval <= MAX_INTERVAL:
            raise NvmeError(
                f'interval must be from 1 to {MAX_INTERVAL} seconds'
            )
        cmd = [self.nvme, 'top', f'--delay={interval}', '-o', 'json']
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=interval + 30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            raise NvmeError(f'{" ".join(cmd)}: {e}') from e
        if res.returncode:
            raise NvmeError(
                f'{" ".join(cmd)} failed ({res.returncode}): '
                f'{res.stderr.strip()}'
            )
        try:
            snap: Snapshot = json.loads(res.stdout)
        except json.JSONDecodeError as e:
            raise NvmeError(f'{" ".join(cmd)}: no JSON output: {e}') from e
        return snap

    def _iopolicy_file(self, subsystem: str) -> Path:
        # the name goes into a path: only nvme-subsysN
        if not re.fullmatch(r'nvme-subsys[0-9]+', subsystem):
            raise NvmeError(f'not a subsystem name: {subsystem!r}')
        f = self.sysfs / 'class' / 'nvme-subsystem' / subsystem / 'iopolicy'
        if not f.exists():
            raise NvmeError(f'no subsystem {subsystem}')
        return f

    def iopolicy(self, subsystem: str) -> str:
        return self._iopolicy_file(subsystem).read_text().strip()

    def set_iopolicy(self, subsystem: str, policy: str) -> None:
        if policy not in IOPOLICIES:
            raise NvmeError(
                f'unknown I/O policy {policy!r}, one of: '
                f'{", ".join(IOPOLICIES)}'
            )
        f = self._iopolicy_file(subsystem)
        try:
            f.write_text(policy)
        except OSError as e:
            raise NvmeError(
                f'cannot set the I/O policy of {subsystem}: {e}'
            ) from e
