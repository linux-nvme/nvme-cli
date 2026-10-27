# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""What nvme-mcp asks of the system: nvme top and the I/O policy."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

IOPOLICIES = ('numa', 'round-robin', 'queue-depth')

# The longest interval a tool call may sample over
MAX_INTERVAL = 60

Snapshot = dict[str, Any]


class NvmeError(Exception):
    """nvme failed, or the system refused a change."""


class System:
    """The nvme binary and the sysfs of the host."""

    def __init__(self, nvme: str = 'nvme', sysfs: Path = Path('/sys')):
        self.nvme = nvme
        self.sysfs = sysfs

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
