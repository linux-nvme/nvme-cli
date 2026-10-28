# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
"""The test scenarios: TOML files with a setup, an action and the
expected result, the VM scripts which run them, and the evaluation of
what the VM logged."""

from __future__ import annotations

import re
import shlex

try:
    import tomllib
except ImportError:  # Python < 3.11
    tomllib = None  # type: ignore[assignment]
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# The subsystem of the loopback target, see vm-setup.sh
NQN = 'nqn.2026-10.test:shutdown'

MOUNTS = ('root-like', 'netdev', 'nofail')
ACTIONS = ('reboot', 'stop-unit')
DISCONNECTS = ('skipped', 'after-unmount', 'while-mounted', 'done', 'none')

# The tag of the marker lines the scenarios log in the VM
TAG = 'dvm-scenario'

# Shared by the scripts: find the namespace of NQN, and bring the VM to
# a known state. Units are transient: they keep the ExecStop= of the
# build which created them, so they are recreated after every install.
_FUNCS = f"""\
NQN={NQN}
find_ns() {{
    for i in $(seq 1 60); do
        s=$(grep -lx "$NQN" /sys/class/nvme-subsystem/*/subsysnqn \\
            2>/dev/null | head -1)
        if [ -n "$s" ]; then
            ns=$(ls "${{s%/*}}" | grep -E '^nvme[0-9]+n1$' | head -1)
            [ -n "$ns" ] && {{ echo "/dev/$ns"; return 0; }}
        fi
        sleep 1
    done
    return 1
}}
io_unit() {{
    for u in $(systemctl list-units 'nvme-discoverd-*' --all --plain \\
            --no-legend | cut -d' ' -f1); do
        systemctl show -p Description --value "$u" | \\
            grep -q 'I/O Controller' && {{ echo "$u"; return 0; }}
    done
    return 1
}}
reset_vm() {{
    systemctl stop mnt-t.mount 2>/dev/null || true
    systemctl disable mnt-t.mount >/dev/null 2>&1 || true
    umount /mnt/t 2>/dev/null || umount -l /mnt/t 2>/dev/null || true
    rm -f /etc/systemd/system/mnt-t.mount
    rm -f /etc/systemd/system/*.wants/mnt-t.mount
    sed -i '\\| /mnt/t |d' /etc/fstab
    tc qdisc del dev lo root 2>/dev/null || true
    systemctl daemon-reload
    systemctl stop nvme-discoverd
    for u in $(systemctl list-units 'nvme-discoverd-*' --all --plain \\
            --no-legend | cut -d' ' -f1); do
        systemctl stop "$u"
    done
    systemctl reset-failed 'nvme-discoverd-*' 2>/dev/null || true
    systemctl start nvme-discoverd
}}
"""

RESET_SCRIPT = f"""\
set -euo pipefail
{_FUNCS}
reset_vm
dev=$(find_ns) || {{ echo "error=namespace of $NQN not found"; exit 1; }}
echo dev=$dev
"""


class ScenarioError(Exception):
    """A scenario file is not valid."""


@dataclass
class Scenario:
    name: str
    description: str
    mount: str
    action: str
    dirty_mb: int = 200
    netem_delay_ms: int = 30
    # True: the VM must run the skip-if-mounted build (ExecStop= runs
    # nvme-discoverd --stop-unit); False: it must not; None: any build
    stop_unit: bool | None = None
    expect: dict[str, Any] = field(default_factory=dict)

    def describe(self) -> dict[str, Any]:
        return {
            'name': self.name,
            'description': self.description,
            'mount': self.mount,
            'action': self.action,
            'stop_unit': self.stop_unit,
            'expect': self.expect,
        }


def load(path: Path) -> Scenario:
    """The scenario in TOML file @path."""
    if tomllib is None:
        raise ScenarioError('the scenarios need Python 3.11 or newer')
    try:
        data = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ScenarioError(f'{path.name}: {e}') from e
    setup = data.get('setup', {})
    build = data.get('build', {})
    expect = data.get('expect', {})
    s = Scenario(
        name=path.stem,
        description=str(data.get('description', '')),
        mount=str(setup.get('mount', '')),
        action=str(data.get('action', '')),
        dirty_mb=int(setup.get('dirty_mb', 200)),
        netem_delay_ms=int(setup.get('netem_delay_ms', 30)),
        stop_unit=build.get('stop_unit'),
        expect=dict(expect),
    )
    if s.mount not in MOUNTS:
        raise ScenarioError(
            f'{path.name}: setup.mount must be one of {MOUNTS}'
        )
    if s.action not in ACTIONS:
        raise ScenarioError(f'{path.name}: action must be one of {ACTIONS}')
    if s.expect.get('disconnect') not in DISCONNECTS:
        raise ScenarioError(
            f'{path.name}: expect.disconnect must be one of {DISCONNECTS}'
        )
    unknown = set(s.expect) - {'disconnect', 'data_intact', 'log_recovery'}
    if unknown:
        raise ScenarioError(f'{path.name}: unknown expect keys {unknown}')
    if s.stop_unit is not None and not isinstance(s.stop_unit, bool):
        raise ScenarioError(f'{path.name}: build.stop_unit must be a bool')
    return s


def load_all(directory: Path) -> dict[str, Scenario]:
    return {p.stem: load(p) for p in sorted(directory.glob('*.toml'))}


def setup_script(s: Scenario) -> str:
    """Resets the VM, creates a new file system, mounts it the way the
    scenario says, and leaves dirty data on it."""
    if s.mount == 'root-like':
        mount = """\
cat > /etc/systemd/system/mnt-t.mount <<UNIT
[Unit]
Description=Root-like test mount, never stopped at shutdown
DefaultDependencies=no

[Mount]
What=/dev/disk/by-uuid/$uuid
Where=/mnt/t
Type=xfs

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now mnt-t.mount
"""
    else:
        opt = '_netdev' if s.mount == 'netdev' else 'nofail'
        mount = f"""\
echo "UUID=$uuid /mnt/t xfs defaults,{opt} 0 0" >> /etc/fstab
systemctl daemon-reload
systemctl start mnt-t.mount
"""
    return f"""\
set -euo pipefail
{_FUNCS}
reset_vm
dev=$(find_ns) || {{ echo "error=namespace of $NQN not found"; exit 1; }}
unit=$(io_unit) || {{ echo "error=no I/O controller unit"; exit 1; }}
if systemctl show -p ExecStop --value "$unit" | grep -q -- --stop-unit; then
    echo stop_unit=true
else
    echo stop_unit=false
fi
mkfs.xfs -q -f "$dev"
udevadm settle
uuid=$(blkid -p -s UUID -o value "$dev")
mkdir -p /mnt/t
{mount}
findmnt /mnt/t >/dev/null || {{ echo "error=/mnt/t is not mounted"; exit 1; }}
sysctl -q vm.dirty_expire_centisecs=360000 vm.dirty_writeback_centisecs=0
modprobe sch_netem
tc qdisc replace dev lo root netem delay {s.netem_delay_ms}ms
dd if=/dev/urandom of=/mnt/t/data bs=1M count={s.dirty_mb} status=none
sha256sum /mnt/t/data > /root/data.sha256
echo dev=$dev
echo unit=$unit
echo dirty_kb=$(awk '/^Dirty:/ {{print $2}}' /proc/meminfo)
echo boot_id=$(cat /proc/sys/kernel/random/boot_id)
logger -t {TAG} {shlex.quote('start ' + s.name)}
"""


# Reboots a second after the ssh session ends
REBOOT_SCRIPT = 'systemd-run --quiet --on-active=1 systemctl reboot\n'

BOOT_ID_SCRIPT = 'cat /proc/sys/kernel/random/boot_id\n'

# The lines of a shutdown that tell the order, see parse_shutdown()
_SHUTDOWN_GREP = (
    f'{TAG}|Unmounted mnt-t.mount|Removing ctrl: NQN "{NQN}"'
    '|in use, not disconnected at shutdown|XFS \\(nvme'
    '|Stopping nvme-discoverd-[0-9a-f]+.service'
    '|Stopped target remote-fs-pre'
)

SHUTDOWN_LOG_SCRIPT = (
    'journalctl -b -1 -o short-monotonic --no-pager | '
    f'grep -E {shlex.quote(_SHUTDOWN_GREP)} || true\n'
)

# After the reboot: is the file system back, did it need log recovery,
# is the data intact?
CHECK_SCRIPT = """\
for i in $(seq 1 60); do findmnt /mnt/t >/dev/null && break; sleep 1; done
findmnt /mnt/t >/dev/null || systemctl start mnt-t.mount 2>/dev/null || true
if findmnt /mnt/t >/dev/null; then
    echo mounted=true
else
    echo mounted=false
fi
if journalctl -b -k --no-pager | grep -q 'XFS (nvme.*Starting recovery'; then
    echo log_recovery=true
else
    echo log_recovery=false
fi
if sha256sum -c --quiet /root/data.sha256 >/dev/null 2>&1; then
    echo data_intact=true
else
    echo data_intact=false
fi
"""


def stop_unit_script(s: Scenario) -> str:
    """Stops the I/O controller unit at runtime, with the file system
    mounted. nvme-discoverd is stopped first, or it starts the unit
    again. Then the VM is reset, so the next scenario finds the
    controller connected."""
    return f"""\
set -uo pipefail
{_FUNCS}
unit=$(io_unit) || {{ echo "error=no I/O controller unit"; exit 1; }}
since=$(date '+%Y-%m-%d %H:%M:%S')
systemctl stop nvme-discoverd
systemctl stop "$unit"
sleep 2
journalctl --since "$since" -o short-monotonic --no-pager | \\
    grep -E {shlex.quote(_SHUTDOWN_GREP)} || true
echo ---
reset_vm
find_ns >/dev/null || echo "error=controller not back"
"""


_LINE = re.compile(r'^\[\s*(\d+\.\d+)\]')


def parse_kv(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        if sep:
            out[key] = value
    return out


def parse_shutdown(lines: list[str]) -> dict[str, Any]:
    """What the shutdown log of the scenario's subsystem says: when the
    file system was unmounted, when the controller was removed, and
    whether the disconnect was skipped. Only the lines after the last
    start marker count: the setup unmounts and reconnects too."""
    starts = [i for i, line in enumerate(lines) if f'{TAG}[' in line]
    if starts:
        lines = lines[starts[-1] + 1 :]
    t_unmounted = t_removed = None
    skipped = False
    for line in lines:
        m = _LINE.match(line)
        t = float(m.group(1)) if m else None
        if 'Unmounted mnt-t.mount' in line and t_unmounted is None:
            t_unmounted = t
        elif 'Removing ctrl' in line and t_removed is None:
            t_removed = t
        elif 'in use, not disconnected at shutdown' in line:
            skipped = True
    if skipped and t_removed is None:
        disconnect = 'skipped'
    elif t_removed is None:
        disconnect = 'none'
    elif t_unmounted is not None and t_removed > t_unmounted:
        disconnect = 'after-unmount'
    else:
        disconnect = 'while-mounted'
    gap = None
    if t_removed is not None and t_unmounted is not None:
        gap = round((t_removed - t_unmounted) * 1000)
    return {
        'disconnect': disconnect,
        'unmounted_at': t_unmounted,
        'removed_at': t_removed,
        # positive: the disconnect came after the unmount
        'removed_after_unmount_ms': gap,
    }


def evaluate(expect: dict[str, Any], observed: dict[str, Any]) -> list[str]:
    """The expectations that @observed does not meet."""
    return [
        f'{key}: expected {want!r}, got {observed.get(key)!r}'
        for key, want in expect.items()
        if observed.get(key) != want
    ]
