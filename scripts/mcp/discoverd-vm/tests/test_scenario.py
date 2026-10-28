# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
"""Tests of the scenario files, the log analysis and run_scenario."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from dvm_mcp import scenario as sc
from dvm_mcp.server import Server
from dvm_mcp.vm import VM, Result

SCENARIOS = Path(__file__).resolve().parent.parent / 'scenarios'

# From a real run of #4332 with a _netdev mount
AFTER_UNMOUNT = [
    '[  117.780065] dshut dvm-scenario[10516]: start s03-netdev',
    '[  118.180757] dshut systemd[1]: Unmounted mnt-t.mount - /mnt/t.',
    '[  118.251349] dshut systemd[1]: Stopping nvme-discoverd-376f56ba622d'
    '.service - NVMe I/O Controller',
    '[  118.261043] dshut kernel: nvme nvme0: Removing ctrl: NQN '
    '"nqn.2026-10.test:shutdown"',
]

WHILE_MOUNTED = [
    '[   19.909315] dshut systemd[1]: Stopping nvme-discoverd-376f56ba622d'
    '.service - NVMe I/O Controller',
    '[   19.925102] dshut kernel: nvme nvme0: Removing ctrl: NQN '
    '"nqn.2026-10.test:shutdown"',
    '[   20.300000] dshut kernel: XFS (nvme0n1): log I/O error -5',
]

# From a real run of #4332 with the root-like mount
WHILE_MOUNTED_LATE = [
    '[24071.360079] dshut kernel: nvme nvme0: Removing ctrl: NQN '
    '"nqn.2026-10.test:shutdown"',
    '[24073.707497] dshut kernel: XFS (nvme0n1): Filesystem has been shut '
    'down due to log error (0x2).',
    '[24073.721956] dshut systemd[1]: Unmounted mnt-t.mount - Root-like '
    'test mount, never stopped at shutdown.',
]

SKIPPED = [
    '[   19.909315] dshut systemd[1]: Stopping nvme-discoverd-376f56ba622d'
    '.service - NVMe I/O Controller',
    '[   19.920000] dshut nvme-discoverd[901]: nvme0: in use, not '
    'disconnected at shutdown',
]


class TestParse(unittest.TestCase):
    def test_after_unmount(self) -> None:
        a = sc.parse_shutdown(AFTER_UNMOUNT)
        self.assertEqual(a['disconnect'], 'after-unmount')
        self.assertEqual(a['removed_after_unmount_ms'], 80)

    def test_while_mounted(self) -> None:
        a = sc.parse_shutdown(WHILE_MOUNTED)
        self.assertEqual(a['disconnect'], 'while-mounted')
        self.assertIsNone(a['unmounted_at'])

    def test_removed_before_unmount(self) -> None:
        lines = [
            AFTER_UNMOUNT[3].replace('118.261043', '118.100000'),
            AFTER_UNMOUNT[1],
        ]
        self.assertEqual(
            sc.parse_shutdown(lines)['disconnect'], 'while-mounted'
        )

    def test_setup_lines_before_the_marker(self) -> None:
        setup = [
            '[   10.000000] dshut systemd[1]: Unmounted mnt-t.mount - x.',
            '[   11.000000] dshut dvm-scenario[1]: start s02',
        ]
        a = sc.parse_shutdown(setup + WHILE_MOUNTED_LATE)
        self.assertEqual(a['disconnect'], 'while-mounted')
        self.assertEqual(a['removed_after_unmount_ms'], -2362)

    def test_skipped(self) -> None:
        self.assertEqual(sc.parse_shutdown(SKIPPED)['disconnect'], 'skipped')

    def test_none(self) -> None:
        self.assertEqual(sc.parse_shutdown([])['disconnect'], 'none')

    def test_evaluate(self) -> None:
        self.assertEqual(sc.evaluate({'a': 1}, {'a': 1, 'b': 2}), [])
        self.assertEqual(
            sc.evaluate({'a': 1}, {'a': 2}), ['a: expected 1, got 2']
        )


@unittest.skipIf(sc.tomllib is None, 'tomllib needs Python 3.11')
class TestLoad(unittest.TestCase):
    def test_shipped_scenarios(self) -> None:
        names = set(sc.load_all(SCENARIOS))
        self.assertIn('s01-root-like-skip', names)

    def _load(self, text: str) -> sc.Scenario:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'x.toml'
            p.write_text(text)
            return sc.load(p)

    def test_bad_mount(self) -> None:
        with self.assertRaises(sc.ScenarioError):
            self._load(
                'action = "reboot"\n[setup]\nmount = "x"\n'
                '[expect]\ndisconnect = "skipped"\n'
            )

    def test_unknown_expect_key(self) -> None:
        with self.assertRaises(sc.ScenarioError):
            self._load(
                'action = "reboot"\n[setup]\nmount = "netdev"\n'
                '[expect]\ndisconnect = "skipped"\nfoo = 1\n'
            )

    def test_setup_script_mounts(self) -> None:
        s = sc.load(SCENARIOS / 's03-netdev.toml')
        self.assertIn('defaults,_netdev', sc.setup_script(s))
        s = sc.load(SCENARIOS / 's01-root-like-skip.toml')
        self.assertIn('DefaultDependencies=no', sc.setup_script(s))


class RebootVM(VM):
    """A VM which reboots and logs @shutdown on the way."""

    def __init__(self, shutdown: list[str], stop_unit: bool) -> None:
        super().__init__(Path('/nonexistent'))
        self.shutdown = shutdown
        self.stop_unit = stop_unit
        self.rebooted = False

    def reachable(self) -> bool:
        return True

    def run(self, script: str, timeout: float = 60) -> Result:
        if 'mkfs.xfs' in script:
            su = 'true' if self.stop_unit else 'false'
            return Result(
                0,
                f'stop_unit={su}\ndev=/dev/nvme0n1\nunit=u\n'
                'dirty_kb=204800\nboot_id=old\n',
                '',
            )
        if 'systemctl reboot' in script:
            self.rebooted = True
            return Result(0, '', '')
        if 'journalctl -b -1' in script:
            return Result(0, '\n'.join(self.shutdown) + '\n', '')
        if 'sha256sum -c' in script:
            return Result(
                0, 'mounted=true\nlog_recovery=false\ndata_intact=true\n', ''
            )
        return Result(0, 'v3.1-1-gabc\n', '')

    def wait_reboot(self, old_boot_id: str, timeout: float = 0) -> float:
        return 41.0


def run(vm: VM, name: str) -> dict[str, Any]:
    resp = Server(vm, Path('/src'), True).handle(
        {
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'tools/call',
            'params': {'name': 'run_scenario', 'arguments': {'name': name}},
        }
    )
    assert resp is not None
    result: dict[str, Any] = resp['result']
    return result


@unittest.skipIf(sc.tomllib is None, 'tomllib needs Python 3.11')
class TestRunScenario(unittest.TestCase):
    def test_pass(self) -> None:
        vm = RebootVM(SKIPPED, stop_unit=True)
        out = run(vm, 's01-root-like-skip')
        self.assertTrue(vm.rebooted)
        self.assertTrue(out['structuredContent']['pass'])

    def test_fail(self) -> None:
        out = run(
            RebootVM(WHILE_MOUNTED, stop_unit=True), 's01-root-like-skip'
        )
        st = out['structuredContent']
        self.assertFalse(st['pass'])
        self.assertIn(
            "disconnect: expected 'skipped', got 'while-mounted'",
            st['mismatches'],
        )

    def test_wrong_build(self) -> None:
        vm = RebootVM(SKIPPED, stop_unit=False)
        out = run(vm, 's01-root-like-skip')
        self.assertTrue(out['isError'])
        self.assertFalse(vm.rebooted)
        self.assertIn('vm_sync_build', out['content'][0]['text'])

    def test_unknown(self) -> None:
        out = run(RebootVM([], True), 'nope')
        self.assertTrue(out['isError'])


if __name__ == '__main__':
    unittest.main()
