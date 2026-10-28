# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
"""Tests of the MCP protocol and the tools, with a fake VM."""

from __future__ import annotations

import io
import json
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from dvm_mcp.server import (
    INVALID_PARAMS,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    Server,
    parse_status,
)
from dvm_mcp.vm import VM, Result, VMError

STATUS = """\
kernel=6.19.10-300.fc44.x86_64
systemd=259
nvme=nvme version 3.1 (git 3.1)
discoverd=active
source=v3.1-1010-g7dfaf566a
ctrl=nvme0 tcp live nqn.2026-10.test:shutdown
unit=nvme-discoverd-376f56ba622d.service active running
mount=/mnt/t /dev/nvme0n1 xfs
"""


class FakeVM(VM):
    """Answers like the test VM, records the scripts it was given."""

    def __init__(self, up: bool = True) -> None:
        super().__init__(Path('/nonexistent'))
        self.up = up
        self.scripts: list[str] = []
        self.synced: list[Path] = []
        self.fail_build = False

    def running(self) -> bool:
        return self.up

    def reachable(self) -> bool:
        return self.up

    def run(self, script: str, timeout: float = 60) -> Result:
        if not self.up:
            raise VMError('ssh failed')
        self.scripts.append(script)
        if 'meson compile' in script:
            if self.fail_build:
                return Result(1, '', 'ninja: build stopped')
            return Result(0, 'nvme version 3.1 (git 3.1)\n', '')
        return Result(0, STATUS, '')

    def wait_up(self, timeout: float = 0) -> float:
        return 0.0

    def start(self) -> float:
        self.up = True
        return 12.34

    def sync(self, src: Path) -> None:
        self.synced.append(src)


def call(server: Server, name: str, **args: Any) -> dict[str, Any]:
    resp = server.handle(
        {
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'tools/call',
            'params': {'name': name, 'arguments': args},
        }
    )
    assert resp is not None
    result: dict[str, Any] = resp['result']
    return result


class TestProtocol(unittest.TestCase):
    def setUp(self) -> None:
        self.server = Server(FakeVM(), Path('/src'))

    def test_initialize(self) -> None:
        resp = self.server.handle(
            {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'initialize',
                'params': {'protocolVersion': '2025-03-26'},
            }
        )
        assert resp is not None
        self.assertEqual(resp['result']['protocolVersion'], '2025-03-26')
        self.assertEqual(resp['result']['serverInfo']['name'], 'discoverd-vm')

    def test_notification(self) -> None:
        self.assertIsNone(
            self.server.handle(
                {'jsonrpc': '2.0', 'method': 'notifications/initialized'}
            )
        )

    def test_unknown_method(self) -> None:
        resp = self.server.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'x'})
        assert resp is not None
        self.assertEqual(resp['error']['code'], METHOD_NOT_FOUND)

    def test_unknown_argument(self) -> None:
        resp = self.server.handle(
            {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'tools/call',
                'params': {'name': 'vm_status', 'arguments': {'x': 1}},
            }
        )
        assert resp is not None
        self.assertEqual(resp['error']['code'], INVALID_PARAMS)

    def test_parse_error(self) -> None:
        out = io.StringIO()
        self.server.serve(io.StringIO('{not json\n'), out)
        self.assertEqual(
            json.loads(out.getvalue())['error']['code'], PARSE_ERROR
        )


class TestTools(unittest.TestCase):
    def test_changes_need_the_flag(self) -> None:
        ro = {'vm_status', 'list_scenarios', 'shutdown_log'}
        names = set(Server(FakeVM(), Path('/src')).tools)
        self.assertEqual(names, ro)
        names = set(Server(FakeVM(), Path('/src'), True).tools)
        self.assertEqual(
            names,
            ro
            | {
                'vm_create',
                'vm_stop',
                'vm_start',
                'vm_sync_build',
                'run_scenario',
            },
        )

    def test_status(self) -> None:
        out = call(Server(FakeVM(), Path('/src')), 'vm_status')
        st = out['structuredContent']
        self.assertTrue(st['ssh'])
        self.assertEqual(st['systemd'], '259')
        self.assertEqual(st['source'], 'v3.1-1010-g7dfaf566a')
        self.assertEqual(
            st['controllers'], ['nvme0 tcp live nqn.2026-10.test:shutdown']
        )
        self.assertEqual(st['mounts'], ['/mnt/t /dev/nvme0n1 xfs'])

    def test_status_vm_down(self) -> None:
        out = call(Server(FakeVM(up=False), Path('/src')), 'vm_status')
        self.assertEqual(out['structuredContent'], {'running': False})

    def test_start(self) -> None:
        vm = FakeVM(up=False)
        out = call(Server(vm, Path('/src'), True), 'vm_start')
        self.assertEqual(
            out['structuredContent'], {'started': True, 'up_after': 12.3}
        )

    @mock.patch('dvm_mcp.server.describe', return_value='v3.1-5-gabc')
    def test_sync_build(self, _: mock.MagicMock) -> None:
        vm = FakeVM()
        out = call(Server(vm, Path('/src'), True), 'vm_sync_build')
        self.assertFalse(out['isError'])
        self.assertEqual(vm.synced, [Path('/src')])
        build = next(x for x in vm.scripts if 'meson compile' in x)
        self.assertIn('echo v3.1-5-gabc > ', build)
        # the units are recreated after the install
        self.assertIn('reset_vm', vm.scripts[-1])
        self.assertEqual(out['structuredContent']['source'], 'v3.1-5-gabc')

    @mock.patch('dvm_mcp.server.describe', return_value='v3.1-5-gabc')
    def test_sync_build_fails(self, _: mock.MagicMock) -> None:
        vm = FakeVM()
        vm.fail_build = True
        out = call(Server(vm, Path('/src'), True), 'vm_sync_build')
        self.assertTrue(out['isError'])
        self.assertIn('ninja: build stopped', out['content'][0]['text'])

    def test_sync_build_vm_down(self) -> None:
        out = call(
            Server(FakeVM(up=False), Path('/src'), True), 'vm_sync_build'
        )
        self.assertTrue(out['isError'])
        self.assertIn('vm_start', out['content'][0]['text'])


class TestParseStatus(unittest.TestCase):
    def test_empty(self) -> None:
        self.assertEqual(
            parse_status(''), {'controllers': [], 'units': [], 'mounts': []}
        )

    def test_no_value_lines_ignored(self) -> None:
        self.assertNotIn('garbage', parse_status('garbage\n'))


if __name__ == '__main__':
    unittest.main()
