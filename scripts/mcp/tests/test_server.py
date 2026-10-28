# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests of the MCP protocol and the tools of nvme-mcp."""

from __future__ import annotations

import datetime
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from nvme_mcp.nvme import NvmeError, System
from nvme_mcp.server import (
    INVALID_PARAMS,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    PROTOCOL_VERSIONS,
    Server,
)

DATA = Path(__file__).resolve().parent / 'data'
# a wall clock time with milliseconds
WALL = 1_800_000_000.25


class FakeSystem(System):
    """Hands out the loop snapshot, keeps the I/O policy in memory"""

    def __init__(self) -> None:
        super().__init__()
        self.policy = 'numa'
        self.history: list[str] = []
        self.intervals: list[int] = []
        self.fail_at: str | None = None

    def snapshot(self, interval: int) -> dict[str, Any]:
        self.intervals.append(interval)
        if self.fail_at == self.policy:
            raise NvmeError('nvme top failed')
        snap: dict[str, Any] = json.loads(
            (DATA / 'loop-3-paths.json').read_text()
        )
        snap['Subsystems'][0]['IOPolicy'] = self.policy
        # round-robin gets twice the I/O of the others
        if self.policy == 'round-robin':
            for p in snap['Subsystems'][0]['Namespaces'][0]['Paths']:
                p['Stats']['ReadIOPS'] *= 2
            snap['Subsystems'][0]['Stats']['ReadIOPS'] *= 2
        return snap

    def iopolicy(self, subsystem: str) -> str:
        return self.policy

    def set_iopolicy(self, subsystem: str, policy: str) -> None:
        self.history.append(policy)
        self.policy = policy


def request(method: str, params: Any = None, mid: int = 1) -> dict[str, Any]:
    msg: dict[str, Any] = {'jsonrpc': '2.0', 'id': mid, 'method': method}
    if params is not None:
        msg['params'] = params
    return msg


class TestProtocol(unittest.TestCase):
    def setUp(self) -> None:
        self.server = Server(FakeSystem(), sleep=lambda s: None)

    def call(self, method: str, params: Any = None) -> Any:
        resp = self.server.handle(request(method, params))
        assert resp is not None
        return resp

    def test_initialize(self) -> None:
        resp = self.call('initialize', {'protocolVersion': '2025-03-26'})
        res = resp['result']
        self.assertEqual(res['protocolVersion'], '2025-03-26')
        self.assertIn('tools', res['capabilities'])
        self.assertEqual(res['serverInfo']['name'], 'nvme-mcp')

    def test_initialize_unknown_version(self) -> None:
        resp = self.call('initialize', {'protocolVersion': '1999-01-01'})
        self.assertEqual(
            resp['result']['protocolVersion'], PROTOCOL_VERSIONS[0]
        )

    def test_notification(self) -> None:
        msg = {'jsonrpc': '2.0', 'method': 'notifications/initialized'}
        self.assertIsNone(self.server.handle(msg))

    def test_ping(self) -> None:
        self.assertEqual(self.call('ping')['result'], {})

    def test_unknown_method(self) -> None:
        resp = self.call('resources/list')
        self.assertEqual(resp['error']['code'], METHOD_NOT_FOUND)

    def test_tools_read_only(self) -> None:
        tools = self.call('tools/list')['result']['tools']
        self.assertEqual(
            [t['name'] for t in tools],
            ['nvme_snapshot', 'nvme_path_health', 'nvme_watch'],
        )
        for t in tools:
            self.assertTrue(t['annotations']['readOnlyHint'])
            self.assertEqual(t['inputSchema']['type'], 'object')

    def test_tools_iopolicy(self) -> None:
        server = Server(FakeSystem(), allow_iopolicy=True)
        resp = server.handle(request('tools/list'))
        assert resp is not None
        tools = {t['name']: t for t in resp['result']['tools']}
        self.assertIn('nvme_compare_iopolicies', tools)
        self.assertFalse(
            tools['nvme_set_iopolicy']['annotations']['readOnlyHint']
        )

    def test_serve(self) -> None:
        rd = io.StringIO(
            json.dumps(request('ping', mid=7))
            + '\n\n'
            + '{not json\n'
            + json.dumps({'jsonrpc': '2.0', 'method': 'notifications/x'})
            + '\n'
        )
        wr = io.StringIO()
        self.server.serve(rd, wr)
        lines = [json.loads(x) for x in wr.getvalue().splitlines()]
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], {'jsonrpc': '2.0', 'id': 7, 'result': {}})
        self.assertEqual(lines[1]['error']['code'], PARSE_ERROR)


class TestTools(unittest.TestCase):
    def setUp(self) -> None:
        self.system = FakeSystem()
        self.server = Server(
            self.system, allow_iopolicy=True, sleep=lambda s: None
        )

    def tool(self, name: str, **args: Any) -> dict[str, Any]:
        resp = self.server.handle(
            request('tools/call', {'name': name, 'arguments': args})
        )
        assert resp is not None
        return resp

    def test_snapshot(self) -> None:
        res = self.tool('nvme_snapshot', interval=3)['result']
        self.assertFalse(res['isError'])
        self.assertEqual(self.system.intervals, [3])
        snap = res['structuredContent']
        self.assertEqual(json.loads(res['content'][0]['text']), snap)
        self.assertEqual(len(snap['Subsystems']), 1)

    def test_snapshot_filter(self) -> None:
        res = self.tool('nvme_snapshot', subsystem='nvme-subsys4')['result']
        self.assertEqual(res['structuredContent']['Subsystems'], [])

    def test_bad_interval(self) -> None:
        res = self.tool('nvme_snapshot', interval='2')['result']
        self.assertTrue(res['isError'])

    def test_unknown_argument(self) -> None:
        resp = self.tool('nvme_snapshot', delay=2)
        self.assertEqual(resp['error']['code'], INVALID_PARAMS)

    def test_unknown_tool(self) -> None:
        resp = self.tool('nvme_format')
        self.assertEqual(resp['error']['code'], INVALID_PARAMS)

    def test_path_health_keeps_counters(self) -> None:
        first = self.tool('nvme_path_health')['result']['structuredContent']
        second = self.tool('nvme_path_health')['result']['structuredContent']
        self.assertTrue(first['Baseline'])
        # the loop snapshot has no counters, so there is still no baseline
        self.assertTrue(second['Baseline'])
        self.assertEqual(len(second['Paths']), 3)

    def test_set_iopolicy(self) -> None:
        res = self.tool(
            'nvme_set_iopolicy', subsystem='nvme-subsys0', policy='round-robin'
        )['result']['structuredContent']
        self.assertEqual(res['Previous'], 'numa')
        self.assertEqual(self.system.policy, 'round-robin')

    def test_compare(self) -> None:
        res = self.tool(
            'nvme_compare_iopolicies',
            subsystem='nvme-subsys0',
            policies=['queue-depth', 'round-robin'],
            interval=4,
        )['result']['structuredContent']
        self.assertEqual(res['BestIOPS'], 'round-robin')
        self.assertEqual(res['Restored'], 'numa')
        self.assertEqual(
            self.system.history, ['queue-depth', 'round-robin', 'numa']
        )
        self.assertEqual(self.system.intervals, [4, 4])

    def test_compare_restores_after_failure(self) -> None:
        self.system.fail_at = 'round-robin'
        res = self.tool(
            'nvme_compare_iopolicies',
            subsystem='nvme-subsys0',
            policies=['queue-depth', 'round-robin'],
        )['result']
        self.assertTrue(res['isError'])
        self.assertEqual(self.system.policy, 'numa')


class ScriptedSystem(System):
    """Hands out a scripted series of snapshots and failures, and moves a
    fake clock by the interval of each"""

    def __init__(
        self, script: list[dict[str, Any] | None], kmsg: Path
    ) -> None:
        super().__init__(kmsg=kmsg)
        self.script = script
        self.now = 100.0
        self.intervals: list[int] = []

    def snapshot(self, interval: int) -> dict[str, Any]:
        self.intervals.append(interval)
        snap = self.script.pop(0)
        if snap is None:
            raise NvmeError('controller nvme1 went away')
        self.now += interval
        if self.kmsg.exists():
            with self.kmsg.open('a') as f:
                f.write(f'4,1,1,-;nvme{len(self.intervals)}: sample\n')
        return snap

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class TestWatchTool(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.kmsg = Path(self.tmp.name) / 'kmsg'
        self.kmsg.touch()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def watch(
        self, script: list[dict[str, Any] | None], **args: Any
    ) -> dict[str, Any]:
        self.system = ScriptedSystem(script, self.kmsg)
        server = Server(
            self.system,
            sleep=self.system.sleep,
            clock=lambda: self.system.now,
            wall=lambda: WALL + self.system.now,
        )
        resp = server.handle(
            request('tools/call', {'name': 'nvme_watch', 'arguments': args})
        )
        assert resp is not None
        result: dict[str, Any] = resp['result']
        return result

    def loop(self, state: str = 'live') -> dict[str, Any]:
        snap: dict[str, Any] = json.loads(
            (DATA / 'loop-3-paths.json').read_text()
        )
        snap['Subsystems'][0]['Controllers'][1]['State'] = state
        return snap

    def test_watch(self) -> None:
        res = self.watch(
            [self.loop(), self.loop('resetting'), self.loop()],
            duration=6,
            interval=2,
        )
        self.assertFalse(res['isError'])
        report = res['structuredContent']
        self.assertEqual(self.system.intervals, [2, 2, 2])
        self.assertEqual((report['Samples'], report['Duration']), (3, 6.0))
        self.assertEqual(
            [(e['T'], e['Name'], e['To']) for e in report['Events']],
            [(4.0, 'nvme1', 'resetting'), (6.0, 'nvme1', 'live')],
        )
        # each line with the end of the sample it was logged in
        self.assertEqual(
            [(x['T'], x['Message']) for x in report['KernelLog']],
            [
                (2.0, 'nvme1: sample'),
                (4.0, 'nvme2: sample'),
                (6.0, 'nvme3: sample'),
            ],
        )
        self.assertNotIn('KernelLogError', report)

    def test_watch_started_is_wall_clock_time(self) -> None:
        # to line T up with the timestamps of other tools
        report = self.watch([self.loop()], duration=2, interval=2)[
            'structuredContent'
        ]
        started = datetime.datetime.fromisoformat(report['Started'])
        self.assertIsNotNone(started.tzinfo)
        # the scripted clock starts at 100 s
        self.assertEqual(started.timestamp(), WALL + 100.0)

    def test_watch_without_kernel_log(self) -> None:
        self.kmsg.unlink()
        report = self.watch([self.loop()], duration=1)['structuredContent']
        self.assertNotIn('KernelLog', report)
        self.assertIn('cannot read the kernel log', report['KernelLogError'])
        self.assertEqual(report['Samples'], 1)

    def test_watch_goes_on_after_failure(self) -> None:
        report = self.watch(
            [self.loop(), None, self.loop('connecting')], duration=3
        )['structuredContent']
        self.assertEqual(report['FailedSamples'], 1)
        self.assertEqual(
            [(e['T'], e['Event']) for e in report['Events']],
            [(2.0, 'sample-failed'), (3.0, 'state')],
        )

    def test_watch_all_failed(self) -> None:
        res = self.watch([None, None], duration=2)
        self.assertTrue(res['isError'])
        self.assertIn('went away', res['content'][0]['text'])

    def test_watch_limits(self) -> None:
        for args in ({'duration': 0}, {'duration': 601}, {'interval': 11}):
            self.assertTrue(self.watch([], **args)['isError'], args)


if __name__ == '__main__':
    unittest.main()
