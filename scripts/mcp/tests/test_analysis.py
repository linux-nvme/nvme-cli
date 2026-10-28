# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests of what nvme-mcp makes of the snapshots of nvme top."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from typing import Any

from nvme_mcp import analysis

DATA = Path(__file__).resolve().parent / 'data'


def loop_snapshot() -> dict[str, Any]:
    """nvme top -o json of an nvme-loop subsystem with three paths under
    round-robin, with a read and a write load"""
    snap: dict[str, Any] = json.loads((DATA / 'loop-3-paths.json').read_text())
    return snap


def paths(snap: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = snap['Subsystems'][0]['Namespaces'][0][
        'Paths'
    ]
    return result


class TestHealth(unittest.TestCase):
    def health(
        self,
        snap: dict[str, Any],
        counters: analysis.Counters | None = None,
    ) -> dict[str, Any]:
        return analysis.health(snap, counters or analysis.Counters())

    def flags(self, report: dict[str, Any]) -> dict[str, list[str]]:
        return {p['Path']: p['Flags'] for p in report['Paths']}

    def test_balanced(self) -> None:
        report = self.health(loop_snapshot())
        self.assertEqual(len(report['Paths']), 3)
        self.assertEqual(report['FlaggedPaths'], [])
        for p in report['Paths']:
            self.assertAlmostEqual(p['SharePercent'], 100 / 3, delta=2)
        self.assertTrue(report['Baseline'])

    def test_where(self) -> None:
        """Each path tells the transport and address of its controller"""
        snap = loop_snapshot()
        addr = 'traddr=192.168.30.30,trsvcid=4421,src_addr=192.168.30.1'
        ctrls = snap['Subsystems'][0]['Controllers']
        ctrls[1].update(Transport='tcp', Address=addr)
        report = self.health(snap)
        where = {
            p['Path']: (p['Controller'], p['Transport'], p['Address'])
            for p in report['Paths']
        }
        self.assertEqual(where['nvme0c0n1'], ('nvme0', 'loop', None))
        self.assertEqual(where['nvme0c1n1'], ('nvme1', 'tcp', addr))

    def test_where_without_controller(self) -> None:
        snap = loop_snapshot()
        snap['Subsystems'][0]['Controllers'] = []
        p = self.health(snap)['Paths'][0]
        self.assertIsNone(p['Transport'])
        self.assertIsNone(p['Address'])

    def test_latency(self) -> None:
        """The average of the read and the write latency, by their IOPS"""
        p = paths(loop_snapshot())[0]['Stats']
        p.update(
            ReadIOPS=300.0,
            WriteIOPS=100.0,
            ReadLatencyMs=1.0,
            WriteLatencyMs=5.0,
        )
        self.assertAlmostEqual(analysis._latency(p), (300 + 500) / 400)

    def test_latency_outlier(self) -> None:
        snap = loop_snapshot()
        paths(snap)[2]['Stats']['ReadLatencyMs'] = 5.0
        paths(snap)[2]['Stats']['WriteLatencyMs'] = 5.0
        self.assertEqual(
            self.flags(self.health(snap))['nvme0c2n1'], ['latency-outlier']
        )

    def test_small_latency_is_no_outlier(self) -> None:
        """Three times 0.02 ms is still nothing to look at"""
        snap = loop_snapshot()
        for p in paths(snap):
            p['Stats']['WriteIOPS'] = 0.0
        paths(snap)[2]['Stats']['ReadLatencyMs'] = 0.06
        self.assertEqual(self.health(snap)['FlaggedPaths'], [])

    def test_imbalance(self) -> None:
        snap = loop_snapshot()
        paths(snap)[0]['Stats']['ReadIOPS'] *= 4
        flags = self.flags(self.health(snap))
        self.assertIn('imbalanced', flags['nvme0c0n1'])

    def test_numa_is_not_imbalanced(self) -> None:
        """numa sends the I/O to the nearest path on purpose"""
        snap = loop_snapshot()
        snap['Subsystems'][0]['IOPolicy'] = 'numa'
        paths(snap)[0]['Stats']['ReadIOPS'] *= 4
        self.assertEqual(self.health(snap)['FlaggedPaths'], [])

    def test_ana_state(self) -> None:
        snap = loop_snapshot()
        paths(snap)[1]['ANAState'] = 'inaccessible'
        paths(snap)[1]['Stats'].update(ReadIOPS=0.0, WriteIOPS=0.0)
        flags = self.flags(self.health(snap))
        self.assertEqual(flags['nvme0c1n1'], ['inaccessible'])
        # the two optimized paths share the I/O evenly
        self.assertEqual(flags['nvme0c0n1'], [])

    def test_no_optimized_path(self) -> None:
        snap = loop_snapshot()
        for p in paths(snap):
            p['ANAState'] = 'non-optimized'
        report = self.health(snap)
        self.assertEqual(
            report['Namespaces'][0]['Flags'], ['no-optimized-path']
        )

    def test_counters_rising(self) -> None:
        counters = analysis.Counters()
        snap = loop_snapshot()
        for p in paths(snap):
            p.update(Retries=1, Failovers=0, Errors=2)
        first = self.health(snap, counters)
        self.assertTrue(first['Baseline'])
        self.assertEqual(first['FlaggedPaths'], [])
        self.assertEqual(first['Paths'][0]['Errors'], 2)

        paths(snap)[1]['Errors'] = 5
        paths(snap)[1]['Failovers'] = 1
        second = self.health(snap, counters)
        self.assertFalse(second['Baseline'])
        p = second['Paths'][1]
        self.assertEqual(p['Flags'], ['failovers-rising', 'errors-rising'])
        self.assertEqual(p['ErrorsDelta'], 3)
        self.assertEqual(second['FlaggedPaths'], ['nvme0c1n1'])

    def test_controller(self) -> None:
        counters = analysis.Counters()
        snap = loop_snapshot()
        ctrl = snap['Subsystems'][0]['Controllers'][1]
        ctrl.update(Resets=0, Reconnects=4)
        self.assertEqual(self.health(snap, counters)['Controllers'], [])

        ctrl.update(State='connecting', Reconnects=5)
        report = self.health(snap, counters)
        self.assertEqual(len(report['Controllers']), 1)
        c = report['Controllers'][0]
        self.assertEqual(c['Controller'], 'nvme1')
        self.assertEqual(c['ReconnectsDelta'], 1)
        self.assertEqual(c['Flags'], ['reconnects-rising', 'state-connecting'])

    def test_subsystem_filter(self) -> None:
        snap = loop_snapshot()
        report = analysis.health(
            snap, analysis.Counters(), subsystem='nvme-subsys9'
        )
        self.assertEqual(report['Paths'], [])

    def test_counters_left_out(self) -> None:
        """A kernel without the diag attributes has no counters"""
        report = self.health(loop_snapshot())
        self.assertNotIn('Errors', report['Paths'][0])


class TestPolicies(unittest.TestCase):
    def test_result(self) -> None:
        r = analysis.policy_result(
            loop_snapshot(), 'nvme-subsys0', 'round-robin'
        )
        self.assertEqual(r['IOPolicy'], 'round-robin')
        self.assertAlmostEqual(r['IOPS'], 36235.74 + 4203.07, places=2)
        self.assertEqual(len(r['PathIOPS']), 3)
        self.assertLess(r['PathSpread'], 0.05)
        self.assertGreater(r['AvgLatencyMs'], 0)

    def test_missing_subsystem(self) -> None:
        r = analysis.policy_result(loop_snapshot(), 'nvme-subsys7', 'numa')
        self.assertIn('Error', r)

    def test_compare(self) -> None:
        fast = analysis.policy_result(loop_snapshot(), 'nvme-subsys0', 'a')
        slow = copy.deepcopy(fast)
        slow.update(
            IOPolicy='b',
            IOPS=fast['IOPS'] / 2,
            AvgLatencyMs=fast['AvgLatencyMs'] / 2,
        )
        out = analysis.compare([fast, slow])
        self.assertEqual(out['BestIOPS'], 'a')
        self.assertEqual(out['BestLatency'], 'b')

    def test_compare_without_io(self) -> None:
        idle = {'IOPolicy': 'numa', 'IOPS': 0.0, 'AvgLatencyMs': 0.0}
        out = analysis.compare([idle])
        self.assertNotIn('BestIOPS', out)
        self.assertIn('Note', out)


if __name__ == '__main__':
    unittest.main()
