# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests of the timeline nvme-mcp makes of a series of snapshots."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from typing import Any

from nvme_mcp import watch

DATA = Path(__file__).resolve().parent / 'data'
LOOP: dict[str, Any] = json.loads((DATA / 'loop-3-paths.json').read_text())


def snapshot() -> dict[str, Any]:
    """The loop subsystem with three busy paths, with counters"""
    snap = copy.deepcopy(LOOP)
    sub = snap['Subsystems'][0]
    for c in sub['Controllers']:
        c.update(Resets=0, Reconnects=0, Errors=0)
    for p in sub['Namespaces'][0]['Paths']:
        p.update(Retries=0, Failovers=0, Errors=0)
    sub['Namespaces'][0].update(RequeueIO=0, FailIO=0)
    return snap


def sub(snap: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = snap['Subsystems'][0]
    return result


def ns(snap: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = sub(snap)['Namespaces'][0]
    return result


def path(snap: dict[str, Any], i: int) -> dict[str, Any]:
    result: dict[str, Any] = ns(snap)['Paths'][i]
    return result


def ctrl(snap: dict[str, Any], i: int) -> dict[str, Any]:
    result: dict[str, Any] = sub(snap)['Controllers'][i]
    return result


def idle(stats: dict[str, Any]) -> None:
    stats.update(ReadIOPS=0.0, WriteIOPS=0.0)


def failed_over() -> dict[str, Any]:
    """nvme1 reconnects, its path is inaccessible and carries no I/O, the
    I/O it had failed over"""
    snap = snapshot()
    ctrl(snap, 1)['State'] = 'connecting'
    ctrl(snap, 1)['Reconnects'] = 1
    path(snap, 1)['ANAState'] = 'inaccessible'
    path(snap, 1)['Failovers'] = 3
    idle(path(snap, 1)['Stats'])
    return snap


def stalled() -> dict[str, Any]:
    """No path and so no namespace has I/O"""
    snap = snapshot()
    idle(ns(snap)['Stats'])
    for p in ns(snap)['Paths']:
        idle(p['Stats'])
    return snap


def events(w: watch.Watch) -> list[tuple[float, str, str, str]]:
    return [(e['T'], e['Type'], e['Name'], e['Event']) for e in w.events]


class TestWatch(unittest.TestCase):
    def run_watch(
        self, snaps: list[dict[str, Any]], interval: int = 1
    ) -> watch.Watch:
        w = watch.Watch(interval)
        for i, snap in enumerate(snaps, 1):
            w.add(float(i * interval), snap)
        return w

    def test_quiet(self) -> None:
        w = self.run_watch([snapshot()] * 3)
        self.assertEqual(w.events, [])
        report = w.report(3.0)
        self.assertEqual(report['Samples'], 3)
        self.assertEqual(report['Stalls'], [])
        self.assertEqual(len(report['Paths']), 3)

    def test_failover(self) -> None:
        """The path is back at 4 s, which takes LOAD_SAMPLES busy samples
        to tell"""
        w = self.run_watch(
            [snapshot(), failed_over(), failed_over()]
            + [snapshot()] * watch.LOAD_SAMPLES
        )
        self.assertEqual(
            events(w),
            [
                (2.0, 'controller', 'nvme1', 'state'),
                (2.0, 'controller', 'nvme1', 'reconnects-rising'),
                (2.0, 'path', 'nvme0c1n1', 'ana-state'),
                (2.0, 'path', 'nvme0c1n1', 'failovers-rising'),
                (2.0, 'path', 'nvme0c1n1', 'io-stopped'),
                (4.0, 'controller', 'nvme1', 'state'),
                (4.0, 'path', 'nvme0c1n1', 'ana-state'),
                (4.0, 'path', 'nvme0c1n1', 'io-started'),
            ],
        )
        state = w.events[0]
        self.assertEqual((state['From'], state['To']), ('live', 'connecting'))
        self.assertEqual(state['Transport'], 'loop')
        ana = w.events[2]
        self.assertEqual(
            (ana['From'], ana['To']), ('optimized', 'inaccessible')
        )
        self.assertEqual(ana['Controller'], 'nvme1')
        self.assertEqual((w.events[3]['Delta'], w.events[3]['Total']), (3, 3))
        self.assertEqual(w.events[5]['To'], 'live')
        # the namespace kept its I/O on the other paths
        self.assertEqual(w.report(6.0)['Stalls'], [])

    def test_events_in_time_order(self) -> None:
        """The path is back at 3 s, known only at 5 s, after nvme2 reset
        at 4 s"""
        resetting = snapshot()
        ctrl(resetting, 2)['State'] = 'resetting'
        w = self.run_watch(
            [snapshot(), failed_over(), snapshot(), resetting, snapshot()]
        )
        report = w.report(5.0)
        self.assertEqual(
            [(e['T'], e['Name'], e['Event']) for e in report['Events']][-3:],
            [
                (3.0, 'nvme0c1n1', 'io-started'),
                (4.0, 'nvme2', 'state'),
                (5.0, 'nvme2', 'state'),
            ],
        )

    def test_path_back_for_a_moment(self) -> None:
        w = self.run_watch(
            [snapshot(), failed_over(), snapshot(), failed_over()]
        )
        io = [e for e in events(w) if e[3].startswith('io-')]
        self.assertEqual(io, [(2.0, 'path', 'nvme0c1n1', 'io-stopped')])

    def test_path_summary(self) -> None:
        w = self.run_watch(
            [snapshot(), failed_over(), failed_over(), snapshot()], interval=2
        )
        p = {x['Path']: x for x in w.report(8.0)['Paths']}
        self.assertEqual(p['nvme0c1n1']['SecondsWithoutIO'], 4)
        self.assertEqual(p['nvme0c0n1']['SecondsWithoutIO'], 0)
        self.assertEqual(p['nvme0c1n1']['Controller'], 'nvme1')
        self.assertEqual(p['nvme0c1n1']['Transport'], 'loop')
        busy = path(LOOP, 1)['Stats']
        iops = busy['ReadIOPS'] + busy['WriteIOPS']
        self.assertAlmostEqual(p['nvme0c1n1']['AvgIOPS'], iops / 2, places=1)

    def test_stall(self) -> None:
        """The I/O stopped in the sample which ended at 3 s, so after 2 s,
        and was back in the one which ended at 5 s"""
        w = self.run_watch(
            [snapshot(), snapshot(), stalled(), stalled()]
            + [snapshot()] * watch.LOAD_SAMPLES
        )
        report = w.report(7.0)
        self.assertEqual(
            report['Stalls'],
            [
                {
                    'Subsystem': 'nvme-subsys0',
                    'Namespace': 'nvme0n1',
                    'From': 2.0,
                    'To': 5.0,
                    'Seconds': 3.0,
                }
            ],
        )
        ns_events = [e for e in events(w) if e[1] == 'namespace']
        self.assertEqual(
            ns_events,
            [
                (3.0, 'namespace', 'nvme0n1', 'io-stopped'),
                (5.0, 'namespace', 'nvme0n1', 'io-resumed'),
            ],
        )

    def test_stall_with_a_burst(self) -> None:
        """A burst during the stall does not end it"""
        w = self.run_watch(
            [snapshot(), stalled(), snapshot(), stalled()]
            + [snapshot()] * watch.LOAD_SAMPLES
        )
        (stall,) = w.report(7.0)['Stalls']
        self.assertEqual((stall['From'], stall['To']), (1.0, 5.0))

    def test_burst_on_idle_namespace(self) -> None:
        """A namespace without a load gets a few reads as its paths come
        back, e.g. from a partition scan: no load, no stall"""
        w = self.run_watch(
            [stalled(), stalled(), snapshot(), snapshot(), stalled()]
        )
        self.assertEqual(w.events, [])
        self.assertEqual(w.report(5.0)['Stalls'], [])

    def test_stall_ongoing(self) -> None:
        w = self.run_watch([snapshot(), stalled(), stalled(), stalled()])
        (stall,) = w.report(4.0)['Stalls']
        self.assertEqual(
            (stall['From'], stall['To'], stall['Seconds']), (1.0, None, 3.0)
        )
        self.assertTrue(stall['Ongoing'])

    def test_workload_starts(self) -> None:
        """No I/O at the start is no stall"""
        w = self.run_watch([stalled()] + [snapshot()] * watch.LOAD_SAMPLES)
        self.assertEqual(w.report(4.0)['Stalls'], [])
        self.assertIn((2.0, 'namespace', 'nvme0n1', 'io-started'), events(w))

    def test_no_optimized_path(self) -> None:
        down = snapshot()
        for p in ns(down)['Paths']:
            p['ANAState'] = 'inaccessible'
        w = self.run_watch([snapshot(), down, snapshot()])
        ns_events = [e[3] for e in events(w) if e[1] == 'namespace']
        self.assertEqual(
            ns_events, ['no-optimized-path', 'optimized-path-back']
        )

    def test_gone_and_back(self) -> None:
        """A controller deleted after ctrl_loss_tmo and connected again,
        with its counters from zero"""
        busy = snapshot()
        for c in sub(busy)['Controllers']:
            c['Resets'] = 5
        gone = copy.deepcopy(busy)
        del sub(gone)['Controllers'][2]
        del ns(gone)['Paths'][2]
        back = snapshot()
        back_ctrl = ctrl(back, 2)
        w = self.run_watch([busy, gone, back])
        self.assertEqual(
            events(w),
            [
                (2.0, 'controller', 'nvme2', 'gone'),
                (2.0, 'path', 'nvme0c2n1', 'gone'),
                (3.0, 'controller', 'nvme2', 'appeared'),
                (3.0, 'path', 'nvme0c2n1', 'appeared'),
            ],
        )
        self.assertEqual(w.events[0]['Subsystem'], 'nvme-subsys0')
        appeared = w.events[2]
        self.assertEqual(appeared['State'], back_ctrl['State'])
        self.assertEqual(appeared['Resets'], 0)

    def test_unreadable_state(self) -> None:
        """A controller being deleted has no readable state for a sample
        before it is gone"""
        deleting = snapshot()
        ctrl(deleting, 2)['State'] = 'deleting (no IO)'
        unreadable = copy.deepcopy(deleting)
        ctrl(unreadable, 2)['State'] = None
        path(unreadable, 2)['ANAState'] = None
        back = copy.deepcopy(deleting)
        w = self.run_watch([snapshot(), deleting, unreadable, back])
        self.assertEqual(
            [(e[0], e[3]) for e in events(w) if e[1] != 'namespace'],
            [(2.0, 'state')],
        )

    def test_counter_rises_are_one_event(self) -> None:
        """A controller which tries to reconnect every 2 s"""
        snaps = []
        for i in range(10):
            snap = snapshot()
            ctrl(snap, 1)['Reconnects'] = i // 2
            snaps.append(snap)
        # a reconnect long after
        late = snapshot()
        ctrl(late, 1)['Reconnects'] = 6
        snaps += [snaps[-1]] * watch.RISING_GAP + [late]
        w = self.run_watch(snaps)
        rising = [e for e in w.events if e['Event'] == 'reconnects-rising']
        self.assertEqual(
            [(e['T'], e.get('Until'), e['Delta'], e['Total']) for e in rising],
            [(3.0, 9.0, 4, 4), (14.0, None, 2, 6)],
        )

    def test_counter_down_is_no_event(self) -> None:
        busy = snapshot()
        path(busy, 0)['Retries'] = 7
        w = self.run_watch([busy, snapshot()])
        self.assertEqual(w.events, [])

    def test_subsystem_filter(self) -> None:
        w = watch.Watch(1, subsystem='nvme-subsys9')
        w.add(1.0, snapshot())
        w.add(2.0, failed_over())
        self.assertEqual(w.events, [])
        self.assertEqual(w.report(2.0)['Paths'], [])

    def test_failed_sample(self) -> None:
        w = watch.Watch(1)
        w.add(1.0, snapshot())
        w.fail(2.04, 'nvme top failed')
        w.add(3.0, snapshot())
        report = w.report(3.0)
        self.assertEqual(report['FailedSamples'], 1)
        self.assertEqual(
            report['Events'],
            [
                {
                    'T': 2.0,
                    'Event': 'sample-failed',
                    'Message': 'nvme top failed',
                }
            ],
        )

    def test_event_cap(self) -> None:
        w = watch.Watch(1)
        w.add(1.0, snapshot())
        n = watch.MAX_EVENTS
        for i in range(n):
            # each flip is 2 events: state and ana-state
            w.add(float(i + 2), failed_over() if i % 2 == 0 else snapshot())
        report = w.report(float(n + 1))
        self.assertEqual(len(report['Events']), watch.MAX_EVENTS)
        self.assertGreater(report['DroppedEvents'], 0)


if __name__ == '__main__':
    unittest.main()
