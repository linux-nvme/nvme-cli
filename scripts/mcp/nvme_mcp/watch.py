# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""What changed over a series of snapshots of nvme top: the timeline of
a failover, a reset or a reconnect."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import analysis
from .analysis import CTRL_COUNTERS, NS_COUNTERS, PATH_COUNTERS, Limits
from .nvme import Snapshot

# The most events a watch reports, the rest are only counted
MAX_EVENTS = 1000

# An object has a load, rather than a burst like a partition scan after
# a reconnect, once it had I/O in this many samples in a row
LOAD_SAMPLES = 3

# Rises of a counter this many intervals apart are one event
RISING_GAP = 3


@dataclass
class _Path:
    """What a watch gathers about a path over its samples"""

    subsystem: str
    namespace: str
    controller: str | None
    where: dict[str, Any]
    samples: int = 0
    iops: float = 0.0
    max_latency: float = 0.0
    idle_samples: int = 0


@dataclass
class Watch:
    """Turns a series of snapshots into events and I/O stalls."""

    interval: int
    limits: Limits = field(default_factory=Limits)
    subsystem: str | None = None
    samples: int = 0
    failed: int = 0
    dropped: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)
    stalls: list[dict[str, Any]] = field(default_factory=list)
    # the state of each object at the previous sample, by (type, name)
    _state: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    # the end of the last sample with I/O of a namespace with a stall
    _stalled: dict[str, float] = field(default_factory=dict)
    _paths: dict[str, _Path] = field(default_factory=dict)
    # the last rising event of each counter, to add the next rises to
    _rising: dict[tuple[str, str, str], dict[str, Any]] = field(
        default_factory=dict
    )
    _last: float = 0.0

    def _event(
        self, t: float, sub: str, kind: str, name: str, event: str, **kw: Any
    ) -> dict[str, Any] | None:
        if len(self.events) >= MAX_EVENTS:
            self.dropped += 1
            return None
        e = {
            'T': round(t, 1),
            'Subsystem': sub,
            'Type': kind,
            'Name': name,
            'Event': event,
            **kw,
        }
        self.events.append(e)
        return e

    def _counter(
        self,
        t: float,
        sub: str,
        kind: str,
        name: str,
        k: str,
        delta: int,
        total: int,
    ) -> None:
        """A counter rose by @delta: e.g. the reconnects of a controller
        rise every reconnect_delay until it is back, one event says it."""
        key = (kind, f'{sub}/{name}', k)
        last = self._rising.get(key)
        if (
            last is not None
            and t - last.get('Until', last['T'])
            <= RISING_GAP * self.interval + 0.5
        ):
            last.update(
                Delta=last['Delta'] + delta, Total=total, Until=round(t, 1)
            )
            return
        e = self._event(
            t,
            sub,
            kind,
            name,
            f'{k.lower()}-rising',
            Delta=delta,
            Total=total,
        )
        if e is not None:
            self._rising[key] = e

    def _load(
        self,
        t: float,
        busy: bool,
        state: dict[str, Any],
        old: dict[str, Any] | None,
        first: bool,
    ) -> str | None:
        """Whether the I/O of an object 'started' or 'stopped' with this
        sample. A load starts at the first of LOAD_SAMPLES busy samples
        in a row, state['_since'], and stops with the first idle one.
        Who is busy at the start of the watch has a load already."""
        streak = (old['_streak'] if old else 0) + 1 if busy else 0
        was = bool(old and old['_loaded'])
        state['_streak'] = streak
        state['_since'] = (
            t if streak == 1 else old['_since'] if old and busy else None
        )
        state['_loaded'] = busy and (
            was or streak >= LOAD_SAMPLES or (first and old is None)
        )
        if state['_loaded'] and not was and not first:
            return 'started'
        if was and not busy:
            return 'stopped'
        return None

    def fail(self, t: float, message: str) -> None:
        """A sample at @t failed with @message."""
        self.failed += 1
        if len(self.events) >= MAX_EVENTS:
            self.dropped += 1
            return
        self.events.append(
            {'T': round(t, 1), 'Event': 'sample-failed', 'Message': message}
        )

    def add(self, t: float, snap: Snapshot) -> None:
        """The snapshot which ended @t seconds after the start."""
        first = not self.samples
        self.samples += 1
        self._last = t
        seen: dict[tuple[str, str], dict[str, Any]] = {}

        for sub in analysis.subsystems(snap, self.subsystem):
            name = sub['Name']
            ctrls = analysis.controllers(sub)
            for c in sub.get('Controllers', []):
                state = {
                    'State': c.get('State'),
                    **{k: c[k] for k in CTRL_COUNTERS if k in c},
                }
                self._update(
                    t,
                    name,
                    'controller',
                    c['Name'],
                    state,
                    seen,
                    first,
                    analysis.where(c),
                )
            for ns in sub.get('Namespaces', []):
                self._namespace(t, name, ns, seen, first)
                for p in ns.get('Paths', []):
                    self._path(t, name, ns, p, ctrls, seen, first)

        for (kind, key), old in self._state.items():
            if (kind, key) not in seen:
                self._event(t, old['_sub'], kind, key.split('/')[-1], 'gone')
        self._state = seen

    def _update(
        self,
        t: float,
        sub: str,
        kind: str,
        name: str,
        state: dict[str, Any],
        seen: dict[tuple[str, str], dict[str, Any]],
        first: bool,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Records @state of an object, with events for the changes since
        the previous sample. Returns the previous state."""
        key = (kind, f'{sub}/{name}')
        state['_sub'] = sub
        seen[key] = state
        old = self._state.get(key)
        if old is None:
            if not first:
                shown = {
                    k: v for k, v in state.items() if not k.startswith('_')
                }
                self._event(
                    t, sub, kind, name, 'appeared', **shown, **(extra or {})
                )
            return None
        for k, v in state.items():
            if k in ('State', 'ANAState') and v is None:
                # unreadable, e.g. while the controller is deleted: no
                # state, keep the last one
                state[k] = old.get(k)
                continue
            if k.startswith('_') or k not in old or old[k] == v:
                continue
            if isinstance(v, int) and not isinstance(v, bool):
                # a counter; one which went down belongs to a new object
                if v > old[k]:
                    self._counter(t, sub, kind, name, k, v - old[k], v)
            elif k in ('State', 'ANAState'):
                self._event(
                    t,
                    sub,
                    kind,
                    name,
                    'state' if k == 'State' else 'ana-state',
                    From=old[k],
                    To=v,
                    **(extra or {}),
                )
        return old

    def _namespace(
        self,
        t: float,
        sub: str,
        ns: dict[str, Any],
        seen: dict[tuple[str, str], dict[str, Any]],
        first: bool,
    ) -> None:
        name = ns['Name']
        busy = analysis._iops(ns['Stats']) >= self.limits.min_iops
        state: dict[str, Any] = {
            **{k: ns[k] for k in NS_COUNTERS if k in ns},
        }
        if 'Paths' in ns:
            state['_optimized'] = any(
                p.get('ANAState') == 'optimized' for p in ns['Paths']
            )
        old = self._update(t, sub, 'namespace', name, state, seen, first)
        load = self._load(t, busy, state, old, first)
        if old is None:
            return

        key = f'{sub}/{name}'
        if load == 'stopped':
            self._stalled[key] = self._prev
            self._event(t, sub, 'namespace', name, 'io-stopped')
        elif load == 'started':
            # back at the start of its load
            t0 = state['_since']
            since = self._stalled.pop(key, None)
            if since is None:
                # the workload started during the watch
                self._event(t0, sub, 'namespace', name, 'io-started')
            else:
                self.stalls.append(
                    {
                        'Subsystem': sub,
                        'Namespace': name,
                        'From': round(since, 1),
                        'To': round(t0, 1),
                        'Seconds': round(t0 - since, 1),
                    }
                )
                self._event(t0, sub, 'namespace', name, 'io-resumed')
        opt, was = state.get('_optimized'), old.get('_optimized')
        if opt is not None and was is not None and opt != was:
            self._event(
                t,
                sub,
                'namespace',
                name,
                'optimized-path-back' if opt else 'no-optimized-path',
            )

    def _path(
        self,
        t: float,
        sub: str,
        ns: dict[str, Any],
        p: dict[str, Any],
        ctrls: dict[str, Any],
        seen: dict[tuple[str, str], dict[str, Any]],
        first: bool,
    ) -> None:
        stats = p['Stats']
        iops = analysis._iops(stats)
        busy = iops >= self.limits.min_iops
        where = {
            'Controller': p.get('Controller'),
            **analysis.where(ctrls.get(p.get('Controller', ''))),
        }
        state = {
            'ANAState': p.get('ANAState'),
            **{k: p[k] for k in PATH_COUNTERS if k in p},
        }
        old = self._update(
            t, sub, 'path', p['Name'], state, seen, first, where
        )
        load = self._load(t, busy, state, old, first)
        if load == 'started':
            self._event(
                state['_since'], sub, 'path', p['Name'], 'io-started', **where
            )
        elif load == 'stopped':
            self._event(t, sub, 'path', p['Name'], 'io-stopped', **where)

        key = f'{sub}/{p["Name"]}'
        acc = self._paths.get(key)
        if acc is None:
            acc = self._paths[key] = _Path(
                sub, ns['Name'], p.get('Controller'), where
            )
        acc.where = where
        acc.samples += 1
        acc.iops += iops
        acc.max_latency = max(acc.max_latency, analysis._latency(stats))
        if not busy:
            acc.idle_samples += 1

    @property
    def _prev(self) -> float:
        """The end of the previous sample"""
        return self._last - self.interval

    def report(self, duration: float) -> dict[str, Any]:
        """The events, the stalls and a summary of each path."""
        stalls = list(self.stalls)
        for key, since in self._stalled.items():
            sub, name = key.split('/', 1)
            stalls.append(
                {
                    'Subsystem': sub,
                    'Namespace': name,
                    'From': round(since, 1),
                    'To': None,
                    'Seconds': round(self._last - since, 1),
                    'Ongoing': True,
                }
            )
        out: dict[str, Any] = {
            'Duration': round(duration, 1),
            'Interval': self.interval,
            'Samples': self.samples,
            'FailedSamples': self.failed,
            # the start of a load is dated back
            'Events': sorted(self.events, key=lambda e: float(e['T'])),
            'Stalls': stalls,
            'Paths': [
                {
                    'Subsystem': p.subsystem,
                    'Namespace': p.namespace,
                    'Path': key.split('/', 1)[1],
                    **p.where,
                    'AvgIOPS': round(p.iops / p.samples, 2),
                    'MaxLatencyMs': round(p.max_latency, 3),
                    'SecondsWithoutIO': p.idle_samples * self.interval,
                }
                for key, p in self._paths.items()
            ],
        }
        if self.dropped:
            out['DroppedEvents'] = self.dropped
        return out
