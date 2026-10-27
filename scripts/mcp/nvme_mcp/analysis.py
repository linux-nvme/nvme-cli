# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""What the snapshots of nvme top tell about the paths and the policies."""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any

from .nvme import Snapshot

# The counters of a path and of a controller, cumulative since boot
PATH_COUNTERS = ('Retries', 'Failovers', 'Errors')
CTRL_COUNTERS = ('Resets', 'Reconnects', 'Errors')
NS_COUNTERS = ('RequeueIO', 'FailIO')


@dataclass
class Limits:
    """When a path counts as an outlier."""

    # its latency is this many times the median of its siblings
    latency_factor: float = 2.0
    # and at least this many milliseconds
    latency_min_ms: float = 0.5
    # its share of the I/O differs from an even share by this fraction
    imbalance: float = 0.5
    # a path or namespace with fewer IOPS has too little I/O to judge
    min_iops: float = 10.0


def _iops(stats: dict[str, Any]) -> float:
    return float(stats.get('ReadIOPS', 0)) + float(stats.get('WriteIOPS', 0))


def _latency(stats: dict[str, Any]) -> float:
    """The average latency of the reads and the writes."""
    r, w = float(stats.get('ReadIOPS', 0)), float(stats.get('WriteIOPS', 0))
    if not r + w:
        return 0.0
    return (
        r * float(stats.get('ReadLatencyMs', 0))
        + w * float(stats.get('WriteLatencyMs', 0))
    ) / (r + w)


def _bandwidth(stats: dict[str, Any]) -> float:
    return float(stats.get('ReadBytesPerSec', 0)) + float(
        stats.get('WriteBytesPerSec', 0)
    )


def subsystems(snap: Snapshot, name: str | None = None) -> list[Any]:
    """The subsystems of @snap, or the one called @name."""
    subs: list[Any] = snap.get('Subsystems', [])
    if name is None:
        return subs
    return [s for s in subs if s.get('Name') == name]


@dataclass
class Counters:
    """The counters of the previous call, to tell which ones went up."""

    seen: dict[str, int] = field(default_factory=dict)

    def delta(self, key: str, value: int) -> int | None:
        """How much @value grew since the last call, None at first."""
        prev = self.seen.get(key)
        self.seen[key] = value
        if prev is None:
            return None
        return value - prev


def _counters(
    obj: dict[str, Any],
    names: tuple[str, ...],
    prefix: str,
    counters: Counters,
    flags: list[str],
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name in names:
        if name not in obj:
            continue
        value = int(obj[name])
        delta = counters.delta(f'{prefix}/{name}', value)
        out[name] = value
        if delta:
            out[f'{name}Delta'] = delta
            flags.append(f'{name.lower()}-rising')
    return out


def _path_health(
    sub: dict[str, Any],
    ns: dict[str, Any],
    limits: Limits,
    counters: Counters,
) -> list[dict[str, Any]]:
    paths = ns.get('Paths', [])
    busy = [p for p in paths if _iops(p['Stats']) >= limits.min_iops]
    lats = [_latency(p['Stats']) for p in busy]
    median = statistics.median(lats) if lats else 0.0
    total = sum(_iops(p['Stats']) for p in paths)
    optimized = [p for p in paths if p.get('ANAState') == 'optimized']
    spreads = sub.get('IOPolicy') in ('round-robin', 'queue-depth')

    out = []
    for p in paths:
        flags: list[str] = []
        stats = p['Stats']
        iops, lat = _iops(stats), _latency(stats)
        share = iops / total if total else 0.0

        state = p.get('ANAState')
        if state is not None and state != 'optimized':
            flags.append(state)
        if (
            len(busy) > 1
            and iops >= limits.min_iops
            and lat >= limits.latency_min_ms
            and lat > limits.latency_factor * median
        ):
            flags.append('latency-outlier')
        if (
            spreads
            and p in optimized
            and len(optimized) > 1
            and total >= limits.min_iops
        ):
            even = 1 / len(optimized)
            if abs(share - even) > limits.imbalance * even:
                flags.append('imbalanced')

        entry: dict[str, Any] = {
            'Subsystem': sub['Name'],
            'Namespace': ns['Name'],
            'Path': p['Name'],
            'Controller': p.get('Controller'),
            'ANAState': state,
            'IOPS': round(iops, 2),
            'SharePercent': round(100 * share, 2),
            'LatencyMs': round(lat, 3),
            'BytesPerSec': round(_bandwidth(stats), 2),
            'UtilPercent': stats.get('UtilPercent'),
            'Inflights': stats.get('Inflights'),
        }
        entry.update(
            _counters(p, PATH_COUNTERS, f'path/{p["Name"]}', counters, flags)
        )
        entry['Flags'] = flags
        out.append(entry)
    return out


def health(
    snap: Snapshot,
    counters: Counters,
    limits: Limits | None = None,
    subsystem: str | None = None,
) -> dict[str, Any]:
    """The paths, namespaces and controllers which need a look."""
    limits = limits or Limits()
    first = not counters.seen
    paths: list[dict[str, Any]] = []
    namespaces: list[dict[str, Any]] = []
    ctrls: list[dict[str, Any]] = []

    for sub in subsystems(snap, subsystem):
        for ns in sub.get('Namespaces', []):
            if 'Paths' in ns:
                paths += _path_health(sub, ns, limits, counters)
            flags: list[str] = []
            entry = _counters(
                ns, NS_COUNTERS, f'ns/{ns["Name"]}', counters, flags
            )
            if 'Paths' in ns and not any(
                p.get('ANAState') == 'optimized' for p in ns['Paths']
            ):
                flags.append('no-optimized-path')
            if flags:
                namespaces.append(
                    {
                        'Subsystem': sub['Name'],
                        'Namespace': ns['Name'],
                        **entry,
                        'Flags': flags,
                    }
                )
        for c in sub.get('Controllers', []):
            flags = []
            entry = _counters(
                c, CTRL_COUNTERS, f'ctrl/{c["Name"]}', counters, flags
            )
            if c.get('State') != 'live':
                flags.append(f'state-{c.get("State") or "unknown"}')
            if flags:
                ctrls.append(
                    {
                        'Subsystem': sub['Name'],
                        'Controller': c['Name'],
                        'Transport': c.get('Transport'),
                        'Address': c.get('Address'),
                        **entry,
                        'Flags': flags,
                    }
                )

    return {
        'Interval': snap.get('Interval'),
        # the counter deltas need a previous call
        'Baseline': first,
        'Paths': paths,
        'FlaggedPaths': [p['Path'] for p in paths if p['Flags']],
        'Namespaces': namespaces,
        'Controllers': ctrls,
    }


def policy_result(
    snap: Snapshot, subsystem: str, policy: str
) -> dict[str, Any]:
    """How the I/O of @subsystem did under @policy."""
    subs = subsystems(snap, subsystem)
    if not subs:
        return {'IOPolicy': policy, 'Error': f'no subsystem {subsystem}'}
    sub = subs[0]
    path_iops: list[float] = []
    weighted = ios = 0.0
    for ns in sub.get('Namespaces', []):
        for p in ns.get('Paths', []):
            iops = _iops(p['Stats'])
            path_iops.append(iops)
            weighted += iops * _latency(p['Stats'])
            ios += iops
    stats = sub['Stats']
    mean = statistics.fmean(path_iops) if path_iops else 0.0
    spread = (
        statistics.pstdev(path_iops) / mean
        if len(path_iops) > 1 and mean
        else 0.0
    )
    return {
        'IOPolicy': policy,
        'IOPS': round(_iops(stats), 2),
        'BytesPerSec': round(_bandwidth(stats), 2),
        'AvgLatencyMs': round(weighted / ios, 3) if ios else 0.0,
        'MaxReadLatencyMs': stats.get('MaxReadLatencyMs'),
        'MaxWriteLatencyMs': stats.get('MaxWriteLatencyMs'),
        # the standard deviation of the path IOPS over their mean
        'PathSpread': round(spread, 3),
        'PathIOPS': [round(i, 2) for i in path_iops],
    }


def compare(results: list[dict[str, Any]]) -> dict[str, Any]:
    """The best policy by IOPS and by latency."""
    ok = [r for r in results if 'Error' not in r and r['IOPS'] > 0]
    out: dict[str, Any] = {'Results': results}
    if ok:
        out['BestIOPS'] = max(ok, key=lambda r: r['IOPS'])['IOPolicy']
        out['BestLatency'] = min(ok, key=lambda r: r['AvgLatencyMs'])[
            'IOPolicy'
        ]
    else:
        out['Note'] = 'no I/O during the measurements: start a workload'
    return out
