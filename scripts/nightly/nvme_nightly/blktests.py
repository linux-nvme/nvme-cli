# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""The results of a blktests run, judged against the known failures.

blktests writes one file per test run, RESULTS/<config>/<group>/<NNN>,
with a 'key<TAB>value' line per item (status, reason, runtime, ...).
<config> is the device name, followed by the condition with ' ' and '='
replaced by '_': nodev_tr_rdma, nvme1n1_tr_loop_bd_file.

The outcome does not depend on the exit status of ./check, so that it
does not depend on the IGNORE_FAILURE support of blktests either.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .known_failures import Entry

SUMMARY_VERSION = 1

_TEST_FILE_RE = re.compile(r'^[0-9]{3}$')


@dataclass(frozen=True, order=True)
class Result:
    """One test run of blktests."""

    test: str
    config: str
    status: str
    reason: str = ''
    runtime: str = ''
    description: str = ''


def read_result(path: Path, config: str, test: str) -> Result:
    items = {}
    for line in path.read_text(
        encoding='utf-8', errors='replace'
    ).splitlines():
        key, _, value = line.partition('\t')
        items[key] = value
    return Result(
        test=test,
        config=config,
        status=items.get('status', 'unknown'),
        reason=items.get('reason', ''),
        runtime=items.get('runtime', ''),
        description=items.get('description', ''),
    )


def read_results(results: Path) -> list[Result]:
    """Return all test runs below the blktests results directory."""
    found = []
    for path in results.glob('*/*/*'):
        if not path.is_file() or not _TEST_FILE_RE.match(path.name):
            continue
        config = path.parent.parent.name
        test = f'{path.parent.name}/{path.name}'
        found.append(read_result(path, config, test))
    return sorted(found)


def matches(test: str, result: Result) -> bool:
    """Whether a known failure entry applies to a test run."""
    name, _, conds = test.partition(':')
    if name not in (result.test, result.test.split('/')[0]):
        return False
    config = f'_{result.config}_'
    for cond in filter(None, conds.split(',')):
        if '_{}_'.format(re.sub('[ =]', '_', cond)) not in config:
            return False
    return True


def summarize(
    results: Iterable[Result],
    known: Iterable[Entry],
    check_status: int | None = None,
) -> dict[str, Any]:
    """Return the summary of a run: every test run and the outcome.

    The run fails when a test fails which no 'ignore' entry covers, or
    when ./check failed without a failed test to explain it (it did not
    get to the end).
    """
    results = list(results)
    known = sorted(known)
    ignores = [e for e in known if e.action == 'ignore']
    tests = []
    counts = {'pass': 0, 'fail': 0, 'ignored': 0, 'not run': 0, 'other': 0}
    hits = dict.fromkeys(known, 0)
    known_passed = 0
    for r in results:
        entry = next((e for e in ignores if matches(e.test, r)), None)
        item: dict[str, Any] = {
            'test': r.test,
            'config': r.config,
            'status': r.status,
        }
        for key in ('reason', 'runtime', 'description'):
            if getattr(r, key):
                item[key] = getattr(r, key)
        if entry:
            item['known'] = entry.ref
            hits[entry] += 1
        if r.status == 'fail':
            counts['ignored' if entry else 'fail'] += 1
        elif r.status in counts:
            counts[r.status] += 1
            if r.status == 'pass' and entry:
                known_passed += 1
        else:
            counts['other'] += 1
        tests.append(item)
    for e in known:
        if e.action == 'exclude':
            hits[e] = -1

    problems = []
    if not results:
        problems.append('no test results')
    if counts['fail']:
        problems.append(f'{counts["fail"]} failed test runs')
    if check_status and not counts['fail'] and not counts['ignored']:
        problems.append(
            f'./check exited with {check_status} without a failed test'
        )
    return {
        'version': SUMMARY_VERSION,
        'outcome': 'fail' if problems else 'pass',
        'problems': problems,
        'check_status': check_status,
        'counts': dict(counts, known_passed=known_passed),
        'known_failures': [
            {
                'action': e.action,
                'test': e.test,
                'ref': e.ref,
                # -1: excluded, never runs; 0: matched no test run
                'matched': hits[e],
            }
            for e in known
        ],
        'tests': tests,
    }
