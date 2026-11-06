# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""The results of a meson test run, from its testlog.json.

meson test writes one JSON object per test to
BUILDDIR/meson-logs/testlog.json (or LOGBASE.json), among others name,
result, duration and stdout. The test suites of nvme-cli are supposed
to pass: there are no known failures, every failure fails the section.

The summary keeps only the tests which did not pass, so that the
history of the status page stays small: a test missing from it passed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# The result of meson, as the status of a test.
STATUS = {
    'OK': 'pass',
    'EXPECTEDFAIL': 'expected fail',
    'SKIP': 'skip',
    'TIMEOUT': 'timeout',
    'FAIL': 'fail',
    'UNEXPECTEDPASS': 'fail',
    'ERROR': 'fail',
    'INTERRUPT': 'fail',
}
COUNTS = ('pass', 'fail', 'timeout', 'skip', 'expected fail')
# The status of the tests which fail the run.
FAILED = ('fail', 'timeout')
# The output of a failed test which the page includes.
OUTPUT_MAX = 64 << 10

# 'nvme-cli:mock / nvme-cli - print' is 'mock / nvme-cli - print' of the
# project nvme-cli: the page shows the latter.
_PROJECT_RE = re.compile(r'^[A-Za-z0-9_.-]+:(?=\S+ / )')


def read_testlog(path: Path) -> list[dict[str, Any]]:
    """The test records of a testlog.json, one JSON object per line.

    A line which is not a JSON object (a run killed while writing) is
    left out.
    """
    tests = []
    for line in path.read_text(encoding='utf-8', errors='replace').split('\n'):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict) and 'name' in item:
            tests.append(item)
    return tests


def display_name(name: str) -> str:
    """The name of a test without the project of its suite."""
    return _PROJECT_RE.sub('', name)


def output(item: dict[str, Any], limit: int = OUTPUT_MAX) -> str:
    """The end of the output of a test: what shows why it failed."""
    text = str(item.get('stdout') or '')
    if item.get('stderr'):
        text += str(item['stderr'])
    if len(text) > limit:
        text = '[truncated]\n' + text[-limit:]
    return text


def _plural(n: int, noun: str) -> str:
    return f'{n} {noun}' + ('' if n == 1 else 's')


def summarize(tests: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the summary of a meson test run: its outcome, the counts by
    status, and the tests which did not pass."""
    counts = dict.fromkeys(COUNTS, 0)
    items = []
    for t in tests:
        result = str(t.get('result', ''))
        status = STATUS.get(result, 'fail')
        counts[status] += 1
        if status == 'pass':
            continue
        item: dict[str, Any] = {
            'test': display_name(str(t['name'])),
            'config': '',
            'status': status,
            # the name in the log, for its line
            'id': str(t['name']),
        }
        if result not in STATUS:
            item['reason'] = f'unknown result {result!r}'
        elif status in FAILED:
            item['reason'] = result
        if isinstance(t.get('duration'), (int, float)):
            item['duration'] = round(float(t['duration']), 1)
        items.append(item)
    problems = []
    if not tests:
        problems.append('no test results')
    if counts['fail']:
        problems.append(_plural(counts['fail'], 'test') + ' failed')
    if counts['timeout']:
        problems.append(_plural(counts['timeout'], 'test') + ' timed out')
    return {
        'kind': 'meson',
        'outcome': 'fail' if problems else 'pass',
        'problems': problems,
        'counts': counts,
        'tests': items,
    }
