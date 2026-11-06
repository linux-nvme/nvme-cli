# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""The results of a daemon wringer run, from its log.

The wringers (discoverd/tests/wringer.sh, keysd/tests/wringer.sh) print a
line per check, '  PASS: ...', '  FAIL: ...' or '  SKIP: ...', and at
the end one line with the totals:

    Results: 94 passed, 0 failed, 0 skipped

in color (ANSI escapes). A log without that line is of a run which did
not get to the end.
"""

from __future__ import annotations

import re
from typing import Any

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
_CHECK_RE = re.compile(r'^\s+(FAIL|SKIP): (.*)$')
_RESULTS_RE = re.compile(
    r'^Results: (\d+) passed, (\d+) failed(?:, (\d+) skipped)?\s*$'
)
COUNTS = ('pass', 'fail', 'skip')


def summarize(log: str) -> dict[str, Any]:
    """Return the summary of a wringer log: its outcome, the totals, and
    the checks which failed or were skipped."""
    tests = []
    totals = None
    for raw in log.splitlines():
        line = _ANSI_RE.sub('', raw)
        m = _CHECK_RE.match(line)
        if m:
            status = 'fail' if m[1] == 'FAIL' else 'skip'
            tests.append(
                {'test': m[2].strip(), 'config': '', 'status': status}
            )
            continue
        m = _RESULTS_RE.match(line)
        if m:
            totals = m
    problems = []
    if totals is None:
        counts = {
            'pass': 0,
            'fail': sum(t['status'] == 'fail' for t in tests),
            'skip': sum(t['status'] == 'skip' for t in tests),
        }
        problems.append('the run did not finish')
    else:
        counts = {
            'pass': int(totals[1]),
            'fail': int(totals[2]),
            'skip': int(totals[3] or 0),
        }
    if counts['fail']:
        n = counts['fail']
        problems.append(f'{n} check' + ('' if n == 1 else 's') + ' failed')
    return {
        'kind': 'wringer',
        'outcome': 'fail' if problems else 'pass',
        'problems': problems,
        'counts': counts,
        'tests': tests,
    }
