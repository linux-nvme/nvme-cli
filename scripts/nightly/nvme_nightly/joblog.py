# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Links to the lines of a GitHub Actions job log.

The web UI of a job addresses a line as JOB_URL#step:STEP:LINE, the
line counted from the start of the step. The REST API gives the log of
the whole job, one '<timestamp> <text>' line each, and the steps with
their start time to the second, but not where a step starts in the log.
That is found here: a step starts with its first line written in or
after the second of its start, which is the runner's start of a step:
'##[group]Run ...', or 'Prepare all required actions' before a local
action. None of this is a documented interface: when a step or a line is
not found, there is no link, and the page links the CI run instead.

blktests prints the result of a test run on a line of its own:

    nvme/003 (tr=rdma) (test if ...) [failed]
    nvme/033 => nvme1n1 (tr=loop bd=file) (create and ...) [failed]
    block/001 (stress device hotplugging) [failed]

The results directory names that config nodev_tr_rdma,
nvme1n1_tr_loop_bd_file and nodev (see blktests.py).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

_LINE_RE = re.compile(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\S*Z ?(.*)$')
_STEP_START = ('##[group]Run ', 'Prepare all required actions')
_RESULT_RE = re.compile(
    r'^(?P<test>[a-z0-9_-]+/\d{3})'
    r'(?: => (?P<dev>\S+))?'
    r'(?: \((?P<conds>[a-z_]+=[^ ()]*(?: [a-z_]+=[^ ()]*)*)\))?'
    r' .*\[(?P<status>[a-z ]+)\]\s*$'
)


def _split(line: str) -> tuple[str, str]:
    """The time to the second and the text of a log line."""
    m = _LINE_RE.match(line)
    return (m.group(1), m.group(2)) if m else ('', line)


def step_starts(
    lines: list[str], steps: Iterable[dict[str, Any]]
) -> dict[int, int]:
    """The index of the first line of each step in the job log, by step
    number, up to the first step which is not found.

    The steps are walked in order, each one starting after the one
    before, so that an earlier step which started in the same second is
    not taken for it.
    """
    starts: dict[int, int] = {}
    pos = -1
    for step in sorted(steps, key=lambda s: int(s.get('number', 0))):
        n = int(step.get('number', 0))
        begin = str(step.get('started_at') or '')[:19]
        # the first step, Set up job, starts the log
        start = 0 if lines and not starts else None
        i = pos + 1
        while start is None and i < len(lines):
            when, text = _split(lines[i])
            if when >= begin and text.startswith(_STEP_START):
                start = i
            i += 1
        if start is None:
            break
        starts[n] = start
        pos = start
    return starts


def config_name(dev: str | None, conds: str | None) -> str:
    """The results directory name of a config, as blktests writes it."""
    name = dev or 'nodev'
    if conds:
        name += '_' + re.sub('[ =]', '_', conds)
    return name


def result_lines(
    lines: list[str], start: int = 0
) -> dict[tuple[str, str], int]:
    """The index of the result line of each (test, config) after start;
    the last one, should a test run more than once."""
    found = {}
    for i in range(start, len(lines)):
        m = _RESULT_RE.match(_split(lines[i])[1])
        if m:
            key = (m['test'], config_name(m['dev'], m['conds']))
            found[key] = i
    return found


def add_links(
    summary: dict[str, Any],
    job: dict[str, Any],
    log: str,
    step_name: str,
) -> int:
    """Add the 'log' link to the failed test runs of a blktests summary.

    job is the job of the REST API (html_url, steps), log its log and
    step_name the step which ran blktests. Returns the number of links.
    """
    url = str(job.get('html_url') or '')
    if not url.startswith('https://'):
        return 0
    steps = job.get('steps') or []
    step = next((s for s in steps if s.get('name') == step_name), None)
    if step is None:
        return 0
    number = int(step['number'])
    lines = log.splitlines()
    starts = step_starts(lines, steps)
    if number not in starts:
        return 0
    start = starts[number]
    # the step ends where the next one starts
    end = min((i for n, i in starts.items() if n > number), default=None)
    found = result_lines(lines[:end], start)
    count = 0
    for t in summary.get('tests', []):
        i = found.get((t.get('test'), t.get('config')))
        if t.get('status') == 'fail' and i is not None:
            t['log'] = f'{url}#step:{number}:{i - start + 1}'
            count += 1
    return count
