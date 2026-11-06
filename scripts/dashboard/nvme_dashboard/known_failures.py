# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""The list of known blktests failures.

Each known failure is tracked in an issue. The issue body names the
tests, one per line:

    blktests-ignore: nvme/004:tr=rdma
    blktests-exclude: nvme/039

'ignore' runs the test but its failure does not fail the nightly run,
'exclude' does not run it at all (for tests which crash or hang the
machine). Once the issue is closed, the test counts again.

The list itself is a plain text file, one entry per line:

    ignore nvme/004:tr=rdma https://example.org/issues/1

so that it can come from any issue tracker, or be written by hand. Only
the GitHub backend exists so far.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

ACTIONS = ('ignore', 'exclude')

# A group, a test, or a test with conditions: nvme, nvme/004,
# nvme/004:tr=rdma,bd=file. Strict, as the names end up in a shell
# script, and the issue bodies are written by anyone.
_WORD = r'[A-Za-z0-9_.=-]+'
TEST_RE = re.compile(
    rf'^[a-z0-9_-]+(?:/[0-9]{{3}}(?::{_WORD}(?:,{_WORD})*)?)?$'
)
# GitHub issue bodies end their lines with \r\n.
_BODY_RE = re.compile(r'^[ \t]*blktests-([a-z]+):[ \t]*(\S+)[ \t\r]*$', re.M)


@dataclass(frozen=True, order=True)
class Entry:
    """One known failure: what to do with which test, and why."""

    action: str
    test: str
    ref: str


def check_entry(action: str, test: str) -> str | None:
    """Return why an entry is not valid, None when it is."""
    if action not in ACTIONS:
        return f'unknown action {action!r}'
    if not TEST_RE.match(test):
        return f'invalid test name {test!r}'
    # blktests' EXCLUDE knows no conditions.
    if action == 'exclude' and ':' in test:
        return f'exclude takes no conditions: {test!r}'
    return None


def parse_body(body: str, ref: str) -> tuple[list[Entry], list[str]]:
    """Return the entries of an issue body and the warnings for it."""
    entries = []
    warnings = []
    for m in _BODY_RE.finditer(body or ''):
        action, test = m.group(1), m.group(2)
        why = check_entry(action, test)
        if why:
            warnings.append(f'{ref}: {why}')
        else:
            entries.append(Entry(action, test, ref))
    return entries, warnings


def parse_list(text: str) -> tuple[list[Entry], list[str]]:
    """Parse the list file. Return its entries and the warnings."""
    entries = []
    warnings = []
    for nr, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        fields = line.split(None, 2)
        if len(fields) < 2:
            warnings.append(f'line {nr}: too few fields')
            continue
        ref = fields[2] if len(fields) > 2 else ''
        why = check_entry(fields[0], fields[1])
        if why:
            warnings.append(f'line {nr}: {why}')
        else:
            entries.append(Entry(fields[0], fields[1], ref))
    return entries, warnings


def format_list(entries: Iterable[Entry]) -> str:
    """Return the list file of the entries."""
    lines = ['# action test reference']
    lines += [f'{e.action} {e.test} {e.ref}' for e in sorted(entries)]
    return '\n'.join(lines) + '\n'


def blktests_config(entries: Iterable[Entry]) -> str:
    """Return the lines to append to a blktests config file.

    They add to whatever the config set before.
    """
    entries = sorted(entries)
    lines = []
    for action, var in (('ignore', 'IGNORE_FAILURE'), ('exclude', 'EXCLUDE')):
        tests = sorted({e.test for e in entries if e.action == action})
        # The entries passed check_entry(): no quoting needed.
        lines.append('{}+=({})'.format(var, ' '.join(tests)))
    return '\n'.join(lines) + '\n'


Fetch = Callable[[str], Any]


def _fetch_json(url: str, token: str | None) -> Any:
    req = urllib.request.Request(url)
    req.add_header('Accept', 'application/vnd.github+json')
    if token:
        req.add_header('Authorization', 'Bearer ' + token)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def from_github(
    repo: str,
    label: str,
    token: str | None = None,
    fetch: Fetch | None = None,
    api: str = 'https://api.github.com',
) -> tuple[list[Entry], list[str]]:
    """Return the entries of the open issues of repo with the label.

    Only maintainers can label issues, so the label is what makes an
    issue count, not its author.
    """

    def get(url: str) -> Any:
        return _fetch_json(url, token)

    fetch = fetch or get
    entries: list[Entry] = []
    warnings: list[str] = []
    page = 1
    while True:
        url = (
            f'{api}/repos/{repo}/issues?state=open'
            f'&labels={urllib.parse.quote(label)}&per_page=100&page={page}'
        )
        issues = fetch(url)
        for issue in issues:
            if 'pull_request' in issue:
                continue
            e, w = parse_body(issue.get('body') or '', issue['html_url'])
            if not e and not w:
                w = [f'{issue["html_url"]}: no blktests-ignore/exclude line']
            entries += e
            warnings += w
        if len(issues) < 100:
            return entries, warnings
        page += 1
