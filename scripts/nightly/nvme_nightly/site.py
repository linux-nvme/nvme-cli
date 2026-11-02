# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""The static status page of the nightly runs.

A plain directory of files, to be uploaded to any web server:

    index.html      the state of the last nights
    style.css       its style
    history.json    the blktests summaries of the last nights, the input
                    of the next build, newest first
    analyzer/       the clang analyzer report, when given

The page keeps no state of its own: each build takes the history.json
of the previous one (from wherever it is published), adds the new
summary and writes everything again.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

KEEP_NIGHTS = 60
MATRIX_NIGHTS = 30
TEMPLATES = Path(__file__).resolve().parent / 'templates'

# The status of a test run in a cell: CSS class, glyph, label.
CELLS = {
    'pass': {'cls': 'good', 'glyph': '\u2713', 'label': 'passed'},
    'fail': {'cls': 'critical', 'glyph': '\u2717', 'label': 'failed'},
    'ignored': {
        'cls': 'warning',
        'glyph': '!',
        'label': 'failed, known failure',
    },
    'not run': {'cls': 'none', 'glyph': '\u2013', 'label': 'not run'},
    'none': {'cls': 'none', 'glyph': '', 'label': 'no result'},
}


def merge_history(
    history: list[dict[str, Any]],
    summary: dict[str, Any] | None,
    keep: int = KEEP_NIGHTS,
) -> list[dict[str, Any]]:
    """Return the history with the summary added, newest first.

    A summary replaces an older one of the same run (the page may be
    built more than once per night).
    """
    runs = list(history)
    if summary is not None:
        key = summary.get('run_id')
        runs = [s for s in runs if key is None or s.get('run_id') != key]
        runs.append(summary)
    runs.sort(key=lambda s: str(s.get('date', '')), reverse=True)
    return runs[:keep]


def weburl(ref: Any) -> str:
    """The reference if it is a web URL, else ''. The results are not
    trusted: no javascript: links."""
    text = str(ref or '')
    return text if text.startswith(('https://', 'http://')) else ''


def short_ref(ref: Any) -> str:
    """An issue URL as #NUMBER, anything else as it is."""
    text = str(ref or '')
    tail = text.rstrip('/').rsplit('/', 1)[-1]
    return '#' + tail if weburl(text) and tail.isdigit() else text


def cell_status(item: dict[str, Any] | None) -> str:
    """The cell of a test run of a summary."""
    if item is None:
        return 'none'
    if item['status'] == 'fail' and item.get('known'):
        return 'ignored'
    return item['status'] if item['status'] in CELLS else 'not run'


def _night_label(s: dict[str, Any]) -> str:
    return str(s.get('date', '?'))[:10]


def latest_model(s: dict[str, Any]) -> dict[str, Any]:
    """What the page shows of the last night."""
    counts = s.get('counts', {})
    failed = [t for t in s.get('tests', []) if t['status'] == 'fail']
    failed.sort(key=lambda t: (bool(t.get('known')), t['test'], t['config']))
    passed: dict[str, int] = {}
    for t in s.get('tests', []):
        if t.get('known') and t['status'] == 'pass':
            passed[t['known']] = passed.get(t['known'], 0) + 1
    known = []
    for k in s.get('known_failures', []):
        if k['action'] == 'exclude':
            note = 'excluded, not run'
        elif not k['matched']:
            note = 'matched no test run'
        elif passed.get(k['ref']):
            note = f'passed {passed[k["ref"]]} of {k["matched"]} runs'
        else:
            note = 'failed'
        known.append(dict(k, note=note))
    return {
        'ok': s.get('outcome') == 'pass',
        'problems': s.get('problems', []),
        'meta': [
            (key, s[key])
            for key in ('date', 'kernel', 'nvme_cli', 'blktests')
            if s.get(key)
        ],
        'run_url': s.get('run_url', ''),
        'tiles': [
            {'label': label, 'count': counts.get(key, 0)}
            for key, label in (
                ('pass', 'passed'),
                ('fail', 'failed'),
                ('ignored', 'known failures, failed'),
                ('known_passed', 'known failures, passed'),
                ('not run', 'not run'),
            )
        ],
        'failed': [
            {
                'test': t['test'],
                'config': t['config'],
                'status': cell_status(t),
                'reason': t.get('reason', ''),
                'known': t.get('known', ''),
            }
            for t in failed
        ],
        'known': known,
    }


def matrix_model(history: list[dict[str, Any]]) -> dict[str, Any]:
    """The test runs which failed in one of the last nights, by night,
    oldest first."""
    nights = list(reversed(history[:MATRIX_NIGHTS]))
    lookup = []
    keys: set[tuple[str, str]] = set()
    for s in nights:
        runs = {(t['test'], t['config']): t for t in s.get('tests', [])}
        lookup.append(runs)
        keys |= {k for k, t in runs.items() if t['status'] == 'fail'}
    return {
        'nights': [
            {
                'label': _night_label(s),
                'run_url': s.get('run_url', ''),
                'status': 'pass' if s.get('outcome') == 'pass' else 'fail',
            }
            for s in nights
        ],
        'rows': [
            {
                'test': test,
                'config': config,
                'cells': [
                    {
                        'status': cell_status(runs.get((test, config))),
                        'title': f'{_night_label(s)} {test} {config}',
                        'run_url': s.get('run_url', ''),
                    }
                    for s, runs in zip(nights, lookup, strict=True)
                ],
            }
            for test, config in sorted(keys)
        ],
    }


def page_model(
    history: list[dict[str, Any]],
    title: str = 'nvme-cli nightly status',
    links: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Everything index.html shows, as plain data."""
    return {
        'title': title,
        'links': [{'text': t, 'href': h} for t, h in links or []],
        'cells': CELLS,
        'latest': latest_model(history[0]) if history else None,
        'matrix': matrix_model(history),
    }


def render(
    history: list[dict[str, Any]],
    title: str = 'nvme-cli nightly status',
    links: list[tuple[str, str]] | None = None,
) -> str:
    """Return the index.html for the history (newest first)."""
    # Only the page needs jinja2, not the steps which run in the test VM.
    import jinja2

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(TEMPLATES),
        autoescape=True,
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters['weburl'] = weburl
    env.filters['short_ref'] = short_ref
    page = env.get_template('index.html.j2')
    return str(page.render(page_model(history, title, links)))


def build(
    out: Path,
    history: list[dict[str, Any]],
    analyzer: Path | None = None,
    links: list[tuple[str, str]] | None = None,
) -> None:
    """Write the site into the directory out."""
    out.mkdir(parents=True, exist_ok=True)
    links = list(links or [])
    if analyzer is not None:
        shutil.copytree(analyzer, out / 'analyzer', dirs_exist_ok=True)
        links.insert(0, ('clang analyzer report', 'analyzer/'))
    links.append(('history.json', 'history.json'))
    shutil.copyfile(TEMPLATES / 'style.css', out / 'style.css')
    (out / 'history.json').write_text(
        json.dumps(history, indent=1) + '\n', encoding='utf-8'
    )
    (out / 'index.html').write_text(
        render(history, links=links), encoding='utf-8'
    )
