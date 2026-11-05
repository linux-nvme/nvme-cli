# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""The static status page of the nightly runs.

A plain directory of files, to be uploaded to any web server:

    index.html      the state of the last runs
    style.css       its style
    history.json    the records of the last runs (see night.py), the
                    input of the next build, newest first
    logs/           the logs of the failed tests of the new records,
                    when given
    analyzer/       the clang analyzer report, when given

The page keeps no state of its own: each build takes the history.json
of the previous one (from wherever it is published), adds the new
records and writes everything again.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from . import night

KEEP_RUNS = 60
MATRIX_NIGHTS = 30
PRIMARY = 'Nightly tests'
TEMPLATES = Path(__file__).resolve().parent / 'templates'

# The status of a test run in a cell: CSS class, glyph, label.
CELLS = {
    'pass': {'cls': 'good', 'glyph': '\u2713', 'label': 'passed'},
    'fail': {'cls': 'critical', 'glyph': '\u2717', 'label': 'failed'},
    'timeout': {'cls': 'critical', 'glyph': 'T', 'label': 'timed out'},
    'ignored': {
        'cls': 'warning',
        'glyph': '!',
        'label': 'failed, known failure',
    },
    'expected fail': {
        'cls': 'good',
        'glyph': '\u2713',
        'label': 'failed as expected',
    },
    'skip': {'cls': 'none', 'glyph': '\u2013', 'label': 'skipped'},
    'not run': {'cls': 'none', 'glyph': '\u2013', 'label': 'not run'},
    'none': {'cls': 'none', 'glyph': '', 'label': 'no result'},
}
# The counts of a section, in the order the page shows them; those not
# in the first two only when there are any.
COUNTS = (
    ('pass', 'passed'),
    ('fail', 'failed'),
    ('timeout', 'timed out'),
    ('ignored', 'known failures failed'),
    ('known_passed', 'known failures passed'),
    ('expected fail', 'failed as expected'),
    ('skip', 'skipped'),
    ('not run', 'not run'),
    ('other', 'other'),
)
# The status of the test runs which failed.
FAILED = ('fail', 'timeout')
# The kinds of section which list every test run, not only the failed
# ones: a test run missing from them did not run.
COMPLETE = ('blktests',)
EVENTS = {'schedule': '', 'workflow_dispatch': 'manual'}


def merge_history(
    history: list[dict[str, Any]],
    records: list[dict[str, Any]],
    keep: int = KEEP_RUNS,
) -> list[dict[str, Any]]:
    """Return the history with the records added, newest first, keep of
    each workflow.

    A record replaces an older one of the same run (the page is built
    after every workflow, so once per workflow and night).
    """
    new = {(r.get('workflow'), r.get('run_id')) for r in records}
    runs = [
        r
        for r in map(night.migrate, history)
        if (r.get('workflow'), r.get('run_id')) not in new
    ]
    runs += records
    runs.sort(key=lambda r: str(r.get('date', '')), reverse=True)
    kept: dict[str, int] = {}
    out = []
    for r in runs:
        w = str(r.get('workflow', ''))
        kept[w] = kept.get(w, 0) + 1
        if kept[w] <= keep:
            out.append(r)
    return out


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


def event_label(record: dict[str, Any]) -> str:
    """What started a run, '' for the schedule."""
    event = str(record.get('event', ''))
    return EVENTS.get(event, event)


def counts_text(counts: dict[str, int]) -> str:
    """The counts of a section as one line."""
    return ', '.join(
        f'{counts.get(key, 0)} {label}'
        for key, label in COUNTS
        if counts.get(key) or key in ('pass', 'fail')
    )


def _day(record: dict[str, Any]) -> str:
    return str(record.get('date', '?'))[:10]


def _ok(item: dict[str, Any]) -> bool:
    return item.get('outcome') == 'pass'


def section_model(sec: dict[str, Any]) -> dict[str, Any]:
    """A section as a card of the overview."""
    return {
        'name': sec.get('name', ''),
        'ok': _ok(sec),
        'counts': counts_text(sec.get('counts', {})),
        'url': sec.get('url', ''),
        'problems': sec.get('problems', []),
        'files': sec.get('files', []),
    }


def known_model(sec: dict[str, Any]) -> list[dict[str, Any]]:
    """The known failures of a blktests section, with what became of
    them."""
    passed: dict[str, int] = {}
    for t in sec.get('tests', []):
        if t.get('known') and t['status'] == 'pass':
            passed[t['known']] = passed.get(t['known'], 0) + 1
    known = []
    for k in sec.get('known_failures', []):
        if k['action'] == 'exclude':
            note = 'excluded, not run'
        elif not k['matched']:
            note = 'matched no test run'
        elif passed.get(k['ref']):
            note = f'passed {passed[k["ref"]]} of {k["matched"]} runs'
        else:
            note = 'failed'
        known.append(dict(k, note=note, section=sec.get('name', '')))
    return known


def latest_model(record: dict[str, Any]) -> dict[str, Any]:
    """What the page shows of the last run of a workflow."""
    sections = record.get('sections', [])
    failed = []
    for i, sec in enumerate(sections):
        for t in sec.get('tests', []):
            if t['status'] not in FAILED:
                continue
            failed.append(
                {
                    'order': (bool(t.get('known')), i, t['test']),
                    'section': sec.get('name', ''),
                    'test': t['test'],
                    'config': t.get('config', ''),
                    'status': cell_status(t),
                    'reason': t.get('reason', ''),
                    'duration': t.get('duration', ''),
                    'known': t.get('known', ''),
                    'log': t.get('log', ''),
                    'files': t.get('files', []),
                }
            )
    failed.sort(key=lambda t: t.pop('order'))
    meta = [
        ('date', record.get('date', '')),
        ('started', event_label(record)),
        ('kernel', record.get('kernel', '')),
        ('nvme-cli', record.get('nvme_cli', '')),
    ]
    meta += [
        (sec['name'], sec['blktests'])
        for sec in sections
        if sec.get('kind') == 'blktests' and sec.get('blktests')
    ]
    return {
        'workflow': record.get('workflow', ''),
        'ok': _ok(record),
        'problems': record.get('problems', []),
        'warnings': record.get('warnings', []),
        'meta': [(k, v) for k, v in meta if v],
        'run_url': record.get('run_url', ''),
        'sections': [section_model(s) for s in sections],
        'failed': failed,
        'known': [
            k
            for sec in sections
            if sec.get('kind') == 'blktests'
            for k in known_model(sec)
        ],
    }


def overview_model(
    history: list[dict[str, Any]], primary: str = PRIMARY
) -> list[dict[str, Any]]:
    """The last run of each workflow, the primary one first."""
    latest: dict[str, dict[str, Any]] = {}
    for r in history:
        latest.setdefault(str(r.get('workflow', '')), r)
    names = sorted(latest, key=lambda w: (w != primary, w))
    return [latest_model(latest[w]) for w in names]


def _cell(status: str, title: str, url: str) -> dict[str, str]:
    return {'status': status, 'title': title, 'run_url': url}


def matrix_model(
    history: list[dict[str, Any]], primary: str = PRIMARY
) -> dict[str, Any]:
    """The last runs of the primary workflow, oldest first: their
    outcome, that of each section, of the other workflows the same day,
    and the tests which failed in one of them."""
    runs = [r for r in history if r.get('workflow') == primary]
    nights = list(reversed(runs[:MATRIX_NIGHTS]))
    others: dict[str, dict[str, dict[str, Any]]] = {}
    for r in history:
        w = str(r.get('workflow', ''))
        if w != primary:
            others.setdefault(w, {}).setdefault(_day(r), r)

    names: list[str] = []
    lookup = []
    keys: set[tuple[str, str, str]] = set()
    for r in nights:
        secs = {s['name']: s for s in r.get('sections', [])}
        lookup.append(secs)
        for name, sec in secs.items():
            if name not in names:
                names.append(name)
            keys |= {
                (name, t['test'], t.get('config', ''))
                for t in sec.get('tests', [])
                if t['status'] in FAILED
            }

    def outcome(item: dict[str, Any] | None) -> str:
        if item is None:
            return 'none'
        return 'pass' if _ok(item) else 'fail'

    def test_cell(
        r: dict[str, Any], secs: dict[str, Any], key: tuple[str, str, str]
    ) -> dict[str, str]:
        name, test, config = key
        title = f'{_day(r)} {name} {test} {config}'.rstrip()
        sec = secs.get(name)
        if sec is None:
            return _cell('none', title, r.get('run_url', ''))
        t = next(
            (
                t
                for t in sec.get('tests', [])
                if (t['test'], t.get('config', '')) == (test, config)
            ),
            None,
        )
        if t is None:
            status = 'none' if sec.get('kind') in COMPLETE else 'pass'
        else:
            status = cell_status(t)
        url = (t or {}).get('log') or sec.get('url') or r.get('run_url', '')
        return _cell(status, title, url)

    rows = [
        {
            'label': f'{name}',
            'cells': [
                _cell(
                    outcome(secs.get(name)),
                    f'{_day(r)} {name}',
                    secs.get(name, {}).get('url') or r.get('run_url', ''),
                )
                for r, secs in zip(nights, lookup, strict=True)
            ],
        }
        for name in names
    ]
    rows += [
        {
            'label': w,
            'cells': [
                _cell(
                    outcome(days.get(_day(r))),
                    f'{_day(r)} {w}',
                    days.get(_day(r), {}).get('run_url', ''),
                )
                for r in nights
            ],
        }
        for w, days in sorted(others.items())
    ]
    return {
        'workflow': primary,
        'nights': [
            {
                'label': _day(r),
                'event': event_label(r),
                'run_url': r.get('run_url', ''),
                'status': outcome(r),
            }
            for r in nights
        ],
        'rows': rows,
        'tests': [
            {
                'section': key[0],
                'test': key[1],
                'config': key[2],
                'cells': [
                    test_cell(r, secs, key)
                    for r, secs in zip(nights, lookup, strict=True)
                ],
            }
            for key in sorted(keys, key=lambda k: (names.index(k[0]), k))
        ],
    }


def page_model(
    history: list[dict[str, Any]],
    title: str = 'nvme-cli nightly status',
    links: list[tuple[str, str]] | None = None,
    primary: str = PRIMARY,
) -> dict[str, Any]:
    """Everything index.html shows, as plain data."""
    history = [night.migrate(r) for r in history]
    overview = overview_model(history, primary)
    return {
        'title': title,
        'links': [{'text': t, 'href': h} for t, h in links or []],
        'cells': CELLS,
        'ok': all(w['ok'] for w in overview),
        'overview': overview,
        'matrix': matrix_model(history, primary),
    }


def render(
    history: list[dict[str, Any]],
    title: str = 'nvme-cli nightly status',
    links: list[tuple[str, str]] | None = None,
    primary: str = PRIMARY,
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
    return str(page.render(page_model(history, title, links, primary)))


def build(
    out: Path,
    history: list[dict[str, Any]],
    analyzer: Path | None = None,
    links: list[tuple[str, str]] | None = None,
    logs: Path | None = None,
    primary: str = PRIMARY,
) -> None:
    """Write the site into the directory out. logs is the directory of
    the log files of the new records (see night.py)."""
    out.mkdir(parents=True, exist_ok=True)
    if logs is not None and logs.is_dir():
        shutil.copytree(logs, out / 'logs', dirs_exist_ok=True)
    links = list(links or [])
    if analyzer is not None:
        shutil.copytree(analyzer, out / 'analyzer', dirs_exist_ok=True)
        links.insert(0, ('clang analyzer report', 'analyzer/'))
    links.append(('history.json', 'history.json'))
    shutil.copyfile(TEMPLATES / 'style.css', out / 'style.css')
    stored = [night.strip_files(r) for r in history]
    (out / 'history.json').write_text(
        json.dumps(stored, indent=1) + '\n', encoding='utf-8'
    )
    (out / 'index.html').write_text(
        render(history, links=links, primary=primary), encoding='utf-8'
    )
