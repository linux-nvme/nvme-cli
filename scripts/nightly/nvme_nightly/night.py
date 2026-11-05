# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""The record of a CI run: what the status page shows of it.

A record is a JSON object, one per run of a workflow:

    workflow    the name of the workflow ('Nightly tests')
    run_id      its run, run_url its web page
    event       what started it: 'schedule', 'workflow_dispatch', ...
    date        when it started, 'YYYY-MM-DD HH:MM:SS' UTC
    nvme_cli    the commit it tested
    conclusion  the conclusion of the run, as the CI has it
    jobs        its jobs, each with its conclusion and steps
    sections    the results of its tests, each the summary of one test
                run (blktests, meson, wringer) with its name and step
    outcome     'pass' or 'fail'
    problems    why it failed
    warnings    what failed without failing the run

The CI run and its jobs are those of the GitHub REST API, but nothing
else is: a run with no jobs and only sections is judged by its sections.

The outcome is that of the whole run, not only of its sections: a step
which failed without a failed section to explain it (a build, a VM which
did not boot, a missing report) fails the record too, so that no failure
is hidden behind green tests.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import meson

RECORD_VERSION = 2
# The conclusions of a job or a step which are failures.
FAILED = ('failure', 'timed_out', 'cancelled', 'startup_failure')
_NAME_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.-]*$')
_SLUG_RE = re.compile(r'[^A-Za-z0-9_.-]+')

# The logs blktests writes next to the result of a test run, which the
# page includes for a failed one: as .txt, which a web server shows
# instead of offering a download.
BLKTESTS_LOGS = ('out.bad', 'full', 'dmesg')
LOG_MAX = 1 << 20


def _date(value: Any) -> str:
    """'2026-11-05T01:27:51Z' as '2026-11-05 01:27:51'."""
    return str(value or '').replace('T', ' ').removesuffix('Z')


def run_record(
    run: dict[str, Any], jobs: list[dict[str, Any]]
) -> dict[str, Any]:
    """The record of a run of the REST API, without sections yet."""
    return {
        'version': RECORD_VERSION,
        'workflow': str(run.get('name') or ''),
        'run_id': str(run.get('id') or ''),
        'run_url': str(run.get('html_url') or ''),
        'event': str(run.get('event') or ''),
        'date': _date(run.get('run_started_at') or run.get('created_at')),
        'nvme_cli': str(run.get('head_sha') or ''),
        'conclusion': str(run.get('conclusion') or ''),
        'jobs': [
            {
                'name': str(j.get('name') or ''),
                'conclusion': str(j.get('conclusion') or ''),
                'url': str(j.get('html_url') or ''),
                'steps': [
                    {
                        'number': int(s.get('number', 0)),
                        'name': str(s.get('name') or ''),
                        'conclusion': str(s.get('conclusion') or ''),
                    }
                    for s in j.get('steps') or []
                ],
            }
            for j in jobs
        ],
        'sections': [],
    }


def find_step(
    record: dict[str, Any], job: str, step: str
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """The job and the step of a record, None for those not found."""
    j = next((x for x in record.get('jobs', []) if x['name'] == job), None)
    if j is None:
        return None, None
    s = next((x for x in j['steps'] if x['name'] == step), None)
    return j, s


def add_section(
    record: dict[str, Any],
    name: str,
    where: str,
    summary: dict[str, Any],
) -> dict[str, Any]:
    """Add the summary of a test run as section name, run by the step
    where, 'JOB/STEP'. Returns the section."""
    job, _, step = where.partition('/')
    section = dict(summary, name=name, job=job, step=step)
    j, s = find_step(record, job, step)
    if j is not None and s is not None and j['url'].startswith('https://'):
        section['url'] = f'{j["url"]}#step:{s["number"]}:1'
    record['sections'].append(section)
    return section


def judge(record: dict[str, Any]) -> dict[str, Any]:
    """Set the outcome, the problems and the warnings of a record."""
    problems: list[str] = []
    warnings: list[str] = []
    explained = set()
    for sec in record.get('sections', []):
        if sec.get('outcome') != 'pass':
            why = '; '.join(sec.get('problems', [])) or 'failed'
            problems.append(f'{sec["name"]}: {why}')
            explained.add((sec.get('job'), sec.get('step')))
    run_failed = record.get('conclusion') not in ('', 'success')
    for j in record.get('jobs', []):
        if j['conclusion'] not in FAILED:
            continue
        failed = [s for s in j['steps'] if s['conclusion'] in FAILED]
        # A failed job of a run which did not fail: continue-on-error.
        out = problems if run_failed else warnings
        if not failed:
            out.append(f'{j["name"]}: {j["conclusion"]}')
        for s in failed:
            if (j['name'], s['name']) not in explained:
                out.append(f'{j["name"]}: {s["name"]}: {s["conclusion"]}')
    if run_failed and not problems:
        problems.append(f'the run: {record["conclusion"]}')
    if not problems and not record.get('sections') and not record.get('jobs'):
        problems.append('no results')
    for sec in record.get('sections', []):
        if sec.get('kernel') and not record.get('kernel'):
            record['kernel'] = sec['kernel']
    record['outcome'] = 'fail' if problems else 'pass'
    record['problems'] = problems
    record['warnings'] = warnings
    return record


def migrate(entry: dict[str, Any]) -> dict[str, Any]:
    """A history entry as a record: the entries before the records were
    the blktests summaries of the nightly tests."""
    if entry.get('version') == RECORD_VERSION or 'sections' in entry:
        return entry
    section = dict(entry, name='blktests', kind='blktests')
    for key in ('run_id', 'run_url', 'date', 'nvme_cli', 'kernel'):
        section.pop(key, None)
    record = {
        'version': RECORD_VERSION,
        'workflow': 'Nightly tests',
        'run_id': str(entry.get('run_id') or ''),
        'run_url': str(entry.get('run_url') or ''),
        'event': '',
        'date': str(entry.get('date') or ''),
        'nvme_cli': str(entry.get('nvme_cli') or ''),
        'conclusion': '',
        'jobs': [],
        'sections': [section],
    }
    if entry.get('kernel'):
        record['kernel'] = entry['kernel']
    return judge(record)


def strip_files(record: dict[str, Any]) -> dict[str, Any]:
    """The record without its log files, which only the page of its own
    build has: for the history."""
    out = dict(record)
    out['sections'] = []
    for sec in record.get('sections', []):
        sec = {k: v for k, v in sec.items() if k != 'files'}
        sec['tests'] = [
            {k: v for k, v in t.items() if k != 'files'}
            for t in sec.get('tests', [])
        ]
        out['sections'].append(sec)
    return out


def slug(name: str) -> str:
    """A name as a plain file name."""
    return _SLUG_RE.sub('-', name).strip('-.') or 'x'


def _write(out: Path, rel: str, data: bytes) -> dict[str, str]:
    path = out / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if len(data) > LOG_MAX:
        data = data[:LOG_MAX] + b'\n[truncated]\n'
    path.write_bytes(data)
    return {'href': 'logs/' + rel}


def copy_blktests_logs(
    section: dict[str, Any], results: Path, out: Path
) -> None:
    """Copy the logs of the failed test runs of a blktests section from
    its results directory into the logs directory out. The names in the
    summary are not trusted: no paths but plain names."""
    base = slug(section['name'])
    for t in section.get('tests', []):
        if t.get('status') != 'fail':
            continue
        test, config = str(t.get('test', '')), str(t.get('config', ''))
        group, _, num = test.partition('/')
        if not all(_NAME_RE.match(x) for x in (group, num, config)):
            continue
        files = []
        for suffix in BLKTESTS_LOGS:
            src = results / config / group / f'{num}.{suffix}'
            if src.is_symlink() or not src.is_file():
                continue
            with src.open('rb') as f:
                data = f.read(LOG_MAX + 1)
            rel = f'{base}/{config}/{group}/{num}.{suffix}.txt'
            files.append(dict(_write(out, rel, data), name=suffix))
        if files:
            t['files'] = files


def write_meson_logs(
    section: dict[str, Any], tests: list[dict[str, Any]], out: Path
) -> None:
    """Write the output of the failed tests of a meson section, from the
    records of its testlog.json, into the logs directory out."""
    by_id = {str(t.get('name')): t for t in tests}
    base = slug(section['name'])
    used: set[str] = set()
    for t in section.get('tests', []):
        if t.get('status') not in meson.FAILED or t.get('id') not in by_id:
            continue
        name = slug(t['test'])
        n = 1
        while name in used:
            n += 1
            name = f'{slug(t["test"])}-{n}'
        used.add(name)
        data = meson.output(by_id[t['id']]).encode('utf-8', 'replace')
        t['files'] = [
            dict(_write(out, f'{base}/{name}.txt', data), name='output')
        ]


def copy_log(section: dict[str, Any], log: Path, out: Path) -> None:
    """Copy the log of a section into the logs directory out."""
    if log.is_symlink() or not log.is_file():
        return
    with log.open('rb') as f:
        data = f.read(LOG_MAX + 1)
    rel = f'{slug(section["name"])}/{slug(log.name)}.txt'
    section['files'] = [dict(_write(out, rel, data), name='log')]
