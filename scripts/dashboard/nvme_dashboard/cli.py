# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""The command line of nvme-dashboard."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from . import blktests, joblog, known_failures, meson, night, site, wringer


def _warn(lines: list[str]) -> None:
    for line in lines:
        print(f'warning: {line}', file=sys.stderr)


def _read_known(path: Path | None) -> list[known_failures.Entry]:
    if path is None:
        return []
    entries, warnings = known_failures.parse_list(
        path.read_text(encoding='utf-8')
    )
    _warn(warnings)
    return entries


def cmd_known_failures(args: argparse.Namespace) -> int:
    entries: list[known_failures.Entry] = []
    warnings: list[str] = []
    if args.github:
        e, w = known_failures.from_github(
            args.github, args.label, os.environ.get('GITHUB_TOKEN')
        )
        entries += e
        warnings += w
    for path in args.file:
        e, w = known_failures.parse_list(path.read_text(encoding='utf-8'))
        entries += e
        warnings += [f'{path}: {x}' for x in w]
    _warn(warnings)
    entries = sorted(set(entries))
    text = known_failures.format_list(entries)
    if args.output:
        args.output.write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)
    if args.config:
        args.config.write_text(
            known_failures.blktests_config(entries), encoding='utf-8'
        )
    return 0


def _meta(pairs: list[str]) -> dict[str, str]:
    meta = {}
    for pair in pairs:
        key, sep, value = pair.partition('=')
        if not sep or not key:
            raise SystemExit(f'--meta wants KEY=VALUE, not {pair!r}')
        meta[key] = value
    return meta


def cmd_blktests_summary(args: argparse.Namespace) -> int:
    results = blktests.read_results(args.results)
    summary = blktests.summarize(
        results, _read_known(args.known_failures), args.check_status
    )
    summary = {**_meta(args.meta), **summary}
    text = json.dumps(summary, indent=1) + '\n'
    if args.output:
        args.output.write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)
    c = summary['counts']
    print(
        f'blktests: {summary["outcome"]}: {c["pass"]} passed, '
        f'{c["fail"]} failed, {c["ignored"]} known failures failed, '
        f'{c["known_passed"]} known failures passed, '
        f'{c["not run"]} not run',
        file=sys.stderr,
    )
    for problem in summary['problems']:
        print(f'blktests: {problem}', file=sys.stderr)
    return 0 if summary['outcome'] == 'pass' else 1


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding='utf-8'))


def _jobs(path: Path | None) -> list[dict[str, Any]]:
    """The jobs of a run: the answer of the REST API, or a plain list."""
    if path is None:
        return []
    data = _read_json(path)
    return list(data['jobs'] if isinstance(data, dict) else data)


def _section(
    kind: str, name: str, path: Path, logs: Path | None
) -> dict[str, Any]:
    """The summary of a section and, for the page, its log files."""
    section: dict[str, Any] = {'name': name}
    if kind == 'blktests':
        section.update(_read_json(path), kind='blktests')
        if logs is not None:
            night.copy_blktests_logs(section, path.parent, logs)
    elif kind == 'meson':
        tests = meson.read_testlog(path)
        section.update(meson.summarize(tests))
        if logs is not None:
            night.write_meson_logs(section, tests, logs)
    else:
        text = path.read_text(encoding='utf-8', errors='replace')
        section.update(wringer.summarize(text))
        if logs is not None:
            night.copy_log(section, path, logs)
    return section


def cmd_night(args: argparse.Namespace) -> int:
    run = _read_json(args.run) if args.run else {}
    jobs = _jobs(args.jobs)
    record = night.run_record(run, jobs)
    record.update(_meta(args.meta))
    job_logs = {}
    for pair in args.job_log:
        job, sep, path = pair.partition('=')
        if not sep:
            raise SystemExit(f'--job-log wants JOB=PATH, not {pair!r}')
        job_logs[job] = Path(path)
    for kind, name, where, path in args.section:
        src = Path(path)
        if not path or not src.is_file():
            _warn([f'{name}: no {path or "file"}, no section'])
            continue
        summary = _section(kind, name, src, args.logs)
        section = night.add_section(record, name, where, summary)
        job = next((j for j in jobs if j.get('name') == section['job']), None)
        log = job_logs.get(section['job'])
        if job is not None and log is not None and log.is_file():
            joblog.add_links(
                section,
                job,
                log.read_text(encoding='utf-8', errors='replace'),
                section['step'],
            )
    night.judge(record)
    text = json.dumps(record, indent=1) + '\n'
    if args.output:
        args.output.write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)
    print(
        f'{record["workflow"] or "run"}: {record["outcome"]}', file=sys.stderr
    )
    for problem in record['problems']:
        print(f'  {problem}', file=sys.stderr)
    return 0


def _load_history(src: str | None) -> list[dict[str, Any]]:
    """The history.json of the last build: a file or a URL.

    A missing one starts a new history. Any other error stops the build,
    so that a short outage does not drop the history of the page.
    """
    if not src:
        return []
    if '://' in src:
        try:
            with urllib.request.urlopen(src, timeout=60) as resp:
                data = json.load(resp)
        except urllib.error.HTTPError as err:
            if err.code != 404:
                raise
            print(f'warning: {src}: not found, new history', file=sys.stderr)
            return []
    else:
        path = Path(src)
        if not path.exists():
            return []
        data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, list):
        raise SystemExit(f'{src}: not a list of records')
    return data


def cmd_site(args: argparse.Namespace) -> int:
    records = [_read_json(path) for path in args.record]
    history = site.merge_history(_load_history(args.history), records)
    links = []
    for pair in args.link:
        text, sep, href = pair.partition('=')
        if not sep:
            raise SystemExit(f'--link wants TEXT=URL, not {pair!r}')
        links.append((text, href))
    site.build(
        args.output, history, args.analyzer, links, args.logs, args.primary
    )
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='nvme-dashboard',
        description='The dashboard of the nvme-cli tests: the '
        'known blktests failures, the summaries and the record of a run, '
        'the status page.',
    )
    sub = p.add_subparsers(dest='command', required=True)

    k = sub.add_parser(
        'known-failures',
        help='collect the known failures from the issue tracker or files',
    )
    k.add_argument(
        '--github',
        metavar='OWNER/REPO',
        help='read the open issues of this GitHub repository',
    )
    k.add_argument(
        '--label',
        default='blktests-known-failure',
        help='the label of the issues (%(default)s)',
    )
    k.add_argument(
        '--file',
        type=Path,
        action='append',
        default=[],
        help='add the entries of a list file',
    )
    k.add_argument(
        '-o',
        '--output',
        type=Path,
        help='write the list here (default: stdout)',
    )
    k.add_argument(
        '--config',
        type=Path,
        help='write blktests config lines for the list here',
    )
    k.set_defaults(func=cmd_known_failures)

    b = sub.add_parser(
        'blktests-summary',
        help='summarize a blktests results directory; exit 1 when the '
        'run failed',
    )
    b.add_argument('results', type=Path, help='the blktests results dir')
    b.add_argument('--known-failures', type=Path, help='the list file')
    b.add_argument(
        '--check-status', type=int, help='the exit status of ./check'
    )
    b.add_argument(
        '--meta',
        action='append',
        default=[],
        metavar='KEY=VALUE',
        help='add an item to the summary (date, kernel, ...)',
    )
    b.add_argument(
        '-o',
        '--output',
        type=Path,
        help='write the summary here (default: stdout)',
    )
    b.set_defaults(func=cmd_blktests_summary)

    n = sub.add_parser(
        'night',
        help='write the record of a CI run: its jobs and the summaries of '
        'its tests',
    )
    n.add_argument(
        '--run', type=Path, help='the run, as JSON of the GitHub REST API'
    )
    n.add_argument(
        '--jobs',
        type=Path,
        help='its jobs, as JSON of the GitHub REST API',
    )
    n.add_argument(
        '--job-log',
        action='append',
        default=[],
        metavar='JOB=PATH',
        help='the log of a job, for the links to the lines of the failed '
        'tests',
    )
    n.add_argument(
        '--section',
        action='append',
        default=[],
        nargs=4,
        metavar=('KIND', 'NAME', 'JOB/STEP', 'PATH'),
        help='add the results of a test run: KIND blktests (PATH: its '
        'summary, in its results directory), meson (PATH: testlog.json) '
        'or wringer (PATH: its log), run by the step STEP of the job JOB; '
        'a missing PATH adds no section',
    )
    n.add_argument(
        '--logs',
        type=Path,
        help='copy the logs of the failed tests into this directory, for '
        'the page (site --logs)',
    )
    n.add_argument(
        '--meta',
        action='append',
        default=[],
        metavar='KEY=VALUE',
        help='set an item of the record (workflow, run_id, date, ...)',
    )
    n.add_argument(
        '-o',
        '--output',
        type=Path,
        help='write the record here (default: stdout)',
    )
    n.set_defaults(func=cmd_night)

    s = sub.add_parser('site', help='build the status page')
    s.add_argument(
        '-o',
        '--output',
        type=Path,
        required=True,
        help='the directory of the site',
    )
    s.add_argument(
        '--record',
        type=Path,
        action='append',
        default=[],
        help='add the record of a new run (see night)',
    )
    s.add_argument(
        '--history',
        metavar='FILE|URL',
        help='the history.json of the last build',
    )
    s.add_argument(
        '--logs',
        type=Path,
        help='the log directory of the new records (night --logs)',
    )
    s.add_argument(
        '--primary',
        default=site.PRIMARY,
        help='the workflow whose runs the history shows (%(default)s)',
    )
    s.add_argument(
        '--analyzer', type=Path, help='the clang analyzer report to include'
    )
    s.add_argument(
        '--link',
        action='append',
        default=[],
        metavar='TEXT=URL',
        help='add a link to the page',
    )
    s.set_defaults(func=cmd_site)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return int(args.func(args))
