# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""The command line of nvme-nightly."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from . import blktests, joblog, known_failures, site


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


def cmd_log_links(args: argparse.Namespace) -> int:
    summary = json.loads(args.summary.read_text(encoding='utf-8'))
    job = json.loads(args.job.read_text(encoding='utf-8'))
    log = args.log.read_text(encoding='utf-8', errors='replace')
    count = joblog.add_links(summary, job, log, args.step)
    failed = sum(t.get('status') == 'fail' for t in summary.get('tests', []))
    text = json.dumps(summary, indent=1) + '\n'
    if args.output:
        args.output.write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)
    print(
        f'log-links: {count} of {failed} failed test runs linked',
        file=sys.stderr,
    )
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
        raise SystemExit(f'{src}: not a list of summaries')
    return data


def cmd_site(args: argparse.Namespace) -> int:
    summary = None
    if args.summary:
        summary = json.loads(args.summary.read_text(encoding='utf-8'))
    history = site.merge_history(_load_history(args.history), summary)
    links = []
    for pair in args.link:
        text, sep, href = pair.partition('=')
        if not sep:
            raise SystemExit(f'--link wants TEXT=URL, not {pair!r}')
        links.append((text, href))
    # The logs of the results directory are those of the new summary.
    results = None
    if args.results and history and history[0] is summary:
        results = args.results
    site.build(args.output, history, args.analyzer, links, results)
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='nvme-nightly',
        description='The tooling of the nightly tests of nvme-cli: the '
        'known blktests failures, the summary of a run, the status page.',
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

    g = sub.add_parser(
        'log-links',
        help='add the links to the job log lines of the failed test runs '
        'to a blktests summary',
    )
    g.add_argument('summary', type=Path, help='the blktests summary')
    g.add_argument(
        '--job',
        type=Path,
        required=True,
        help='the job which ran blktests, as JSON of the GitHub REST API',
    )
    g.add_argument(
        '--log', type=Path, required=True, help='the log of the job'
    )
    g.add_argument(
        '--step',
        default='Run blktests in VM',
        help='the name of the step which ran blktests (%(default)s)',
    )
    g.add_argument(
        '-o',
        '--output',
        type=Path,
        help='write the summary here (default: stdout)',
    )
    g.set_defaults(func=cmd_log_links)

    s = sub.add_parser('site', help='build the status page')
    s.add_argument(
        '-o',
        '--output',
        type=Path,
        required=True,
        help='the directory of the site',
    )
    s.add_argument(
        '--summary', type=Path, help='the blktests summary of the new run'
    )
    s.add_argument(
        '--history',
        metavar='FILE|URL',
        help='the history.json of the last build',
    )
    s.add_argument(
        '--results',
        type=Path,
        help='the blktests results directory of the summary: the page '
        'includes the logs of its failed test runs',
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
