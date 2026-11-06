# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for the record of a CI run."""

import tempfile
import unittest
from pathlib import Path
from typing import Any

from nvme_dashboard import night

RUN_URL = 'https://github.com/o/r/actions/runs/7'
JOB_URL = RUN_URL + '/job/8'


def step(number: int, name: str, conclusion: str = 'success') -> Any:
    return {'number': number, 'name': name, 'conclusion': conclusion}


def job(name: str, conclusion: str, *steps: Any) -> dict[str, Any]:
    return {
        'name': name,
        'conclusion': conclusion,
        'html_url': JOB_URL,
        'steps': list(steps),
    }


def run(conclusion: str = 'success', **kw: Any) -> dict[str, Any]:
    return dict(
        {
            'id': 7,
            'name': 'Nightly tests',
            'html_url': RUN_URL,
            'event': 'schedule',
            'run_started_at': '2026-11-05T01:27:51Z',
            'head_sha': 'abc',
            'conclusion': conclusion,
        },
        **kw,
    )


def section(outcome: str = 'pass', **kw: Any) -> dict[str, Any]:
    return dict(
        {
            'kind': 'meson',
            'outcome': outcome,
            'problems': [] if outcome == 'pass' else ['1 test failed'],
            'counts': {},
            'tests': [],
        },
        **kw,
    )


class RunRecord(unittest.TestCase):
    def test_record(self) -> None:
        r = night.run_record(
            run(), [job('tests', 'success', step(1, 'Set up job'))]
        )
        self.assertEqual(
            {k: v for k, v in r.items() if k != 'jobs'},
            {
                'version': night.RECORD_VERSION,
                'workflow': 'Nightly tests',
                'run_id': '7',
                'run_url': RUN_URL,
                'event': 'schedule',
                'date': '2026-11-05 01:27:51',
                'nvme_cli': 'abc',
                'conclusion': 'success',
                'sections': [],
            },
        )
        self.assertEqual(
            r['jobs'],
            [
                {
                    'name': 'tests',
                    'conclusion': 'success',
                    'url': JOB_URL,
                    'steps': [step(1, 'Set up job')],
                }
            ],
        )

    def test_add_section(self) -> None:
        r = night.run_record(
            run(), [job('tests', 'success', step(3, 'Run blktests'))]
        )
        s = night.add_section(r, 'blktests', 'tests/Run blktests', section())
        self.assertEqual(
            (s['name'], s['job'], s['step'], s['url']),
            ('blktests', 'tests', 'Run blktests', JOB_URL + '#step:3:1'),
        )
        s = night.add_section(r, 'x', 'tests/no such step', section())
        self.assertNotIn('url', s)
        self.assertEqual(len(r['sections']), 2)


class Judge(unittest.TestCase):
    def judge(
        self,
        conclusion: str,
        jobs: list[dict[str, Any]],
        sections: list[tuple[str, str, dict[str, Any]]],
    ) -> dict[str, Any]:
        r = night.run_record(run(conclusion), jobs)
        for name, where, s in sections:
            night.add_section(r, name, where, s)
        return night.judge(r)

    def test_pass(self) -> None:
        r = self.judge(
            'success',
            [job('tests', 'success', step(3, 'blktests'))],
            [('blktests', 'tests/blktests', section(kernel='7.4'))],
        )
        self.assertEqual(
            (r['outcome'], r['problems'], r['warnings']), ('pass', [], [])
        )
        self.assertEqual(r['kernel'], '7.4')

    def test_failed_section(self) -> None:
        # the failed step is explained by its section
        r = self.judge(
            'failure',
            [
                job(
                    'tests',
                    'failure',
                    step(3, 'blktests'),
                    step(4, 'meson', 'failure'),
                )
            ],
            [
                ('blktests', 'tests/blktests', section()),
                ('nvme-cli tests', 'tests/meson', section('fail')),
            ],
        )
        self.assertEqual(r['outcome'], 'fail')
        self.assertEqual(r['problems'], ['nvme-cli tests: 1 test failed'])

    def test_unexplained_step(self) -> None:
        # the tests passed, but their step failed: a build, a report
        r = self.judge(
            'failure',
            [job('tests', 'failure', step(3, 'blktests', 'failure'))],
            [('blktests', 'tests/blktests', section())],
        )
        self.assertEqual(r['problems'], ['tests: blktests: failure'])
        # a failed step without a section at all
        r = self.judge(
            'failure',
            [job('build', 'failure', step(2, 'make', 'failure'))],
            [],
        )
        self.assertEqual(r['problems'], ['build: make: failure'])

    def test_job_without_failed_step(self) -> None:
        r = self.judge('cancelled', [job('tests', 'cancelled')], [])
        self.assertEqual(r['problems'], ['tests: cancelled'])
        r = self.judge('timed_out', [], [])
        self.assertEqual(r['problems'], ['the run: timed_out'])

    def test_continue_on_error(self) -> None:
        # a failed job which did not fail the run
        r = self.judge(
            'success',
            [job('upload', 'failure', step(3, 'codecov', 'failure'))],
            [],
        )
        self.assertEqual(r['outcome'], 'pass')
        self.assertEqual(r['warnings'], ['upload: codecov: failure'])

    def test_skipped(self) -> None:
        r = self.judge('success', [job('tests', 'skipped')], [])
        self.assertEqual((r['outcome'], r['problems']), ('pass', []))

    def test_no_results(self) -> None:
        r = night.judge(night.run_record({}, []))
        self.assertEqual(r['problems'], ['no results'])

    def test_sections_only(self) -> None:
        # a run outside of GitHub: only its sections count
        r = night.run_record({}, [])
        night.add_section(r, 'meson', 'local/tests', section('fail'))
        self.assertEqual(night.judge(r)['problems'], ['meson: 1 test failed'])


class Migrate(unittest.TestCase):
    def test_migrate(self) -> None:
        old = {
            'run_id': '5',
            'run_url': RUN_URL,
            'date': '2026-11-03 09:51:47',
            'kernel': '7.4',
            'nvme_cli': 'abc',
            'blktests': 'def',
            'outcome': 'fail',
            'problems': ['2 failed test runs'],
            'counts': {'pass': 1},
            'tests': [],
        }
        r = night.migrate(old)
        self.assertEqual(
            (r['workflow'], r['run_id'], r['date'], r['kernel']),
            ('Nightly tests', '5', '2026-11-03 09:51:47', '7.4'),
        )
        self.assertEqual(
            r['sections'],
            [
                {
                    'name': 'blktests',
                    'kind': 'blktests',
                    'blktests': 'def',
                    'outcome': 'fail',
                    'problems': ['2 failed test runs'],
                    'counts': {'pass': 1},
                    'tests': [],
                }
            ],
        )
        self.assertEqual(r['problems'], ['blktests: 2 failed test runs'])
        self.assertIs(night.migrate(r), r)

    def test_strip_files(self) -> None:
        r = night.run_record(run(), [])
        night.add_section(
            r,
            'x',
            'a/b',
            section(
                files=[{'href': 'logs/x'}],
                tests=[{'test': 't', 'files': [{'href': 'logs/y'}]}],
            ),
        )
        s = night.strip_files(r)
        self.assertNotIn('files', s['sections'][0])
        self.assertEqual(s['sections'][0]['tests'], [{'test': 't'}])
        # the record itself keeps them
        self.assertIn('files', r['sections'][0])


class Logs(unittest.TestCase):
    def test_blktests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            res, out = Path(tmp, 'results'), Path(tmp, 'logs')
            d = res / 'nodev_tr_tcp' / 'nvme'
            d.mkdir(parents=True)
            (d / '073.full').write_text('full log', encoding='utf-8')
            (d / '073.out.bad').write_text('bad', encoding='utf-8')
            (d / '074.full').write_bytes(b'x' * (night.LOG_MAX + 10))
            (d / '075.full').symlink_to('/etc/passwd')
            (res / 'secret').write_text('no', encoding='utf-8')
            tests = [
                {'test': f'nvme/{n}', 'config': 'nodev_tr_tcp', 'status': st}
                for n, st in (
                    ('073', 'fail'),
                    ('074', 'fail'),
                    ('075', 'fail'),
                    ('076', 'pass'),
                )
            ] + [
                {'test': '../secret', 'config': '..', 'status': 'fail'},
                {'test': 'nvme/001', 'config': '.hidden', 'status': 'fail'},
            ]
            s = {'name': 'blktests', 'tests': tests}
            night.copy_blktests_logs(s, res, out)
            base = 'logs/blktests/nodev_tr_tcp/nvme'
            self.assertEqual(
                [t.get('files') for t in tests],
                [
                    [
                        {'href': f'{base}/073.out.bad.txt', 'name': 'out.bad'},
                        {'href': f'{base}/073.full.txt', 'name': 'full'},
                    ],
                    [{'href': f'{base}/074.full.txt', 'name': 'full'}],
                    None,
                    None,
                    None,
                    None,
                ],
            )
            self.assertEqual(
                (out / 'blktests/nodev_tr_tcp/nvme/073.full.txt').read_text(
                    encoding='utf-8'
                ),
                'full log',
            )
            big = (
                out / 'blktests/nodev_tr_tcp/nvme/074.full.txt'
            ).read_bytes()
            self.assertTrue(big.endswith(b'\n[truncated]\n'))
            self.assertEqual(
                sorted(p.name for p in out.rglob('*') if p.is_file()),
                ['073.full.txt', '073.out.bad.txt', '074.full.txt'],
            )

    def test_meson(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            records = [
                {'name': 'p:mock / a/b', 'stdout': 'why'},
                {'name': 'p:mock / a b', 'stdout': 'other'},
                {'name': 'p:mock / skipped', 'stdout': 'x'},
            ]
            tests = [
                {'test': 'mock / a/b', 'id': 'p:mock / a/b', 'status': 'fail'},
                # the same file name
                {
                    'test': 'mock / a b',
                    'id': 'p:mock / a b',
                    'status': 'timeout',
                },
                {
                    'test': 'mock / skipped',
                    'id': 'p:mock / skipped',
                    'status': 'skip',
                },
                {'test': 'gone', 'id': 'gone', 'status': 'fail'},
            ]
            s = {'name': 'nvme-cli tests', 'tests': tests}
            night.write_meson_logs(s, records, out)
            self.assertEqual(
                [t.get('files') for t in tests],
                [
                    [
                        {
                            'href': 'logs/nvme-cli-tests/mock-a-b.txt',
                            'name': 'output',
                        }
                    ],
                    [
                        {
                            'href': 'logs/nvme-cli-tests/mock-a-b-2.txt',
                            'name': 'output',
                        }
                    ],
                    None,
                    None,
                ],
            )
            self.assertEqual(
                (out / 'nvme-cli-tests/mock-a-b-2.txt').read_text(
                    encoding='utf-8'
                ),
                'other',
            )

    def test_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src, out = Path(tmp, 'k.log'), Path(tmp, 'logs')
            src.write_text('log', encoding='utf-8')
            s: dict[str, Any] = {'name': 'nvme-keysd'}
            night.copy_log(s, src, out)
            self.assertEqual(
                s['files'],
                [{'href': 'logs/nvme-keysd/k.log.txt', 'name': 'log'}],
            )
            link = Path(tmp, 'link.log')
            link.symlink_to(src)
            s = {'name': 'x'}
            night.copy_log(s, link, out)
            self.assertNotIn('files', s)

    def test_slug(self) -> None:
        self.assertEqual(night.slug('unit tests (VM)'), 'unit-tests-VM')
        self.assertEqual(night.slug('../..'), 'x')


if __name__ == '__main__':
    unittest.main()
