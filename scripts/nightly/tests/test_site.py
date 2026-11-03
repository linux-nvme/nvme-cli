# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for the status page."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from nvme_nightly import site

# The CI containers have jinja2; without it only the page models are
# tested.
HAVE_JINJA2 = importlib.util.find_spec('jinja2') is not None
needs_jinja2 = unittest.skipUnless(HAVE_JINJA2, 'needs python3 jinja2')


def summary(run_id: str, date: str, **kw: Any) -> dict[str, Any]:
    s: dict[str, Any] = {
        'run_id': run_id,
        'date': date,
        'outcome': 'pass',
        'problems': [],
        'counts': {},
        'known_failures': [],
        'tests': [],
    }
    s.update(kw)
    return s


class MergeHistory(unittest.TestCase):
    def test_merge(self) -> None:
        old = [summary('2', '2026-11-02'), summary('1', '2026-11-01')]
        new = summary('3', '2026-11-03')
        self.assertEqual(
            [s['run_id'] for s in site.merge_history(old, new)],
            ['3', '2', '1'],
        )
        # the page is built again for the same run
        again = summary('2', '2026-11-02', outcome='fail')
        merged = site.merge_history(old, again)
        self.assertEqual([s['run_id'] for s in merged], ['2', '1'])
        self.assertEqual(merged[0]['outcome'], 'fail')
        self.assertEqual(len(site.merge_history(old, new, keep=2)), 2)
        self.assertEqual(site.merge_history(old, None), old)


class Model(unittest.TestCase):
    def test_refs(self) -> None:
        self.assertEqual(site.weburl('javascript:alert(1)'), '')
        self.assertEqual(site.weburl('https://e.org/x'), 'https://e.org/x')
        self.assertEqual(site.short_ref('https://e.org/issues/7'), '#7')
        self.assertEqual(
            site.short_ref('https://e.org/issues'), 'https://e.org/issues'
        )
        self.assertEqual(
            site.short_ref('issue 7 on the list'), 'issue 7 on the list'
        )

    def test_cell_status(self) -> None:
        self.assertEqual(site.cell_status(None), 'none')
        self.assertEqual(site.cell_status({'status': 'fail'}), 'fail')
        self.assertEqual(
            site.cell_status({'status': 'fail', 'known': 'x'}), 'ignored'
        )
        self.assertEqual(site.cell_status({'status': 'odd'}), 'not run')

    def test_latest(self) -> None:
        s = summary(
            '1',
            '2026-11-01',
            kernel='7.4',
            tests=[
                {
                    'test': 'nvme/073',
                    'config': c,
                    'status': st,
                    'known': 'https://e.org/issues/9',
                }
                for c, st in (
                    ('nodev_tr_loop', 'pass'),
                    ('nodev_tr_tcp', 'fail'),
                )
            ]
            + [{'test': 'nvme/005', 'config': 'nodev', 'status': 'fail'}],
            known_failures=[
                {
                    'action': 'ignore',
                    'test': 'nvme/073',
                    'ref': 'https://e.org/issues/9',
                    'matched': 2,
                },
                {
                    'action': 'ignore',
                    'test': 'nvme/099',
                    'ref': 'https://e.org/issues/8',
                    'matched': 0,
                },
                {
                    'action': 'exclude',
                    'test': 'nvme/010',
                    'ref': 'https://e.org/issues/3',
                    'matched': -1,
                },
            ],
        )
        m = site.latest_model(s)
        self.assertEqual(
            m['meta'], [('date', '2026-11-01'), ('kernel', '7.4')]
        )
        # new failures first
        self.assertEqual(
            [(t['test'], t['status']) for t in m['failed']],
            [('nvme/005', 'fail'), ('nvme/073', 'ignored')],
        )
        self.assertEqual(
            [k['note'] for k in m['known']],
            ['passed 1 of 2 runs', 'matched no test run', 'excluded, not run'],
        )

    def test_matrix(self) -> None:
        old = summary(
            '1',
            '2026-11-01',
            outcome='fail',
            tests=[
                {'test': 'md/001', 'config': 'nodev', 'status': 'fail'},
                {'test': 'nvme/004', 'config': 'nodev', 'status': 'pass'},
            ],
        )
        new = summary(
            '2',
            '2026-11-02',
            run_url='https://e.org/2',
            tests=[
                {'test': 'md/001', 'config': 'nodev', 'status': 'pass'},
                {'test': 'nvme/004', 'config': 'nodev', 'status': 'pass'},
            ],
        )
        m = site.matrix_model([new, old])
        self.assertEqual(
            [(n['label'], n['status']) for n in m['nights']],
            [('2026-11-01', 'fail'), ('2026-11-02', 'pass')],
        )
        # only the runs which failed once
        self.assertEqual([r['test'] for r in m['rows']], ['md/001'])
        self.assertEqual(
            [c['status'] for c in m['rows'][0]['cells']], ['fail', 'pass']
        )
        self.assertEqual(
            m['rows'][0]['cells'][1]['run_url'], 'https://e.org/2'
        )

    def test_matrix_log(self) -> None:
        log = 'https://e.org/2/job/3#step:3:7'
        s = summary(
            '2',
            '2026-11-02',
            outcome='fail',
            run_url='https://e.org/2',
            tests=[
                {'test': 'md/001', 'config': 'nodev', 'status': 'fail'},
                {
                    'test': 'md/002',
                    'config': 'nodev',
                    'status': 'fail',
                    'log': log,
                },
            ],
        )
        m = site.matrix_model([s])
        self.assertEqual(
            [r['cells'][0]['run_url'] for r in m['rows']],
            ['https://e.org/2', log],
        )

    def test_window(self) -> None:
        history = [summary(str(i), f'2026-{i:04d}') for i in range(40)]
        self.assertEqual(
            len(site.matrix_model(history)['nights']), site.MATRIX_NIGHTS
        )


@needs_jinja2
class Render(unittest.TestCase):
    def test_escapes(self) -> None:
        evil = '<script>alert(1)</script>'
        s = summary(
            '1',
            '2026-11-01',
            outcome='fail',
            problems=[evil],
            kernel=evil,
            run_url='javascript:alert(1)',
            known_failures=[
                {
                    'action': 'ignore',
                    'test': 'nvme/004',
                    'ref': 'javascript:x',
                    'matched': 1,
                }
            ],
            tests=[
                {
                    'test': 'nvme/004',
                    'config': evil,
                    'status': 'fail',
                    'reason': evil,
                    'known': '"><script>',
                }
            ],
        )
        page = site.render([s])
        self.assertNotIn('<script>', page)
        self.assertNotIn('href="javascript', page)

    def test_states(self) -> None:
        tests = [
            {
                'test': 'nvme/004',
                'config': 'nodev_tr_rdma',
                'status': 'fail',
                'known': 'https://e.org/issues/7',
            },
            {'test': 'nvme/005', 'config': 'nodev', 'status': 'fail'},
            {'test': 'md/001', 'config': 'nodev', 'status': 'pass'},
        ]
        s = summary(
            '1',
            '2026-11-01',
            outcome='fail',
            tests=tests,
            known_failures=[
                {
                    'action': 'ignore',
                    'test': 'nvme/004:tr=rdma',
                    'ref': 'https://e.org/issues/7',
                    'matched': 1,
                },
                {
                    'action': 'ignore',
                    'test': 'nvme/099',
                    'ref': 'https://e.org/issues/8',
                    'matched': 0,
                },
            ],
        )
        page = site.render([s, summary('0', '2026-10-31')])
        self.assertIn('✗ failed', page)
        self.assertIn('>#7</a>', page)
        self.assertIn('matched no test run', page)
        # the matrix lists the failed runs only
        self.assertIn('nodev_tr_rdma', page.split('<h2>History')[1])
        self.assertNotIn('md/001', page.split('<h2>History')[1])

    def test_known_failure_passed(self) -> None:
        s = summary(
            '1',
            '2026-11-01',
            tests=[
                {
                    'test': 'nvme/073',
                    'config': c,
                    'status': st,
                    'known': 'https://e.org/issues/9',
                }
                for c, st in (
                    ('nodev_tr_loop', 'pass'),
                    ('nodev_tr_tcp', 'fail'),
                )
            ],
            known_failures=[
                {
                    'action': 'ignore',
                    'test': 'nvme/073',
                    'ref': 'https://e.org/issues/9',
                    'matched': 2,
                }
            ],
        )
        self.assertIn('passed 1 of 2 runs', site.render([s]))

    def test_empty(self) -> None:
        self.assertIn('No nightly results yet', site.render([]))


class CopyLogs(unittest.TestCase):
    def test_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            res, out = Path(tmp, 'results'), Path(tmp, 'site')
            d = res / 'nodev_tr_tcp' / 'nvme'
            d.mkdir(parents=True)
            (d / '073.full').write_text('full log', encoding='utf-8')
            (d / '073.out.bad').write_text('bad', encoding='utf-8')
            (d / '074.full').write_bytes(b'x' * (site.LOG_MAX + 10))
            (d / '075.full').symlink_to('/etc/passwd')
            (res / 'secret').write_text('no', encoding='utf-8')
            s = summary(
                '1',
                '2026-11-01',
                tests=[
                    {
                        'test': f'nvme/{n}',
                        'config': 'nodev_tr_tcp',
                        'status': st,
                    }
                    for n, st in (
                        ('073', 'fail'),
                        ('074', 'fail'),
                        ('075', 'fail'),
                        ('076', 'pass'),
                    )
                ]
                + [
                    {'test': '../secret', 'config': '..', 'status': 'fail'},
                    {
                        'test': 'nvme/001',
                        'config': '.hidden',
                        'status': 'fail',
                    },
                ],
            )
            logs = site.copy_logs(res, s, out)
            self.assertEqual(
                logs,
                {
                    ('nvme/073', 'nodev_tr_tcp'): [
                        {
                            'name': 'out.bad',
                            'href': 'logs/nodev_tr_tcp/nvme/073.out.bad.txt',
                        },
                        {
                            'name': 'full',
                            'href': 'logs/nodev_tr_tcp/nvme/073.full.txt',
                        },
                    ],
                    ('nvme/074', 'nodev_tr_tcp'): [
                        {
                            'name': 'full',
                            'href': 'logs/nodev_tr_tcp/nvme/074.full.txt',
                        }
                    ],
                },
            )
            self.assertEqual(
                (out / 'logs/nodev_tr_tcp/nvme/073.full.txt').read_text(
                    encoding='utf-8'
                ),
                'full log',
            )
            big = (out / 'logs/nodev_tr_tcp/nvme/074.full.txt').read_bytes()
            self.assertTrue(big.endswith(b'\n[truncated]\n'))
            self.assertEqual(
                sorted(p.name for p in out.rglob('*') if p.is_file()),
                ['073.full.txt', '073.out.bad.txt', '074.full.txt'],
            )


@needs_jinja2
class Build(unittest.TestCase):
    def test_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            analyzer = Path(tmp, 'scan')
            analyzer.mkdir()
            (analyzer / 'index.html').write_text('report', encoding='utf-8')
            out = Path(tmp, 'site')
            history = [summary('1', '2026-11-01')]
            site.build(out, history, analyzer, [('Codecov', 'https://c.io')])
            self.assertEqual(
                json.loads((out / 'history.json').read_text(encoding='utf-8')),
                history,
            )
            self.assertEqual(
                (out / 'analyzer/index.html').read_text(encoding='utf-8'),
                'report',
            )
            self.assertTrue((out / 'style.css').exists())
            page = (out / 'index.html').read_text(encoding='utf-8')
            self.assertIn('href="analyzer/"', page)
            self.assertIn('href="https://c.io"', page)

    def test_logs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            res, out = Path(tmp, 'results'), Path(tmp, 'site')
            (res / 'nodev' / 'md').mkdir(parents=True)
            (res / 'nodev' / 'md' / '001.full').write_text(
                'log', encoding='utf-8'
            )
            log = 'https://e.org/1/job/2#step:3:7'
            s = summary(
                '1',
                '2026-11-01',
                outcome='fail',
                tests=[
                    {
                        'test': 'md/001',
                        'config': 'nodev',
                        'status': 'fail',
                        'log': log,
                    },
                    {
                        'test': 'md/002',
                        'config': 'nodev',
                        'status': 'fail',
                        'log': 'javascript:x',
                    },
                ],
            )
            site.build(out, [s], results=res)
            page = (out / 'index.html').read_text(encoding='utf-8')
            failed = page.split('<h2>Failed test runs')[1].split('<h2>')[0]
            self.assertIn(f'<a href="{log}">job log</a>', failed)
            self.assertIn(
                '<a href="logs/nodev/md/001.full.txt">full</a>', failed
            )
            self.assertNotIn('javascript', page)


if __name__ == '__main__':
    unittest.main()
