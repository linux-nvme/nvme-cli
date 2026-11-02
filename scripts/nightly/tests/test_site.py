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


if __name__ == '__main__':
    unittest.main()
