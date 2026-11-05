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


def section(name: str, kind: str = 'meson', **kw: Any) -> dict[str, Any]:
    s: dict[str, Any] = {
        'name': name,
        'kind': kind,
        'outcome': 'pass',
        'problems': [],
        'counts': {},
        'tests': [],
    }
    s.update(kw)
    return s


def record(
    run_id: str,
    date: str,
    *sections: dict[str, Any],
    workflow: str = 'Nightly tests',
    **kw: Any,
) -> dict[str, Any]:
    r: dict[str, Any] = {
        'version': 2,
        'workflow': workflow,
        'run_id': run_id,
        'run_url': f'https://e.org/{run_id}',
        'event': 'schedule',
        'date': date,
        'outcome': 'pass',
        'problems': [],
        'warnings': [],
        'jobs': [],
        'sections': list(sections),
    }
    r.update(kw)
    return r


def blktests(*tests: tuple[str, str, str], **kw: Any) -> dict[str, Any]:
    return section(
        'blktests',
        'blktests',
        tests=[{'test': t, 'config': c, 'status': st} for t, c, st in tests],
        **kw,
    )


class MergeHistory(unittest.TestCase):
    def test_merge(self) -> None:
        old = [record('2', '2026-11-02'), record('1', '2026-11-01')]
        new = record('3', '2026-11-03')
        self.assertEqual(
            [r['run_id'] for r in site.merge_history(old, [new])],
            ['3', '2', '1'],
        )
        # the page is built again for the same run
        again = record('2', '2026-11-02', outcome='fail')
        merged = site.merge_history(old, [again])
        self.assertEqual([r['run_id'] for r in merged], ['2', '1'])
        self.assertEqual(merged[0]['outcome'], 'fail')
        self.assertEqual(site.merge_history(old, []), old)

    def test_keep_per_workflow(self) -> None:
        old = [record(str(i), f'2026-11-0{i}') for i in range(5, 0, -1)]
        new = record('a', '2026-11-06', workflow='Nightly analyzers')
        merged = site.merge_history(old, [new], keep=2)
        self.assertEqual(
            [(r['workflow'], r['run_id']) for r in merged],
            [
                ('Nightly analyzers', 'a'),
                ('Nightly tests', '5'),
                ('Nightly tests', '4'),
            ],
        )
        # the same run id of another workflow is another run
        other = record('5', '2026-11-07', workflow='Nightly analyzers')
        merged = site.merge_history(old, [other])
        self.assertEqual(len(merged), 6)

    def test_migrate(self) -> None:
        # a blktests summary of the history before the records
        old = {
            'run_id': '1',
            'date': '2026-11-01 02:00:00',
            'outcome': 'pass',
            'problems': [],
            'counts': {},
            'tests': [],
        }
        merged = site.merge_history([old], [record('2', '2026-11-02')])
        self.assertEqual(merged[1]['workflow'], 'Nightly tests')
        self.assertEqual(merged[1]['sections'][0]['name'], 'blktests')
        # the record of the same run replaces it
        merged = site.merge_history([old], [record('1', '2026-11-01')])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]['version'], 2)


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
        self.assertEqual(site.cell_status({'status': 'timeout'}), 'timeout')
        self.assertEqual(
            site.cell_status({'status': 'fail', 'known': 'x'}), 'ignored'
        )
        self.assertEqual(site.cell_status({'status': 'odd'}), 'not run')

    def test_counts_text(self) -> None:
        self.assertEqual(site.counts_text({}), '0 passed, 0 failed')
        self.assertEqual(
            site.counts_text(
                {'skip': 18, 'pass': 278, 'timeout': 1, 'fail': 0}
            ),
            '278 passed, 0 failed, 1 timed out, 18 skipped',
        )

    def test_event(self) -> None:
        self.assertEqual(site.event_label({'event': 'schedule'}), '')
        self.assertEqual(
            site.event_label({'event': 'workflow_dispatch'}), 'manual'
        )
        self.assertEqual(site.event_label({'event': 'push'}), 'push')
        self.assertEqual(site.event_label({}), '')

    def test_latest(self) -> None:
        known = 'https://e.org/issues/9'
        b = blktests(
            ('nvme/005', 'nodev', 'fail'),
            blktests='def',
            known_failures=[
                {
                    'action': 'ignore',
                    'test': 'nvme/073',
                    'ref': known,
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
        b['tests'] += [
            {'test': 'nvme/073', 'config': c, 'status': st, 'known': known}
            for c, st in (('nodev_tr_loop', 'pass'), ('nodev_tr_tcp', 'fail'))
        ]
        m = section(
            'nvme-cli tests',
            outcome='fail',
            url='https://e.org/1/job/2#step:4:1',
            counts={'pass': 3, 'timeout': 1},
            tests=[
                {
                    'test': 'mock / print',
                    'config': '',
                    'status': 'timeout',
                    'reason': 'TIMEOUT',
                    'duration': 300.2,
                    'files': [{'href': 'logs/x.txt', 'name': 'output'}],
                },
                {'test': 'unit / skipped', 'config': '', 'status': 'skip'},
            ],
        )
        r = record(
            '1',
            '2026-11-01 01:00:00',
            b,
            m,
            event='workflow_dispatch',
            kernel='7.4',
            nvme_cli='abc',
            outcome='fail',
            problems=['nvme-cli tests: 1 test timed out'],
        )
        lm = site.latest_model(r)
        self.assertFalse(lm['ok'])
        self.assertEqual(
            lm['meta'],
            [
                ('date', '2026-11-01 01:00:00'),
                ('started', 'manual'),
                ('kernel', '7.4'),
                ('nvme-cli', 'abc'),
                ('blktests', 'def'),
            ],
        )
        self.assertEqual(
            [(s['name'], s['ok'], s['counts']) for s in lm['sections']],
            [
                ('blktests', True, '0 passed, 0 failed'),
                ('nvme-cli tests', False, '3 passed, 0 failed, 1 timed out'),
            ],
        )
        # new failures first, of any section; the known ones last
        self.assertEqual(
            [(t['section'], t['test'], t['status']) for t in lm['failed']],
            [
                ('blktests', 'nvme/005', 'fail'),
                ('nvme-cli tests', 'mock / print', 'timeout'),
                ('blktests', 'nvme/073', 'ignored'),
            ],
        )
        self.assertEqual(lm['failed'][1]['duration'], 300.2)
        self.assertEqual(lm['failed'][1]['files'][0]['href'], 'logs/x.txt')
        self.assertEqual(
            [k['note'] for k in lm['known']],
            ['passed 1 of 2 runs', 'matched no test run', 'excluded, not run'],
        )

    def test_overview(self) -> None:
        history = [
            record('a2', '2026-11-03', workflow='Nightly analyzers'),
            record('t2', '2026-11-02', outcome='fail'),
            record('z', '2026-11-02', workflow='A first by name'),
            record('t1', '2026-11-01'),
        ]
        o = site.overview_model(history)
        self.assertEqual(
            [(w['workflow'], w['ok']) for w in o],
            [
                ('Nightly tests', False),
                ('A first by name', True),
                ('Nightly analyzers', True),
            ],
        )
        self.assertFalse(site.page_model(history)['ok'])
        self.assertTrue(site.page_model(history[2:])['ok'])

    def test_matrix(self) -> None:
        old = record(
            '1',
            '2026-11-01 01:00:00',
            blktests(
                ('md/001', 'nodev', 'fail'), ('nvme/004', 'nodev', 'pass')
            ),
            outcome='fail',
        )
        new = record(
            '2',
            '2026-11-02 01:00:00',
            blktests(
                ('md/001', 'nodev', 'pass'), ('nvme/004', 'nodev', 'pass')
            ),
            section(
                'nvme-cli tests',
                outcome='fail',
                url='https://e.org/2/job/3#step:4:1',
                tests=[
                    {'test': 'mock / print', 'config': '', 'status': 'fail'}
                ],
            ),
            event='workflow_dispatch',
        )
        later = record(
            '3',
            '2026-11-03 01:00:00',
            blktests(),
            # the meson section has only the tests which did not pass
            section('nvme-cli tests'),
        )
        analyzer = record(
            'a',
            '2026-11-02 01:30:00',
            workflow='Nightly analyzers',
            outcome='fail',
        )
        m = site.matrix_model([later, analyzer, new, old])
        self.assertEqual(
            [(n['label'], n['status'], n['event']) for n in m['nights']],
            [
                ('2026-11-01', 'fail', ''),
                ('2026-11-02', 'pass', 'manual'),
                ('2026-11-03', 'pass', ''),
            ],
        )
        self.assertEqual(
            [
                (r['label'], [c['status'] for c in r['cells']])
                for r in m['rows']
            ],
            [
                ('blktests', ['pass', 'pass', 'pass']),
                ('nvme-cli tests', ['none', 'fail', 'pass']),
                ('Nightly analyzers', ['none', 'fail', 'none']),
            ],
        )
        self.assertEqual(
            m['rows'][1]['cells'][1]['run_url'],
            'https://e.org/2/job/3#step:4:1',
        )
        self.assertEqual(
            m['rows'][2]['cells'][1]['run_url'], 'https://e.org/a'
        )
        # only the tests which failed once, by section
        self.assertEqual(
            [
                (r['section'], r['test'], [c['status'] for c in r['cells']])
                for r in m['tests']
            ],
            [
                # not in the blktests results of the last night
                ('blktests', 'md/001', ['fail', 'pass', 'none']),
                ('nvme-cli tests', 'mock / print', ['none', 'fail', 'pass']),
            ],
        )
        self.assertEqual(
            m['tests'][0]['cells'][1]['run_url'], 'https://e.org/2'
        )

    def test_matrix_log(self) -> None:
        log = 'https://e.org/2/job/3#step:3:7'
        b = blktests(('md/001', 'nodev', 'fail'), ('md/002', 'nodev', 'fail'))
        b['tests'][1]['log'] = log
        m = site.matrix_model([record('2', '2026-11-02', b, outcome='fail')])
        self.assertEqual(
            [r['cells'][0]['run_url'] for r in m['tests']],
            ['https://e.org/2', log],
        )

    def test_window(self) -> None:
        history = [record(str(i), f'2026-{i:04d}') for i in range(40)]
        history.append(record('a', '2026-0001', workflow='other'))
        m = site.matrix_model(history)
        self.assertEqual(len(m['nights']), site.MATRIX_NIGHTS)
        self.assertEqual(m['nights'][-1]['label'], '2026-0000')
        m = site.matrix_model(history, primary='other')
        self.assertEqual(len(m['nights']), 1)


@needs_jinja2
class Render(unittest.TestCase):
    def test_escapes(self) -> None:
        evil = '<script>alert(1)</script>'
        b = blktests(
            ('nvme/004', evil, 'fail'),
            outcome='fail',
            problems=[evil],
            url='javascript:alert(1)',
            known_failures=[
                {
                    'action': 'ignore',
                    'test': 'nvme/004',
                    'ref': 'javascript:x',
                    'matched': 1,
                }
            ],
            files=[{'href': 'javascript:x', 'name': evil}],
        )
        b['tests'][0].update(
            reason=evil,
            known='"><script>',
            log='javascript:y',
            files=[{'href': 'https://evil.org', 'name': evil}],
        )
        r = record(
            '1',
            '2026-11-01',
            b,
            outcome='fail',
            problems=[evil],
            warnings=[evil],
            kernel=evil,
            workflow=evil,
            run_url='javascript:alert(1)',
        )
        page = site.render([r], primary=evil)
        self.assertNotIn('<script>', page)
        self.assertNotIn('href="javascript', page)
        # the log files are those the page copied, nothing else
        self.assertNotIn('evil.org', page)

    def test_states(self) -> None:
        b = blktests(
            ('nvme/004', 'nodev_tr_rdma', 'fail'),
            ('nvme/005', 'nodev', 'fail'),
            ('md/001', 'nodev', 'pass'),
            outcome='fail',
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
        b['tests'][0]['known'] = 'https://e.org/issues/7'
        m = section(
            'nvme-cli tests',
            outcome='fail',
            tests=[
                {
                    'test': 'mock / print',
                    'config': '',
                    'status': 'timeout',
                    'duration': 300.2,
                    'files': [{'href': 'logs/t/print.txt', 'name': 'output'}],
                }
            ],
        )
        page = site.render(
            [
                record(
                    '2',
                    '2026-11-02',
                    b,
                    m,
                    outcome='fail',
                    problems=['nvme-cli tests: 1 test timed out'],
                    event='workflow_dispatch',
                ),
                record('a', '2026-11-02', workflow='Nightly analyzers'),
                record('1', '2026-10-31'),
            ]
        )
        top = page.split('<section')[0]
        self.assertIn('✗ failed', top)
        self.assertIn('Nightly tests', top)
        self.assertNotIn('Nightly analyzers', top)
        self.assertIn('nvme-cli tests: 1 test timed out', page)
        self.assertIn('>#7</a>', page)
        self.assertIn('matched no test run', page)
        self.assertIn('300.2s', page)
        self.assertIn('<a href="logs/t/print.txt">output</a>', page)
        self.assertIn('<h2>Nightly analyzers <span class="badge good">', page)
        history = page.split('<h2>History')[1]
        # the matrix lists the failed runs only
        self.assertIn('nodev_tr_rdma', history)
        self.assertIn('mock / print', history)
        self.assertNotIn('md/001', history)
        self.assertIn('<span title="manual">*</span>', history)

    def test_known_failure_passed(self) -> None:
        known = 'https://e.org/issues/9'
        b = blktests(
            known_failures=[
                {
                    'action': 'ignore',
                    'test': 'nvme/073',
                    'ref': known,
                    'matched': 2,
                }
            ]
        )
        b['tests'] = [
            {'test': 'nvme/073', 'config': c, 'status': st, 'known': known}
            for c, st in (('nodev_tr_loop', 'pass'), ('nodev_tr_tcp', 'fail'))
        ]
        page = site.render([record('1', '2026-11-01', b)])
        self.assertIn('passed 1 of 2 runs', page)

    def test_old_history(self) -> None:
        # the history.json before the records still renders
        old = {
            'run_id': '1',
            'date': '2026-11-01',
            'outcome': 'fail',
            'problems': ['1 failed test runs'],
            'counts': {},
            'known_failures': [],
            'tests': [{'test': 'md/001', 'config': 'nodev', 'status': 'fail'}],
        }
        page = site.render([old])
        self.assertIn('blktests: 1 failed test runs', page)
        self.assertIn('md/001', page.split('<h2>History')[1])

    def test_empty(self) -> None:
        self.assertIn('No nightly results yet', site.render([]))


@needs_jinja2
class Build(unittest.TestCase):
    def test_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            analyzer = Path(tmp, 'scan')
            analyzer.mkdir()
            (analyzer / 'index.html').write_text('report', encoding='utf-8')
            logs = Path(tmp, 'logs')
            (logs / 'blktests').mkdir(parents=True)
            (logs / 'blktests' / 'x.txt').write_text('log', encoding='utf-8')
            out = Path(tmp, 'site')
            b = blktests(('md/001', 'nodev', 'fail'), outcome='fail')
            b['tests'][0]['files'] = [
                {'href': 'logs/blktests/x.txt', 'name': 'full'}
            ]
            history = [record('1', '2026-11-01', b, outcome='fail')]
            site.build(
                out, history, analyzer, [('Codecov', 'https://c.io')], logs
            )
            stored = json.loads(
                (out / 'history.json').read_text(encoding='utf-8')
            )
            # the log files are only of this build
            self.assertNotIn('files', stored[0]['sections'][0]['tests'][0])
            self.assertEqual(stored[0]['run_id'], '1')
            self.assertEqual(
                (out / 'analyzer/index.html').read_text(encoding='utf-8'),
                'report',
            )
            self.assertEqual(
                (out / 'logs/blktests/x.txt').read_text(encoding='utf-8'),
                'log',
            )
            self.assertTrue((out / 'style.css').exists())
            page = (out / 'index.html').read_text(encoding='utf-8')
            self.assertIn('href="analyzer/"', page)
            self.assertIn('href="https://c.io"', page)
            self.assertIn('<a href="logs/blktests/x.txt">full</a>', page)


if __name__ == '__main__':
    unittest.main()
