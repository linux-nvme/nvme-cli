# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for the links to the job log lines."""

import unittest
from typing import Any

from nvme_nightly import joblog

URL = 'https://github.com/o/r/actions/runs/1/job/2'

# The shape of a job log of the nightly: the checkout step ends in the
# second the blktests step starts, which runs a local action.
LOG = [
    '2026-11-03T09:06:40.1Z Current runner version',
    '2026-11-03T09:06:41.1Z ##[group]Run actions/checkout@v7',
    '2026-11-03T09:06:41.2Z with:',
    '2026-11-03T09:06:42.7Z ##[endgroup]',
    '2026-11-03T09:06:42.8Z f8a27c97c3413506a7fecfc63803554e776562c1',
    '2026-11-03T09:06:42.9Z Prepare all required actions',
    '2026-11-03T09:06:44.2Z ##[group]Run ./.github/actions/kubevirt-action',
    '2026-11-03T09:06:44.3Z ignore nvme/003:tr=rdma https://e.org/issues/1',
    '2026-11-03T09:30:27.0Z nvme/003 (tr=loop) (keep-alives) [passed]',
    '2026-11-03T09:30:53.9Z nvme/003 (tr=rdma) (keep-alives) [failed]',
    '2026-11-03T09:30:54.0Z     runtime    ...  12.481s',
    '2026-11-03T09:31:00.0Z nvme/033 => nvme1n1 (tr=loop bd=file) (x) '
    '[failed]',
    '2026-11-03T09:31:01.0Z block/001 (stress device hotplugging) [failed]',
    '2026-11-03T09:52:18.4Z ##[group]Run actions/upload-artifact@v7',
    '2026-11-03T09:54:37.1Z Prepare all required actions',
    '2026-11-03T09:54:38.0Z nvme/005 (tr=loop) (reset) [failed]',
    '2026-11-03T10:50:17.0Z Post job cleanup.',
]

STEPS = [
    {'number': 1, 'name': 'Set up job', 'started_at': '2026-11-03T09:06:40Z'},
    {'number': 2, 'name': 'checkout', 'started_at': '2026-11-03T09:06:41Z'},
    {
        'number': 3,
        'name': 'Run blktests in VM',
        'started_at': '2026-11-03T09:06:42Z',
    },
    {
        'number': 4,
        'name': 'Run nvme-cli tests in VM',
        'started_at': '2026-11-03T09:54:37Z',
    },
    # the post steps are numbered after a gap
    {
        'number': 10,
        'name': 'Post checkout',
        'started_at': '2026-11-03T10:50:17Z',
    },
]


def failed(test: str, config: str) -> dict[str, Any]:
    return {'test': test, 'config': config, 'status': 'fail'}


class StepStarts(unittest.TestCase):
    def test_starts(self) -> None:
        # step 3 is not the checkout's output in the same second; the
        # local action's run group is not a step of its own
        self.assertEqual(
            joblog.step_starts(LOG, STEPS), {1: 0, 2: 1, 3: 5, 4: 14}
        )

    def test_not_found(self) -> None:
        steps = [*STEPS[:2], dict(STEPS[2], started_at='2026-11-04T00:00:00Z')]
        self.assertEqual(joblog.step_starts(LOG, steps), {1: 0, 2: 1})
        self.assertEqual(joblog.step_starts([], STEPS), {})


class Results(unittest.TestCase):
    def test_configs(self) -> None:
        self.assertEqual(
            joblog.result_lines(LOG),
            {
                ('nvme/003', 'nodev_tr_loop'): 8,
                ('nvme/003', 'nodev_tr_rdma'): 9,
                ('nvme/033', 'nvme1n1_tr_loop_bd_file'): 11,
                ('block/001', 'nodev'): 12,
                ('nvme/005', 'nodev_tr_loop'): 15,
            },
        )


class AddLinks(unittest.TestCase):
    def test_links(self) -> None:
        s = {
            'tests': [
                failed('nvme/003', 'nodev_tr_rdma'),
                failed('nvme/033', 'nvme1n1_tr_loop_bd_file'),
                failed('block/001', 'nodev'),
                # in the log, but of the next step
                failed('nvme/005', 'nodev_tr_loop'),
                {'test': 'nvme/003', 'config': 'nodev_tr_loop'},
            ]
        }
        job = {'html_url': URL, 'steps': STEPS}
        log = '\n'.join(LOG)
        self.assertEqual(
            joblog.add_links(s, job, log, 'Run blktests in VM'), 3
        )
        self.assertEqual(
            [t.get('log') for t in s['tests']],
            [
                f'{URL}#step:3:5',
                f'{URL}#step:3:7',
                f'{URL}#step:3:8',
                None,
                None,
            ],
        )

    def test_no_links(self) -> None:
        log = '\n'.join(LOG)
        for job, step in (
            ({'html_url': URL, 'steps': STEPS}, 'no such step'),
            ({'html_url': 'javascript:x', 'steps': STEPS}, 'checkout'),
            ({'steps': STEPS}, 'checkout'),
        ):
            s = {'tests': [failed('nvme/003', 'nodev_tr_rdma')]}
            self.assertEqual(joblog.add_links(s, job, log, step), 0)
            self.assertNotIn('log', s['tests'][0])


# A meson run and a wringer in one step, as the job log has them: the
# wringer output in color.
TESTS_LOG = [
    '2026-11-05T01:00:00.1Z Current runner version',
    '2026-11-05T01:00:01.1Z ##[group]Run ./.github/actions/kubevirt-action',
    '2026-11-05T01:10:00.0Z   1/302 nvme-cli:unit / libnvme - uuid'
    '                OK              0.02s',
    '2026-11-05T01:20:00.0Z 223/302 nvme-cli:mock / nvme-cli - print'
    '                TIMEOUT        300.15s   killed by signal 15 SIGTERM',
    '2026-11-05T01:21:00.0Z  9/276 mock - nvme-cli:nvme-cli - old'
    ' FAIL 1.00s   exit status 1',
    '2026-11-05T01:22:00.0Z \x1b[0;31m  FAIL: the unit is active\x1b[0m',
    '2026-11-05T01:22:01.0Z   PASS: key A is in .nvme',
    '2026-11-05T01:22:02.0Z \x1b[0;31m  FAIL: the unit is active\x1b[0m',
]
TESTS_STEPS = [
    {'number': 1, 'name': 'Set up job', 'started_at': '2026-11-05T01:00:00Z'},
    {'number': 2, 'name': 'tests', 'started_at': '2026-11-05T01:00:01Z'},
]


class OtherKinds(unittest.TestCase):
    def test_meson(self) -> None:
        s: dict[str, Any] = {
            'kind': 'meson',
            'tests': [
                {
                    'id': 'nvme-cli:mock / nvme-cli - print',
                    'status': 'timeout',
                },
                {'id': 'mock - nvme-cli:nvme-cli - old', 'status': 'fail'},
                # passed, or not in the log
                {'id': 'nvme-cli:unit / libnvme - uuid', 'status': 'skip'},
                {'id': 'nvme-cli:unit / x', 'status': 'fail'},
            ],
        }
        job = {'html_url': URL, 'steps': TESTS_STEPS}
        self.assertEqual(
            joblog.add_links(s, job, '\n'.join(TESTS_LOG), 'tests'), 2
        )
        self.assertEqual(
            [t.get('log') for t in s['tests']],
            [f'{URL}#step:2:3', f'{URL}#step:2:4', None, None],
        )

    def test_wringer(self) -> None:
        s: dict[str, Any] = {
            'kind': 'wringer',
            'tests': [{'test': 'the unit is active', 'status': 'fail'}],
        }
        job = {'html_url': URL, 'steps': TESTS_STEPS}
        self.assertEqual(
            joblog.add_links(s, job, '\n'.join(TESTS_LOG), 'tests'), 1
        )
        # the first failure of the check
        self.assertEqual(s['tests'][0]['log'], f'{URL}#step:2:5')


if __name__ == '__main__':
    unittest.main()
