# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for reading and judging blktests results."""

import tempfile
import unittest
from pathlib import Path

from nvme_nightly import blktests
from nvme_nightly.blktests import Result
from nvme_nightly.known_failures import Entry


def write(results: Path, config: str, test: str, **items: str) -> None:
    path = results / config / test
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        ''.join('{}\t{}\n'.format(*kv) for kv in items.items()),
        encoding='utf-8',
    )


class ReadResults(unittest.TestCase):
    def test_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp)
            write(
                res,
                'nodev_tr_rdma',
                'nvme/004',
                status='fail',
                reason='dmesg',
                runtime='2.6s',
                description='uuid',
            )
            write(res, 'nvme1n1', 'block/001', status='not run')
            # leftovers of a test run, not results
            write(res, 'nodev_tr_rdma', 'nvme/004.full', status='x')
            write(res, 'nodev_tr_rdma', 'nvme/004.out.bad', status='x')
            (res / 'nvme-cli.version').write_text(
                'nvme version 3\n', encoding='utf-8'
            )
            (res / 'nodev' / 'nvme' / '005').mkdir(parents=True)
            self.assertEqual(
                blktests.read_results(res),
                [
                    Result('block/001', 'nvme1n1', 'not run'),
                    Result(
                        'nvme/004',
                        'nodev_tr_rdma',
                        'fail',
                        'dmesg',
                        '2.6s',
                        'uuid',
                    ),
                ],
            )


class Matches(unittest.TestCase):
    def test_matches(self) -> None:
        r = Result('nvme/004', 'nodev_tr_rdma_bd_file', 'fail')
        for test, want in (
            ('nvme/004', True),
            ('nvme', True),
            ('nvme/004:tr=rdma', True),
            ('nvme/004:bd=file,tr=rdma', True),
            ('nvme/004:tr=tcp', False),
            ('nvme/004:tr=rdma,bd=device', False),
            ('nvme/005', False),
            ('nvm', False),
            ('nvme/004:tr=rd', False),
        ):
            with self.subTest(test=test):
                self.assertEqual(blktests.matches(test, r), want)


KNOWN = [
    Entry('ignore', 'nvme/004:tr=rdma', 'https://e.org/1'),
    Entry('ignore', 'nvme/073', 'https://e.org/2'),
    Entry('exclude', 'nvme/039', 'https://e.org/3'),
    Entry('ignore', 'md/002', 'https://e.org/4'),
]


class Summarize(unittest.TestCase):
    def test_known_failures_only(self) -> None:
        s = blktests.summarize(
            [
                Result('nvme/004', 'nodev_tr_rdma', 'fail'),
                Result('nvme/004', 'nodev_tr_tcp', 'pass'),
                Result('nvme/073', 'nodev_tr_loop', 'fail'),
                Result('nvme/073', 'nodev_tr_tcp', 'pass'),
                Result('md/001', 'nodev', 'not run'),
            ],
            KNOWN,
            check_status=1,
        )
        self.assertEqual(s['outcome'], 'pass')
        self.assertEqual(s['problems'], [])
        self.assertEqual(
            s['counts'],
            {
                'pass': 2,
                'fail': 0,
                'ignored': 2,
                'not run': 1,
                'other': 0,
                'known_passed': 1,
            },
        )
        self.assertEqual(
            [k['matched'] for k in s['known_failures']], [-1, 0, 1, 2]
        )
        tcp = s['tests'][1]
        self.assertNotIn('known', tcp)
        self.assertEqual(s['tests'][3]['known'], 'https://e.org/2')

    def test_new_failure(self) -> None:
        s = blktests.summarize(
            [
                Result('nvme/004', 'nodev_tr_tcp', 'fail', 'output'),
                Result('nvme/073', 'nodev_tr_loop', 'fail'),
            ],
            KNOWN,
            check_status=1,
        )
        self.assertEqual(s['outcome'], 'fail')
        self.assertEqual(s['problems'], ['1 failed test runs'])
        self.assertEqual(s['tests'][0]['reason'], 'output')

    def test_check_failed_without_failed_test(self) -> None:
        s = blktests.summarize(
            [Result('md/001', 'nodev', 'pass')], KNOWN, check_status=2
        )
        self.assertEqual(s['outcome'], 'fail')
        self.assertIn('exited with 2', s['problems'][0])
        # no ./check status given: the results decide
        s = blktests.summarize([Result('md/001', 'nodev', 'pass')], KNOWN)
        self.assertEqual(s['outcome'], 'pass')

    def test_no_results(self) -> None:
        s = blktests.summarize([], KNOWN, check_status=0)
        self.assertEqual(s['outcome'], 'fail')
        self.assertEqual(s['problems'], ['no test results'])


if __name__ == '__main__':
    unittest.main()
