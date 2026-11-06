# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for the list of known failures."""

from __future__ import annotations

import unittest
from typing import Any

from nvme_dashboard import known_failures as kf
from nvme_dashboard.known_failures import Entry

REF = 'https://example.org/issues/1'


class CheckEntry(unittest.TestCase):
    def test_valid(self) -> None:
        for test in (
            'nvme',
            'nvme/004',
            'nvme/004:tr=rdma',
            'nvme/004:tr=rdma,bd=file',
            'zbd/010',
        ):
            with self.subTest(test=test):
                self.assertIsNone(kf.check_entry('ignore', test))

    def test_invalid(self) -> None:
        for test in (
            'nvme/4',
            'nvme/0040',
            'nvme/004;reboot',
            'nvme/004:$(reboot)',
            'nvme/004:tr=rdma)',
            '../x',
            'nvme:tr=rdma',
            'nvme/004:',
            'nvme/004:a,,b',
            'NVME/004',
            "nvme/004:'x'",
        ):
            with self.subTest(test=test):
                self.assertIsNotNone(kf.check_entry('ignore', test))

    def test_actions(self) -> None:
        self.assertIsNotNone(kf.check_entry('skip', 'nvme/004'))
        self.assertIsNone(kf.check_entry('exclude', 'nvme/004'))
        # blktests' EXCLUDE has no conditions
        self.assertIsNotNone(kf.check_entry('exclude', 'nvme/004:tr=tcp'))


class ParseBody(unittest.TestCase):
    def test_lines(self) -> None:
        body = (
            'nvme/004 fails with rdma since 7.3-rc1.\r\n'
            '\r\n'
            'blktests-ignore: nvme/004:tr=rdma\r\n'
            '  blktests-exclude: nvme/039  \n'
            'see blktests-ignore: nvme/005 in the log\n'
            'blktests-ignore: nvme/006 nvme/007\n'
            'blktests-skip: nvme/008\n'
            'blktests-ignore: nvme/009;reboot\n'
        )
        entries, warnings = kf.parse_body(body, REF)
        self.assertEqual(
            entries,
            [
                Entry('ignore', 'nvme/004:tr=rdma', REF),
                Entry('exclude', 'nvme/039', REF),
            ],
        )
        # not a line of its own: nvme/005, nvme/006 nvme/007
        self.assertEqual(len(warnings), 2)
        self.assertIn('skip', warnings[0])
        self.assertIn('reboot', warnings[1])

    def test_empty(self) -> None:
        self.assertEqual(kf.parse_body('', REF), ([], []))


class ListFile(unittest.TestCase):
    def test_round_trip(self) -> None:
        entries = [
            Entry('ignore', 'nvme/073', 'https://e.org/2'),
            Entry('exclude', 'nvme/039', 'https://e.org/3'),
            Entry('ignore', 'nvme/004:tr=rdma', 'issue 1 on the list'),
        ]
        text = kf.format_list(entries)
        self.assertTrue(text.startswith('#'))
        self.assertEqual(kf.parse_list(text), (sorted(entries), []))

    def test_warnings(self) -> None:
        entries, warnings = kf.parse_list(
            'ignore\nignore nvme/04 x\nignore nvme/004\n'
        )
        self.assertEqual(entries, [Entry('ignore', 'nvme/004', '')])
        self.assertEqual(
            [w.split(':')[0] for w in warnings], ['line 1', 'line 2']
        )


class Config(unittest.TestCase):
    def test_config(self) -> None:
        cfg = kf.blktests_config(
            [
                Entry('ignore', 'nvme/074', 'a'),
                Entry('ignore', 'nvme/073', 'a'),
                Entry('ignore', 'nvme/073', 'b'),
                Entry('exclude', 'nvme/039', 'c'),
            ]
        )
        self.assertEqual(
            cfg, 'IGNORE_FAILURE+=(nvme/073 nvme/074)\nEXCLUDE+=(nvme/039)\n'
        )

    def test_empty(self) -> None:
        self.assertEqual(
            kf.blktests_config([]), 'IGNORE_FAILURE+=()\nEXCLUDE+=()\n'
        )


class GitHub(unittest.TestCase):
    def test_pages(self) -> None:
        def issue(n: int, body: str | None) -> dict[str, Any]:
            return {'html_url': f'https://gh/i/{n}', 'body': body}

        page1 = [
            issue(n, f'blktests-ignore: nvme/{n:03d}') for n in range(100)
        ]
        page1[5] = dict(page1[5], pull_request={})
        page2 = [issue(100, 'no tests here'), issue(101, None)]
        urls = []

        def fetch(url: str) -> list[dict[str, Any]]:
            urls.append(url)
            return page1 if url.endswith('&page=1') else page2

        entries, warnings = kf.from_github('o/r', 'a label', fetch=fetch)
        self.assertEqual(len(urls), 2)
        self.assertIn('/repos/o/r/issues?state=open&labels=a%20label', urls[0])
        self.assertEqual(len(entries), 99)
        self.assertNotIn(
            Entry('ignore', 'nvme/005', 'https://gh/i/5'), entries
        )
        self.assertEqual(len(warnings), 2)


if __name__ == '__main__':
    unittest.main()
