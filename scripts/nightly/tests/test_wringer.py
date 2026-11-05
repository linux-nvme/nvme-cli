# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for the summary of a daemon wringer log."""

import unittest

from nvme_nightly import wringer

CYAN, RED, YELLOW, NORMAL = '\x1b[1;36m', '\x1b[0;31m', '\x1b[1;33m', '\x1b[0m'


class Summarize(unittest.TestCase):
    def test_pass(self) -> None:
        log = (
            f'{CYAN}Phase 1{NORMAL}\n'
            '  PASS: the unit is active\n'
            f'{YELLOW}  SKIP: no mDNS{NORMAL}\n'
            f'{CYAN}Results: 94 passed, 0 failed, 1 skipped{NORMAL}\n'
            f'{CYAN}Cleanup{NORMAL}\n'
        )
        s = wringer.summarize(log)
        self.assertEqual((s['kind'], s['outcome']), ('wringer', 'pass'))
        self.assertEqual(s['counts'], {'pass': 94, 'fail': 0, 'skip': 1})
        self.assertEqual(
            s['tests'], [{'test': 'no mDNS', 'config': '', 'status': 'skip'}]
        )

    def test_fail(self) -> None:
        # nvme-keysd's wringer counts no skipped checks
        log = (
            f'{RED}  FAIL: key A is in .nvme{NORMAL}\n'
            f'{RED}  FAIL: the unit is not failed{NORMAL}\n'
            f'{CYAN}Results: 107 passed, 2 failed{NORMAL}\n'
        )
        s = wringer.summarize(log)
        self.assertEqual(s['outcome'], 'fail')
        self.assertEqual(s['problems'], ['2 checks failed'])
        self.assertEqual(s['counts'], {'pass': 107, 'fail': 2, 'skip': 0})
        self.assertEqual(
            [t['test'] for t in s['tests']],
            ['key A is in .nvme', 'the unit is not failed'],
        )

    def test_unfinished(self) -> None:
        s = wringer.summarize(f'{RED}  FAIL: setup{NORMAL}\n')
        self.assertEqual(
            s['problems'], ['the run did not finish', '1 check failed']
        )
        self.assertEqual(s['counts'], {'pass': 0, 'fail': 1, 'skip': 0})
        self.assertEqual(wringer.summarize('')['outcome'], 'fail')


if __name__ == '__main__':
    unittest.main()
