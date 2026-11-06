# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for the summary of a meson test run."""

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from nvme_dashboard import meson


def test(name: str, result: str, **kw: Any) -> dict[str, Any]:
    return dict({'name': name, 'result': result, 'duration': 1.234}, **kw)


class ReadTestlog(unittest.TestCase):
    def test_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, 'testlog.json')
            path.write_text(
                json.dumps(test('a', 'OK'))
                + '\n\n'
                + '[1, 2]\n'
                + '{"no": "name"}\n'
                + json.dumps(test('b', 'FAIL'))
                # killed while writing the last line
                + '\n{"name": "c", "res',
                encoding='utf-8',
            )
            self.assertEqual(
                [t['name'] for t in meson.read_testlog(path)], ['a', 'b']
            )


class Summarize(unittest.TestCase):
    def test_pass(self) -> None:
        s = meson.summarize(
            [
                test('nvme-cli:unit / a', 'OK'),
                test('nvme-cli:unit / b', 'SKIP'),
                test('nvme-cli:unit / c', 'EXPECTEDFAIL'),
            ]
        )
        self.assertEqual((s['kind'], s['outcome']), ('meson', 'pass'))
        self.assertEqual(s['problems'], [])
        self.assertEqual(
            s['counts'],
            {
                'pass': 1,
                'fail': 0,
                'timeout': 0,
                'skip': 1,
                'expected fail': 1,
            },
        )
        # only the tests which did not pass, by the name the page shows
        self.assertEqual(
            [(t['test'], t['status']) for t in s['tests']],
            [('unit / b', 'skip'), ('unit / c', 'expected fail')],
        )
        self.assertEqual(s['tests'][0]['id'], 'nvme-cli:unit / b')
        self.assertEqual(s['tests'][0]['duration'], 1.2)

    def test_fail(self) -> None:
        s = meson.summarize(
            [
                test('nvme-cli:mock / nvme-cli - print', 'TIMEOUT'),
                test('x', 'FAIL'),
                test('y', 'UNEXPECTEDPASS'),
                test('z', 'ERROR', duration=None),
                test('w', 'NEWRESULT'),
            ]
        )
        self.assertEqual(s['outcome'], 'fail')
        self.assertEqual(s['problems'], ['4 tests failed', '1 test timed out'])
        self.assertEqual(s['counts']['fail'], 4)
        self.assertEqual(s['counts']['timeout'], 1)
        self.assertEqual(
            [(t['status'], t['reason']) for t in s['tests']],
            [
                ('timeout', 'TIMEOUT'),
                ('fail', 'FAIL'),
                ('fail', 'UNEXPECTEDPASS'),
                ('fail', 'ERROR'),
                ('fail', "unknown result 'NEWRESULT'"),
            ],
        )
        self.assertNotIn('duration', s['tests'][3])

    def test_empty(self) -> None:
        s = meson.summarize([])
        self.assertEqual(
            (s['outcome'], s['problems']), ('fail', ['no test results'])
        )

    def test_names(self) -> None:
        self.assertEqual(
            meson.display_name('nvme-cli:mock / nvme-cli - print'),
            'mock / nvme-cli - print',
        )
        # the older format of meson: the project is in the name
        self.assertEqual(
            meson.display_name('mock - nvme-cli:nvme-cli - print'),
            'mock - nvme-cli:nvme-cli - print',
        )

    def test_output(self) -> None:
        t = test('a', 'FAIL', stdout='out\n', stderr='err\n')
        self.assertEqual(meson.output(t), 'out\nerr\n')
        t = test('a', 'FAIL', stdout='x' * 10 + 'the end')
        self.assertEqual(meson.output(t, limit=7), '[truncated]\nthe end')
        self.assertEqual(meson.output(test('a', 'FAIL')), '')


if __name__ == '__main__':
    unittest.main()
