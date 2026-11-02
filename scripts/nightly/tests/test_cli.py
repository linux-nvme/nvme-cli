# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for the command line, from the issue list to the page."""

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

from nvme_nightly import cli


def run(*argv: str) -> int:
    with (
        contextlib.redirect_stderr(io.StringIO()),
        contextlib.redirect_stdout(io.StringIO()),
    ):
        return cli.main(list(argv))


class EndToEnd(unittest.TestCase):
    def test_night(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / 'in.txt').write_text(
                'ignore nvme/004:tr=rdma https://e.org/issues/1\n'
                'exclude nvme/039 https://e.org/issues/2\n'
                'ignore nvme/004;reboot https://e.org/issues/3\n',
                encoding='utf-8',
            )
            self.assertEqual(
                run(
                    'known-failures',
                    '--file',
                    str(d / 'in.txt'),
                    '-o',
                    str(d / 'kf.txt'),
                    '--config',
                    str(d / 'cfg'),
                ),
                0,
            )
            self.assertEqual(
                (d / 'cfg').read_text(encoding='utf-8'),
                'IGNORE_FAILURE+=(nvme/004:tr=rdma)\nEXCLUDE+=(nvme/039)\n',
            )

            res = d / 'results'
            for config, status in (
                ('nodev_tr_rdma', 'fail'),
                ('nodev_tr_tcp', 'pass'),
            ):
                (res / config / 'nvme').mkdir(parents=True)
                (res / config / 'nvme' / '004').write_text(
                    f'status\t{status}\n', encoding='utf-8'
                )
            args = [
                'blktests-summary',
                str(res),
                '--known-failures',
                str(d / 'kf.txt'),
                '--check-status',
                '1',
                '--meta',
                'run_id=7',
                '--meta',
                'date=2026-11-02 01:00',
                '-o',
                str(d / 's.json'),
            ]
            self.assertEqual(run(*args), 0)
            s = json.loads((d / 's.json').read_text(encoding='utf-8'))
            self.assertEqual((s['run_id'], s['outcome']), ('7', 'pass'))

            # the same run without the list fails
            self.assertEqual(
                run('blktests-summary', str(res), '--check-status', '1'), 1
            )

            if importlib.util.find_spec('jinja2') is None:
                return
            out = d / 'site'
            for _ in range(2):
                self.assertEqual(
                    run(
                        'site',
                        '-o',
                        str(out),
                        '--summary',
                        str(d / 's.json'),
                        '--history',
                        str(out / 'history.json'),
                    ),
                    0,
                )
            history = json.loads(
                (out / 'history.json').read_text(encoding='utf-8')
            )
            self.assertEqual([h['run_id'] for h in history], ['7'])

    def test_bad_meta(self) -> None:
        with self.assertRaises(SystemExit):
            run('blktests-summary', '.', '--meta', 'novalue')


if __name__ == '__main__':
    unittest.main()
