# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for nvme-fuzz run, with a stand-in for a libFuzzer binary."""

import argparse
import os
import signal
import stat
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from nvme_fuzz import run, targets

# What a libFuzzer binary does, as far as nvme-fuzz run cares: FAKE_MODE
# says whether it finds something, ignores SIGTERM or just runs
FAKE = f"""#!{sys.executable}
import os, signal, sys, time
args = [a for a in sys.argv[1:] if a.startswith('-')]
prefix = [a.split('=', 1)[1] for a in args if 'artifact_prefix' in a]
mode = os.environ.get('FAKE_MODE', 'sleep')
os.mkdir('fuzz-device-abcdef')
if mode == 'crash':
    open(prefix[0] + 'crash-1234', 'wb').write(b'x')
    open('fuzz-0.log', 'w').write('SUMMARY: AddressSanitizer: x\\n')
    sys.exit(1)
if mode == 'ignore-term':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(60)
"""


@unittest.skipIf(
    sys.platform == 'win32', 'nvme-fuzz run needs POSIX process groups'
)
class RunTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.build = Path(self.tmp.name) / 'build'
        binary = self.build / 'tests' / 'fuzz' / 'fuzz-device'
        binary.parent.mkdir(parents=True)
        binary.write_text(FAKE)
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
        self.results = Path(self.tmp.name) / 'results'

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run(self, mode: str, seconds: int = 1) -> int:
        args = argparse.Namespace(
            build_dir=self.build,
            results=self.results,
            seconds=seconds,
            jobs=1,
            targets=[targets.TARGETS['device']],
        )
        with mock.patch.dict(os.environ, {'FAKE_MODE': mode}):
            return run.main(args)

    def _summary(self) -> list[str]:
        return (self.results / 'summary.txt').read_text().splitlines()

    def test_finding(self) -> None:
        self.assertEqual(self._run('crash'), 1)
        summary = self._summary()
        self.assertEqual(summary[0], 'fuzz-device: 1 findings, exit status 1')
        self.assertIn('SUMMARY: AddressSanitizer: x', summary)
        self.assertTrue(summary[-1].endswith('artifacts/device/crash-1234'))
        # the seeds are in the corpus, the leftovers of jobs gone
        self.assertTrue(any((self.results / 'corpus' / 'device').iterdir()))
        logs = self.results / 'logs' / 'device'
        self.assertFalse(list(logs.glob('fuzz-device-*')))

    def test_deadline(self) -> None:
        with mock.patch.object(run, 'DEADLINE_EXTRA', 0):
            self.assertEqual(self._run('sleep'), 0)
        self.assertEqual(self._summary(), ['fuzz-device: no finding in 1s'])

    def test_kill_after_grace(self) -> None:
        with (
            mock.patch.object(run, 'DEADLINE_EXTRA', 0),
            mock.patch.object(run, 'GRACE_SECONDS', 1),
        ):
            start = time.time()
            self.assertEqual(self._run('ignore-term'), 0)
        self.assertLess(time.time() - start, 30)

    def test_interrupt(self) -> None:
        def ctrl_c() -> None:
            time.sleep(1)
            os.kill(os.getpid(), signal.SIGINT)

        threading.Thread(target=ctrl_c).start()
        start = time.time()
        self.assertEqual(self._run('sleep', seconds=600), 130)
        self.assertLess(time.time() - start, 30)
        self.assertEqual(
            self._summary(), ['fuzz-device: no finding until interrupted']
        )


if __name__ == '__main__':
    unittest.main()
