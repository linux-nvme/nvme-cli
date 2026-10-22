# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for running a libFuzzer binary on given inputs."""

import stat
import sys
import tempfile
import unittest
from pathlib import Path

from nvme_fuzz import libfuzzer

# Reports the data limit it runs with
FAKE = f"""#!{sys.executable}
import os, sys
sys.stderr.write(os.environ.get('FUZZ_DATA_LIMIT', 'none'))
"""


class LibFuzzerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _input(self, name: str) -> Path:
        f = self.dir / name
        f.write_bytes(b'x')
        return f

    @unittest.skipIf(
        sys.platform == 'win32', 'runs a script as the fuzz target'
    )
    def test_replay_data_limit(self) -> None:
        binary = self.dir / 'fuzz-device'
        binary.write_text(FAKE)
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
        for name, limit in (
            ('data-16384-crash-1234', '16384'),
            ('crash-1234', 'none'),
            ('regress-data-16384-x', 'none'),
        ):
            status, report = libfuzzer.replay(binary, self._input(name))
            self.assertEqual((status, report), (0, limit), name)

    def test_slow_unit(self) -> None:
        for name, slow in (
            ('slow-unit-1234', True),
            ('data-65536-slow-unit-1234', True),
            ('data-65536-crash-1234', False),
            ('crash-1234', False),
        ):
            self.assertEqual(libfuzzer.is_slow_unit(Path(name)), slow, name)

    def test_inputs_of(self) -> None:
        for name in ('crash-1', 'data-4096-slow-unit-2', 'data-4096-crash-3'):
            self._input(name)
        self.assertEqual(
            [f.name for f in libfuzzer.inputs_of([self.dir])],
            ['crash-1', 'data-4096-crash-3'],
        )


if __name__ == '__main__':
    unittest.main()
