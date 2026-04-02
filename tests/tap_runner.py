#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""
TAP (Test Anything Protocol) version 13 runner for nvme-cli Python tests.

Wraps Python's unittest framework and emits TAP output so that meson can
parse individual subtest results when protocol: 'tap' is set in meson.build.
"""

import argparse
import importlib
import sys
import traceback
import unittest


class TAPTestResult(unittest.TestResult):
    """Collect unittest results and render them as TAP version 13."""

    def __init__(self) -> None:
        super().__init__()
        self._test_count = 0
        self._lines: list[str] = []

    def _description(self, test: unittest.TestCase) -> str:
        return '{} ({})'.format(test._testMethodName, type(test).__name__)

    def addSuccess(self, test: unittest.TestCase) -> None:
        super().addSuccess(test)
        self._test_count += 1
        self._lines.append('ok {} - {}\n'.format(
            self._test_count, self._description(test)))

    def addError(self, test: unittest.TestCase, err: object) -> None:
        super().addError(test, err)
        self._test_count += 1
        self._lines.append('not ok {} - {}\n'.format(
            self._test_count, self._description(test)))
        for line in traceback.format_exception(*err):  # type: ignore[misc]
            for subline in line.splitlines():
                self._lines.append('# {}\n'.format(subline))

    def addFailure(self, test: unittest.TestCase, err: object) -> None:
        super().addFailure(test, err)
        self._test_count += 1
        self._lines.append('not ok {} - {}\n'.format(
            self._test_count, self._description(test)))
        for line in traceback.format_exception(*err):  # type: ignore[misc]
            for subline in line.splitlines():
                self._lines.append('# {}\n'.format(subline))

    def addSkip(self, test: unittest.TestCase, reason: str) -> None:
        super().addSkip(test, reason)
        self._test_count += 1
        self._lines.append('ok {} - {} # SKIP {}\n'.format(
            self._test_count, self._description(test), reason))

    def addExpectedFailure(self, test: unittest.TestCase, err: object) -> None:
        super().addExpectedFailure(test, err)
        self._test_count += 1
        self._lines.append('ok {} - {} # TODO expected failure\n'.format(
            self._test_count, self._description(test)))

    def addUnexpectedSuccess(self, test: unittest.TestCase) -> None:
        super().addUnexpectedSuccess(test)
        self._test_count += 1
        self._lines.append('not ok {} - {} # TODO unexpected success\n'.format(
            self._test_count, self._description(test)))

    def print_tap(self, stream: object = sys.stdout) -> None:
        stream.write('TAP version 13\n')  # type: ignore[union-attr]
        stream.write('1..{}\n'.format(self._test_count))  # type: ignore[union-attr]
        for line in self._lines:
            stream.write(line)  # type: ignore[union-attr]
        stream.flush()  # type: ignore[union-attr]


def run_tests(test_module_name: str, start_dir: str | None = None) -> bool:
    if start_dir:
        sys.path.insert(0, start_dir)

    module = importlib.import_module(test_module_name)

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(module)

    result = TAPTestResult()
    suite.run(result)
    result.print_tap()
    return result.wasSuccessful()


def main() -> None:
    parser = argparse.ArgumentParser(
        description='TAP test runner for nvme-cli tests')
    parser.add_argument('test_module', help='Test module name to run')
    parser.add_argument('--start-dir',
                        help='Directory to prepend to sys.path for imports',
                        default=None)
    args = parser.parse_args()

    success = run_tests(args.test_module, args.start_dir)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
