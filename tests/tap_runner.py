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
import io
import sys
import traceback
import unittest


class TAPDiagnosticStream(io.TextIOBase):
    """Wrap a stream and prefix every line with '# ' for TAP diagnostics.

    This lets print()/sys.stdout.write() calls from setUp/tearDown/tests
    appear on stdout as TAP-compliant diagnostic lines instead of being
    mixed into stderr.
    """

    def __init__(self, stream: io.TextIOBase) -> None:
        super().__init__()
        self._stream = stream
        self._pending = ''

    def write(self, s: str) -> int:
        self._pending += s
        while '\n' in self._pending:
            line, self._pending = self._pending.split('\n', 1)
            self._stream.write('# {}\n'.format(line))
        self._stream.flush()
        return len(s)

    def flush(self) -> None:
        if self._pending:
            self._stream.write('# {}\n'.format(self._pending))
            self._pending = ''
        self._stream.flush()


class TAPTestResult(unittest.TestResult):
    """Collect unittest results and render them as TAP version 13."""

    def __init__(self, stdout_stream: io.TextIOBase,
                 stderr_stream: io.TextIOBase) -> None:
        super().__init__()
        self._stdout_stream = stdout_stream
        self._stderr_stream = stderr_stream
        self._test_count = 0

    def _description(self, test: unittest.TestCase) -> str:
        return '{} ({})'.format(test._testMethodName, type(test).__name__)

    def _output_traceback(self, err):
        tb = ''.join(traceback.format_exception(*err))

        self._stderr_stream.write('  ---\n')
        self._stderr_stream.write('  traceback: |\n')

        for line in tb.splitlines():
            self._stderr_stream.write(f'    {line}\n')

        self._stderr_stream.write('  ...\n')
        self._stderr_stream.flush()

    def addSuccess(self, test: unittest.TestCase) -> None:
        super().addSuccess(test)
        self._test_count += 1
        self._stdout_stream.write('ok {} - {}\n'.format(
            self._test_count, self._description(test)))
        self._stdout_stream.flush()

    def addError(self, test: unittest.TestCase, err: object) -> None:
        super().addError(test, err)
        self._test_count += 1
        self._stdout_stream.write('not ok {} - {}\n'.format(
            self._test_count, self._description(test)))
        self._stdout_stream.flush()
        self._output_traceback(err)

    def addFailure(self, test: unittest.TestCase, err: object) -> None:
        super().addFailure(test, err)
        self._test_count += 1
        self._stdout_stream.write('not ok {} - {}\n'.format(
            self._test_count, self._description(test)))
        self._stdout_stream.flush()
        self._output_traceback(err)

    def addSkip(self, test: unittest.TestCase, reason: str) -> None:
        super().addSkip(test, reason)
        self._test_count += 1
        self._stdout_stream.write('ok {} - {} # SKIP {}\n'.format(
            self._test_count, self._description(test), reason))
        self._stdout_stream.flush()

    def addExpectedFailure(self, test: unittest.TestCase, err: object) -> None:
        super().addExpectedFailure(test, err)
        self._test_count += 1
        self._stdout_stream.write('ok {} - {} # TODO expected failure\n'.format(
            self._test_count, self._description(test)))
        self._stdout_stream.flush()

    def addUnexpectedSuccess(self, test: unittest.TestCase) -> None:
        super().addUnexpectedSuccess(test)
        self._test_count += 1
        self._stdout_stream.write('not ok {} - {} # TODO unexpected success\n'.format(
            self._test_count, self._description(test)))
        self._stdout_stream.flush()


def run_tests(test_module_name: str, start_dir: str | None = None) -> bool:
    if start_dir:
        sys.path.insert(0, start_dir)

    module = importlib.import_module(test_module_name)

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(module)

    real_stdout = sys.stdout
    real_stderr = sys.stderr
    # TAP version header and plan must appear before any test output.
    real_stdout.write('TAP version 13\n')
    real_stdout.write('1..{}\n'.format(suite.countTestCases()))
    real_stdout.flush()

    # Redirect sys.stdout to a TAP diagnostic stream so that
    # print()/sys.stdout.write() calls from setUp/tearDown/tests appear on
    # stdout as '# ...' diagnostic lines rather than being sent to stderr.
    # Error tracebacks (genuine failures) still go to stderr via stderr_stream.
    sys.stdout = TAPDiagnosticStream(real_stdout)  # type: ignore[assignment]
    try:
        result = TAPTestResult(real_stdout, real_stderr)
        suite.run(result)
    finally:
        sys.stdout = real_stdout

    return result.wasSuccessful()


def main() -> None:
    parser = argparse.ArgumentParser(
        description='TAP test runner for nvme-cli tests')
    parser.add_argument('test_module', help='Test module name to run')
    parser.add_argument('--start-dir',
                        help='Directory to prepend to sys.path for imports',
                        default=None)
    args = parser.parse_args()

    run_tests(args.test_module, args.start_dir)
    sys.exit(0)


if __name__ == '__main__':
    main()
