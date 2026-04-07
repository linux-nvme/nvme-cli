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
import os
import sys
import threading
import traceback
import unittest


class DiagnosticCapture(io.TextIOBase):
    """Capture writes and re-emit them as TAP diagnostic lines (# ...)."""

    def __init__(self, stream: io.TextIOBase) -> None:
        self._real = stream
        self._buf = ''

    def write(self, text: str) -> int:
        self._buf += text
        while '\n' in self._buf:
            line, self._buf = self._buf.split('\n', 1)
            self._real.write('# {}\n'.format(line))
        self._real.flush()
        return len(text)

    def flush(self) -> None:
        if self._buf:
            self._real.write('# {}\n'.format(self._buf))
            self._buf = ''
        self._real.flush()


class FDCapture:
    """Redirect a file descriptor at the OS level and re-emit captured output
    as TAP diagnostic lines.  This intercepts writes from subprocesses which
    bypass the Python-level sys.stderr redirect."""

    def __init__(self, fd: int, real_stdout: io.TextIOBase) -> None:
        self._fd = fd
        self._real = real_stdout
        self._saved_fd = os.dup(fd)
        r_fd, w_fd = os.pipe()
        os.dup2(w_fd, fd)
        os.close(w_fd)
        self._thread = threading.Thread(target=self._reader, args=(r_fd,),
                                        daemon=True)
        # daemon=True: if restore() is somehow never called (e.g. os._exit()),
        # the process can still exit rather than hang on a blocking read.
        self._thread.start()

    def _reader(self, r_fd: int) -> None:
        buf = b''
        # Open unbuffered (bufsize=0) so bytes are delivered to the reader
        # as soon as they are written, without waiting for a buffer to fill.
        with open(r_fd, 'rb', 0) as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                buf += chunk
                while b'\n' in buf:
                    line, buf = buf.split(b'\n', 1)
                    self._real.write(
                        '# {}\n'.format(line.decode('utf-8', errors='replace')))
                    self._real.flush()
        if buf:
            self._real.write(
                '# {}\n'.format(buf.decode('utf-8', errors='replace')))
            self._real.flush()

    def restore(self) -> None:
        """Restore the original file descriptor and wait for the reader to drain."""
        os.dup2(self._saved_fd, self._fd)
        os.close(self._saved_fd)
        self._thread.join()


class TAPTestResult(unittest.TestResult):
    """Collect unittest results and render them as TAP version 13."""

    def __init__(self, stream: io.TextIOBase) -> None:
        super().__init__()
        self._stream = stream
        self._test_count = 0

    def _description(self, test: unittest.TestCase) -> str:
        return '{} ({})'.format(test._testMethodName, type(test).__name__)

    def addSuccess(self, test: unittest.TestCase) -> None:
        super().addSuccess(test)
        self._test_count += 1
        self._stream.write('ok {} - {}\n'.format(
            self._test_count, self._description(test)))
        self._stream.flush()

    def addError(self, test: unittest.TestCase, err: object) -> None:
        super().addError(test, err)
        self._test_count += 1
        self._stream.write('not ok {} - {}\n'.format(
            self._test_count, self._description(test)))
        for line in traceback.format_exception(*err):  # type: ignore[misc]
            for subline in line.splitlines():
                self._stream.write('# {}\n'.format(subline))
        self._stream.flush()

    def addFailure(self, test: unittest.TestCase, err: object) -> None:
        super().addFailure(test, err)
        self._test_count += 1
        self._stream.write('not ok {} - {}\n'.format(
            self._test_count, self._description(test)))
        for line in traceback.format_exception(*err):  # type: ignore[misc]
            for subline in line.splitlines():
                self._stream.write('# {}\n'.format(subline))
        self._stream.flush()

    def addSkip(self, test: unittest.TestCase, reason: str) -> None:
        super().addSkip(test, reason)
        self._test_count += 1
        self._stream.write('ok {} - {} # SKIP {}\n'.format(
            self._test_count, self._description(test), reason))
        self._stream.flush()

    def addExpectedFailure(self, test: unittest.TestCase, err: object) -> None:
        super().addExpectedFailure(test, err)
        self._test_count += 1
        self._stream.write('ok {} - {} # TODO expected failure\n'.format(
            self._test_count, self._description(test)))
        self._stream.flush()

    def addUnexpectedSuccess(self, test: unittest.TestCase) -> None:
        super().addUnexpectedSuccess(test)
        self._test_count += 1
        self._stream.write('not ok {} - {} # TODO unexpected success\n'.format(
            self._test_count, self._description(test)))
        self._stream.flush()


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

    # Redirect stdout and stderr so any print()/sys.stderr.write() calls from
    # setUp/tearDown/tests are re-emitted as TAP diagnostic lines and do not
    # break the TAP stream.
    sys.stdout = DiagnosticCapture(real_stdout)  # type: ignore[assignment]
    sys.stderr = DiagnosticCapture(real_stdout)  # type: ignore[assignment]
    # Also redirect fd 2 at the OS level so that subprocess stderr (which
    # inherits the raw file descriptor and bypasses sys.stderr) is captured.
    stderr_fd_capture = FDCapture(2, real_stdout)
    try:
        result = TAPTestResult(real_stdout)
        suite.run(result)
    finally:
        sys.stdout.flush()
        sys.stdout = real_stdout
        sys.stderr.flush()
        sys.stderr = real_stderr
        stderr_fd_capture.restore()

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
