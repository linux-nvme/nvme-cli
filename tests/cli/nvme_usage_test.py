#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for the help and the usage errors of the commands. They need no
device: the parsing stops before one would be opened.

Usage: python3 nvme_usage_test.py <path-to-nvme-binary>
"""
import subprocess
import sys
import unittest

_NVME_BIN = sys.argv[1] if len(sys.argv) > 1 else 'nvme'


def run(*args):
    return subprocess.run([_NVME_BIN] + list(args), capture_output=True,
                          text=True, stdin=subprocess.DEVNULL, check=False)


class HelpTest(unittest.TestCase):

    def test_help_on_stdout_and_success(self):
        for opt in ('--help', '-h', '-?'):
            with self.subTest(opt=opt):
                result = run('id', 'ctrl', opt)
                self.assertEqual(result.returncode, 0)
                self.assertIn('Usage: nvme id ctrl <device>', result.stdout)
                self.assertNotIn('Usage:', result.stderr)

    def test_usage_error_on_stderr_and_failure(self):
        result = run('id', 'ctrl', '--bogus')
        self.assertEqual(result.returncode, 1)
        self.assertIn("unrecognized option '--bogus'", result.stderr)
        self.assertIn('Usage: nvme id ctrl <device>', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_no_escape_sequences_when_not_a_terminal(self):
        result = run('id', 'ctrl', '--help')
        self.assertNotIn('\033[', result.stdout)


class OperandTest(unittest.TestCase):
    """A command takes a device, an optional one or none. A missing
    device and extra operands are usage errors."""

    def assert_usage_error(self, result, message):
        self.assertEqual(result.returncode, 1)
        self.assertIn(message, result.stderr)
        self.assertIn('Usage:', result.stderr)

    def test_missing_device(self):
        self.assert_usage_error(run('id', 'ctrl'), 'missing <device>')

    def test_extra_operand(self):
        self.assert_usage_error(run('id', 'ctrl', '/dev/nvme0', 'extra'),
                                "unexpected argument 'extra'")

    def test_no_device_command(self):
        result = run('list', '--help')
        self.assertIn('Usage: nvme list [OPTIONS]', result.stdout)
        self.assert_usage_error(run('list', 'extra'),
                                "unexpected argument 'extra'")

    def test_optional_device_command(self):
        result = run('list-subsys', '--help')
        self.assertIn('Usage: nvme list-subsys [<device>] [OPTIONS]',
                      result.stdout)
        self.assert_usage_error(run('list-subsys', 'nvme0', 'extra'),
                                "unexpected argument 'extra'")


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]])
