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
import os
import subprocess
import sys
import tempfile
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
        self.assertIn("id ctrl: unrecognized option '--bogus'", result.stderr)
        self.assertEqual(result.stdout, '')

    def test_usage_error_shows_synopsis_and_hint(self):
        # the error must not drown in the full help
        for args in (('id', 'ctrl', '--bogus'),
                     ('id', 'ctrl'),
                     ('id', 'ns', '/dev/nvme0', '-n', '1x')):
            with self.subTest(args=args):
                result = run(*args)
                self.assertEqual(result.returncode, 1)
                self.assertIn('Usage: nvme id ', result.stderr)
                self.assertRegex(result.stderr,
                                 r"Try 'nvme id c?\w+ --help' for more "
                                 r"information\.")
                self.assertNotIn('Options:', result.stderr)

    def test_open_failure_is_no_usage_error(self):
        result = run('id', 'ns', '/dev/nvme-does-not-exist')
        self.assertEqual(result.returncode, 1)
        self.assertIn('/dev/nvme-does-not-exist', result.stderr)
        self.assertNotIn('Usage:', result.stderr)
        result = run('id', 'ns', '/dev/nvme-does-not-exist', '-o', 'json')
        self.assertNotIn('Usage:', result.stdout + result.stderr)

    def test_value_error_names_the_spelling(self):
        result = run('id', 'ns', '/dev/nvme0', '-n', '1x')
        self.assertIn("id ns: invalid value '1x' for -n: expected a number "
                      "from 0 to 4294967295 or one of: all, -1",
                      result.stderr)
        result = run('id', 'ns', '/dev/nvme0', '--namespace-id=1x')
        self.assertIn("invalid value '1x' for --namespace-id",
                      result.stderr)

    def test_no_escape_sequences_when_not_a_terminal(self):
        for args in (('id', 'ctrl', '--help'), ('help',), ('id', 'help')):
            with self.subTest(args=args):
                result = run(*args)
                self.assertNotIn('\033[', result.stdout + result.stderr)


class DeprecatedOptionTest(unittest.TestCase):
    """--human-readable and -H still raise the verbose level, with a
    warning which names the replacement."""

    def test_human_readable(self):
        for opt in ('-H', '--human-readable'):
            with self.subTest(opt=opt):
                result = run('list', opt)
                self.assertIn(f"WARNING: '{opt}' is deprecated", result.stderr)
                self.assertIn("use '--verbose/-v' instead", result.stderr)

    def test_old_option_name(self):
        # discover takes the old spelling of --fast-io-fail-tmo
        if run('discover', '--help').returncode:
            self.skipTest('no fabrics commands in this build')
        result = run('discover', '--fast_io_fail_tmo=1', '--help')
        self.assertEqual(result.returncode, 0)
        self.assertIn("WARNING: '--fast_io_fail_tmo' is deprecated",
                      result.stderr)
        self.assertIn("use '--fast-io-fail-tmo' instead", result.stderr)
        self.assertNotIn('fast_io_fail_tmo', result.stdout)

    def test_warns_once(self):
        result = run('list', '-HH')
        self.assertEqual(result.stderr.count('WARNING'), 1)

    def test_verbose_does_not_warn(self):
        self.assertNotIn('WARNING', run('list', '-v').stderr)


class SpecialValuesTest(unittest.TestCase):

    def test_help_lists_the_names(self):
        result = run('id', 'ns', '--help')
        self.assertIn('Names: all, -1', result.stdout)
        self.assertIn('Names: infinite, -1', result.stdout)


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

    def test_deprecated_command_which_translates(self):
        # gen-dhchap-key rebuilds the arguments for its replacement
        if run('gen-dhchap-key', '--help').returncode:
            self.skipTest('no deprecated fabrics commands in this build')
        self.assert_usage_error(run('gen-dhchap-key', 'extra'),
                                "unexpected argument 'extra'")
        self.assert_usage_error(run('check-dhchap-key', 'extra'),
                                "unexpected argument 'extra'")
        self.assert_usage_error(run('tls-key', '--export', 'extra'),
                                "unexpected argument 'extra'")

    def test_tls_key(self):
        # tls-key picks the command which replaces it from its options
        if run('gen-dhchap-key', '--help').returncode:
            self.skipTest('no deprecated fabrics commands in this build')
        result = run('tls-key', '--help')
        self.assertIn('Usage: nvme tls-key [OPTIONS]', result.stdout)
        self.assertIn('--revoke', result.stdout)
        result = run('tls-key', '--import', '--export')
        self.assertEqual(result.returncode, 1)
        self.assertIn('only one of --import, --export, or --revoke',
                      result.stderr)

    def test_optional_device_command(self):
        result = run('list-subsys', '--help')
        self.assertIn('Usage: nvme list-subsys [<device>] [OPTIONS]',
                      result.stdout)
        self.assert_usage_error(run('list-subsys', 'nvme0', 'extra'),
                                "unexpected argument 'extra'")


class HelpCommandTest(unittest.TestCase):
    """'nvme help <command>' finds the command like the dispatcher does and
    shows its man page. A fake man prints which page it was asked for."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        man = os.path.join(self.dir.name, 'man')
        with open(man, 'w', encoding='utf-8') as f:
            f.write('#!/bin/sh\necho "MAN: $1"\n')
        os.chmod(man, 0o755)
        self.env = dict(os.environ)
        self.env['PATH'] = self.dir.name + os.pathsep + self.env['PATH']

    def tearDown(self):
        self.dir.cleanup()

    def man_page(self, *args):
        result = subprocess.run([_NVME_BIN] + list(args), capture_output=True,
                                text=True, stdin=subprocess.DEVNULL,
                                env=self.env, check=False)
        return result.stdout.strip()

    def test_builtin_command(self):
        self.assertEqual(self.man_page('help', 'list-subsys'),
                         'MAN: nvme-list-subsys')

    def test_unique_prefix(self):
        self.assertEqual(self.man_page('help', 'list-sub'),
                         'MAN: nvme-list-subsys')

    def test_plugin_command(self):
        self.assertEqual(self.man_page('help', 'id', 'ctrl'),
                         'MAN: nvme-id-ctrl')
        self.assertEqual(self.man_page('--help', 'id', 'ctrl'),
                         'MAN: nvme-id-ctrl')


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]])
