#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for the sandboxed parsers of nvme-cli (shared/sandbox-util.c).

NVME_SANDBOX=1 parses the options, global options and --set-options in a
sandboxed child process, NVME_SANDBOX=0 in nvme-cli itself. The results
must not differ.

Usage: python3 nvme_sandbox_test.py <path-to-nvme-binary>
"""
import os
import shlex
import subprocess
import sys
import tempfile
import unittest

_NVME_BIN = sys.argv[1] \
    if len(sys.argv) > 1 and not sys.argv[1].startswith('-') \
    else 'nvme'

# Invocations which parse options without a device.
_CASES = [
    ['version'],
    ['--version'],
    ['list', '-o', 'json'],
    ['list', '--output-format=json', '-v'],
    ['-o', 'json', 'list'],
    ['--out=json', 'list'],
    ['list', '--bogus'],
    ['list', '-o'],
    ['list', '--timeout=nope'],
    ['list', '-h'],
    ['list-subsys', '--verbose', '--verbose'],
    ['id-ctrl'],
    ['id-ctrl', '--vendor-specific', '--raw-binary'],
    ['zzz'],
    ['list', '--set-options', 'bogus=1'],
    ['list', '--set-options', 'force-4k'],
    ['list', '--set-options', ',force-4k=1,,mi-probe-enabled=true,'],
    ['list', '--set-options', 'test-base-dir=/etc'],
    ['list', '--timeout=infinite'],
    ['list', '--timeout=010'],
    ['list', 'operand'],
    ['list', '--', '-v'],
    ['list-subsys', 'dev1', 'dev2'],
    ['-v', '--dry-run', 'list-subsys', '-v'],
]


class SandboxCLITest(unittest.TestCase):

    def setUp(self):
        self.sysfs = tempfile.mkdtemp(prefix='nvme-sandbox-test-', dir='/tmp')

    def tearDown(self):
        os.rmdir(self.sysfs)

    def nvme(self, sandbox, args, limit_procs=False):
        env = dict(os.environ, NVME_SANDBOX=sandbox, LC_ALL='C')
        cmd = [_NVME_BIN, '--set-options',
               f'test-sysfs-dir={self.sysfs}'] + args
        if limit_procs:
            # The shell is forked already; nvme then cannot fork.
            cmd = ['/bin/sh', '-c',
                   'ulimit -u 1 && exec ' + shlex.join(cmd)]
        return subprocess.run(cmd, env=env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=60,
                              check=False)

    def test_same_results(self):
        """The sandbox changes nothing nvme-cli prints or returns."""
        for args in _CASES:
            with self.subTest(args=args):
                direct = self.nvme('0', args)
                sandboxed = self.nvme('1', args)
                self.assertEqual(sandboxed.returncode, direct.returncode)
                self.assertEqual(sandboxed.stdout, direct.stdout)
                self.assertEqual(sandboxed.stderr, direct.stderr)

    @unittest.skipIf(os.geteuid() == 0, 'process limits do not apply to root')
    def test_sandbox_forks(self):
        """With the sandbox, parsing needs a child process."""
        direct = self.nvme('0', ['list', '-o', 'json'], limit_procs=True)
        if direct.returncode != 0:
            self.skipTest('ulimit -u not supported')
        sandboxed = self.nvme('1', ['list', '-o', 'json'], limit_procs=True)
        self.assertNotEqual(sandboxed.returncode, 0)


if __name__ == '__main__':
    unittest.main(argv=sys.argv[:1])
