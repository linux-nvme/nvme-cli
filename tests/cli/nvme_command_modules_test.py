#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
"""Tests for the top-level commands of the plugin modules.

nvme loads the module of a top-level command it doesn't have from the
command index. The deprecated commands are such commands: "nvme smart-log"
loads cmds-deprecated.so, which runs "nvme log smart" from cmds-log.so.

Each test runs nvme with NVME_PLUGIN_DIR on a directory with links to some
of the modules, and a file which is no module. nvme reports that file when
it loads all modules, so a test sees when nvme loaded more than it needed.

Usage: python3 nvme_command_modules_test.py <nvme-binary> <module-dir>
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

if len(sys.argv) < 3:
    print("usage: %s <nvme-binary> <module-dir>" % sys.argv[0])
    sys.exit(77)

NVME_BIN = sys.argv[1]
MODULE_DIR = os.path.abspath(sys.argv[2])
LOAD_ERROR = 'cannot load plugin'


class CommandModulesTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        with open(os.path.join(self.dir, 'not-a-module.so'), 'w',
                  encoding='utf-8') as f:
            f.write('not a module\n')

    def tearDown(self):
        shutil.rmtree(self.dir)

    def modules(self, *names):
        for name in names:
            os.symlink(os.path.join(MODULE_DIR, name + '.so'),
                       os.path.join(self.dir, name + '.so'))

    def nvme(self, *args):
        env = dict(os.environ, NVME_PLUGIN_DIR=self.dir)
        return subprocess.run([NVME_BIN] + list(args), capture_output=True,
                              text=True, encoding='utf-8',
                              stdin=subprocess.DEVNULL, env=env,
                              check=False)

    def test_all_modules_report_the_file(self):
        """The help loads all modules, and reports the file."""
        r = self.nvme('help')
        self.assertIn(LOAD_ERROR, r.stderr)
        self.assertIn('not-a-module.so', r.stderr)

    def test_command_loads_only_its_module(self):
        self.modules('cmds-deprecated', 'cmds-log')
        r = self.nvme('smart-log', '--help')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("'smart-log' is deprecated", r.stderr)
        self.assertIn('Usage: nvme log smart <device>', r.stdout)
        self.assertNotIn(LOAD_ERROR, r.stderr)

    def test_alias(self):
        self.modules('cmds-deprecated', 'cmds-fw')
        r = self.nvme('fw-activate', '--help')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("'fw-commit' is deprecated", r.stderr)
        self.assertIn('Usage: nvme fw commit <device>', r.stdout)
        self.assertNotIn(LOAD_ERROR, r.stderr)

    def test_prefix(self):
        self.modules('cmds-deprecated', 'cmds-log')
        r = self.nvme('smart-lo', '--help')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('Usage: nvme log smart <device>', r.stdout)
        self.assertNotIn(LOAD_ERROR, r.stderr)

    def test_ambiguous_prefix_loads_no_command_module(self):
        """"ns" starts ns-rescan and the deprecated ns-descs: it is the
        plugin ns."""
        self.modules('cmds-ns')
        r = self.nvme('ns', 'create', '--help')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('Usage: nvme ns create <device>', r.stdout)
        self.assertNotIn(LOAD_ERROR, r.stderr)

    def test_unknown_command(self):
        r = self.nvme('zzz')
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, '')
        self.assertIn("invalid sub-command 'zzz'", r.stderr)
        self.assertIn("See 'nvme --help' for the commands.", r.stderr)

    def test_module_not_installed(self):
        self.modules('cmds-log')
        r = self.nvme('smart-log', '/dev/nvme0')
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, '')
        self.assertIn('command smart-log not installed: plugin cmds-deprecated '
                      'has no module in ' + self.dir, r.stderr)
        self.assertNotIn(LOAD_ERROR, r.stderr)


if __name__ == '__main__':
    unittest.main(argv=sys.argv[:1])
