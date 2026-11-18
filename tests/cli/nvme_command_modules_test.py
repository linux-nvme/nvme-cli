#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
"""Tests for the top-level commands of the plugin modules.

nvme loads the module of a top-level command it doesn't have from the
command index. The deprecated commands are such commands: "nvme smart-log"
loads cmds-deprecated.so, which runs "nvme log smart" from cmds-log.so. So are the
I/O commands: "nvme read" loads cmds-io.so.

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
from pathlib import Path

if len(sys.argv) < 3:
    print("usage: %s <nvme-binary> <module-dir>" % sys.argv[0])
    sys.exit(77)

NVME_BIN = sys.argv[1]
MODULE_DIR = os.path.abspath(sys.argv[2])
LOAD_ERROR = 'cannot load plugin'
# sysfs trees captured from real systems, from the libnvme tests
SYSFS_DATA = Path(__file__).resolve().parents[2] / 'libnvme/tests/sysfs/data'


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

    def test_io_command_loads_only_its_module(self):
        self.modules('cmds-io')
        r = self.nvme('read', '--help')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('Usage: nvme read <device>', r.stdout)
        self.assertNotIn(LOAD_ERROR, r.stderr)

    def test_list_loads_only_its_module(self):
        self.modules('cmds-list')
        r = self.nvme('list', '--help')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('Usage: nvme list', r.stdout)
        self.assertNotIn(LOAD_ERROR, r.stderr)

    def test_list_module_not_installed(self):
        r = self.nvme('list')
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, '')
        self.assertIn('command list not installed: plugin cmds-list has no '
                      'module in ' + self.dir, r.stderr)

    @unittest.skipUnless(sys.platform.startswith('linux'),
                         'the sysfs tree is a Linux one')
    def test_zns_list_needs_cmds_list(self):
        """zns list prints its rows with the printer of cmds-list."""
        if not os.path.exists(os.path.join(MODULE_DIR, 'cmds-zns.so')):
            self.skipTest('nvme has no zns plugin')
        self.modules('cmds-zns', 'cmds-list')
        sysfs = os.path.join(self.dir, 'sysfs')
        os.mkdir(sysfs)
        subprocess.run(['tar', 'xJf', SYSFS_DATA / 'tree-pcie.tar.xz',
                        '-C', sysfs], check=True)
        zoned = os.path.join(sysfs, 'sys/class/nvme/nvme0/nvme0n1',
                             'queue/zoned')
        os.chmod(zoned, 0o644)
        with open(zoned, 'w', encoding='utf-8') as f:
            f.write('host-managed\n')
        r = self.nvme('--set-options', 'test-sysfs-dir=' + sysfs,
                      'zns', 'list')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.splitlines()[2].split()[:3],
                         ['nvme0n1', 'ng0n1', 'S7DFNG0W700063'])
        self.assertNotIn(LOAD_ERROR, r.stderr)

    def test_fabrics_command_loads_only_its_module(self):
        if not os.path.exists(os.path.join(MODULE_DIR, 'cmds-fabrics.so')):
            self.skipTest('nvme has no fabrics commands')
        self.modules('cmds-fabrics')
        r = self.nvme('connect-all', '--help')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('Usage: nvme connect-all', r.stdout)
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

    def test_io_module_not_installed(self):
        r = self.nvme('read', '/dev/nvme0n1')
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, '')
        self.assertIn('command read not installed: plugin cmds-io has no '
                      'module in ' + self.dir, r.stderr)
        self.assertNotIn(LOAD_ERROR, r.stderr)


if __name__ == '__main__':
    unittest.main(argv=sys.argv[:1])
