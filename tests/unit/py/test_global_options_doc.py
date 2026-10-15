#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
"""Check that the documentation lists every global option.

The global options are one table in src/global-options.c. Every command
accepts them, and the visible ones are also the keys of nvme-cli.conf. This
test takes them from `nvme utils dump-command-metadata` and checks that
Documentation/global-options.txt describes each of them and that
Documentation/nvme-cli.conf.txt lists each as a key.

Usage: test_global_options_doc.py <nvme-binary> <documentation-dir>
"""
import json
import os
import re
import subprocess
import sys
import unittest

if len(sys.argv) < 3:
    print("usage: %s <nvme-binary> <documentation-dir>" % sys.argv[0])
    sys.exit(77)

NVME_BIN = sys.argv[1]
DOC_DIR = sys.argv[2]


def global_options():
    """The long names of the visible global options."""
    out = subprocess.run([NVME_BIN, 'utils', 'dump-command-metadata'],
                         capture_output=True, text=True, check=True).stdout
    model = json.loads(out)
    for cmd in model['commands']:
        opts = [o for o in cmd.get('options', []) if o.get('global')]
        if opts:
            return {o['long'] for o in opts if not o.get('hidden')}
    raise AssertionError('no command with global options')


class GlobalOptionsDocTest(unittest.TestCase):

    def setUp(self):
        self.options = global_options()

    def test_global_options_txt(self):
        with open(os.path.join(DOC_DIR, 'global-options.txt')) as f:
            doc = f.read()
        for name in sorted(self.options):
            with self.subTest(option=name):
                self.assertRegex(doc, rf'(?m)^--{re.escape(name)}\b')

    def test_nvme_cli_conf_keys(self):
        with open(os.path.join(DOC_DIR, 'nvme-cli.conf.txt')) as f:
            doc = f.read()
        keys = re.search(r'^KEYS\n-+\n(.*?)\n[A-Z ]+\n-+\n', doc,
                         re.M | re.S)
        self.assertIsNotNone(keys, 'no KEYS section')
        listed = set(re.findall(r'[a-z][a-z-]+',
                                keys.group(1).split('\n\n')[1]))
        self.assertEqual(listed, self.options)


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]])
