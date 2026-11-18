#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
"""Check the index of the top-level commands of the plugins.

A plugin lists its top-level commands in plugin_commands and their aliases
in plugin_command_aliases (plugins/meson.build). nvme loads the module of a
top-level command it doesn't have from this index, so the index has to
list exactly the commands each module adds.

The commands come from `nvme utils dump-command-metadata`. With modules,
the test runs it with only the utils module, and with the utils module and
one more: the commands it adds are the ones of that module.

Usage: test_command_index.py <nvme-binary> <module-dir>|- [<entry>...]

An entry is "<plugin>:<command>[=<alias>]", "-" means no modules.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

if len(sys.argv) < 3:
    print("usage: %s <nvme-binary> <module-dir>|- [<entry>...]" %
          sys.argv[0])
    sys.exit(77)

NVME_BIN = sys.argv[1]
MODULE_DIR = None if sys.argv[2] == '-' else os.path.abspath(sys.argv[2])
MODULE_SUFFIX = '.so'
METADATA_MODULE = 'cmds-utils'


def parse_index(entries):
    """{command: (plugin, alias)} of the entries, and the duplicates."""
    index = {}
    dups = []
    for entry in entries:
        plugin, cmd = entry.split(':', 1)
        cmd, _, alias = cmd.partition('=')
        if cmd in index:
            dups.append(cmd)
        index[cmd] = (plugin, alias or None)
    return index, dups


INDEX, DUPLICATES = parse_index(sys.argv[3:])


def top_level_commands(module_dir=None):
    """{command: alias} of the top-level commands of nvme."""
    env = dict(os.environ)
    if module_dir is not None:
        env['NVME_PLUGIN_DIR'] = module_dir
        # the libraries the modules are linked to
        env['LD_LIBRARY_PATH'] = MODULE_DIR
    proc = subprocess.run([NVME_BIN, 'utils', 'dump-command-metadata'],
                          capture_output=True, text=True, encoding='utf-8',
                          env=env, check=True)
    model = json.loads(proc.stdout)
    return {c['name']: c.get('alias') for c in model['commands']}


def modules():
    """The names of the modules in MODULE_DIR."""
    return sorted(f[:-len(MODULE_SUFFIX)] for f in os.listdir(MODULE_DIR)
                  if f.endswith(MODULE_SUFFIX))


class CommandIndexTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.commands = top_level_commands()

    def test_no_duplicates(self):
        self.assertEqual(DUPLICATES, [])
        names = list(INDEX) + [a for _, a in INDEX.values() if a]
        self.assertEqual(sorted(set(names)), sorted(names))

    def test_index_commands_exist(self):
        """Every command of the index is a command of nvme."""
        for cmd, (plugin, alias) in INDEX.items():
            with self.subTest(command=cmd, plugin=plugin):
                self.assertIn(cmd, self.commands)
                self.assertEqual(self.commands[cmd], alias)

    @unittest.skipIf(MODULE_DIR is None, 'built without modules')
    def test_module_commands_indexed(self):
        """The commands each module adds are its commands in the index."""
        names = modules()
        self.assertIn(METADATA_MODULE, names)
        for cmd, (plugin, _) in INDEX.items():
            with self.subTest(command=cmd, plugin=plugin):
                self.assertIn(plugin, names)

        tmp = tempfile.mkdtemp()
        try:
            def link(name):
                os.symlink(os.path.join(MODULE_DIR, name + MODULE_SUFFIX),
                           os.path.join(tmp, name + MODULE_SUFFIX))

            def unlink(name):
                os.unlink(os.path.join(tmp, name + MODULE_SUFFIX))

            link(METADATA_MODULE)
            base = top_level_commands(tmp)
            for cmd, (plugin, _) in INDEX.items():
                if plugin == METADATA_MODULE:
                    with self.subTest(command=cmd, plugin=plugin):
                        self.assertIn(cmd, base)

            for name in names:
                if name == METADATA_MODULE:
                    continue
                link(name)
                added = set(top_level_commands(tmp)) - set(base)
                unlink(name)
                indexed = {c for c, (p, _) in INDEX.items() if p == name}
                with self.subTest(module=name):
                    self.assertEqual(sorted(added), sorted(indexed))
        finally:
            shutil.rmtree(tmp)


if __name__ == '__main__':
    unittest.main(argv=sys.argv[:1])
