#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
"""Check that the option names of a command don't collide.

The global options (src/global-options.c) are looked up before the options
of a command, so a command option with the long or short name of a global
option could never be given. -h and -? always ask for the help. And of two
options of a command with the same name only the first one is reachable.

This test takes the options of every command from
`nvme utils dump-command-metadata` and checks that a command option uses
neither the name of a global option nor -h or -?, and that no two options
of a command share a name. A hidden option may share the name of a visible
one: it is the old spelling of that option.

Usage: test_option_names.py <nvme-binary>
"""
import collections
import json
import subprocess
import sys
import unittest

if len(sys.argv) < 2:
    print("usage: %s <nvme-binary>" % sys.argv[0])
    sys.exit(77)

NVME_BIN = sys.argv[1]
HELP_SHORT = {'h', '?'}


def commands():
    """(name, options) of every command, the global options left out, and
    the global options."""
    out = subprocess.run([NVME_BIN, 'utils', 'dump-command-metadata'],
                         capture_output=True, text=True, check=True).stdout
    model = json.loads(out)
    cmds = [(c['name'], c) for c in model['commands']]
    for plugin in model['plugins']:
        cmds += [(plugin['name'] + ' ' + c['name'], c)
                 for c in plugin['commands']]

    global_opts = None
    result = []
    for name, cmd in cmds:
        opts = cmd.get('options', [])
        if global_opts is None and any(o.get('global') for o in opts):
            global_opts = [o for o in opts if o.get('global')]
        result.append((name, [o for o in opts if not o.get('global')]))
    if not global_opts:
        raise AssertionError('no command with global options')
    return result, global_opts


class OptionNamesTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.commands, global_opts = commands()
        cls.global_long = {o['long'] for o in global_opts}
        cls.global_short = {o['short'] for o in global_opts
                            if o.get('short')}

    def test_no_global_option_name(self):
        for name, opts in self.commands:
            for o in opts:
                with self.subTest(command=name, option=o['long']):
                    self.assertNotIn(o['long'], self.global_long)
                    self.assertNotIn(o.get('short'), self.global_short)

    def test_no_help_short_name(self):
        for name, opts in self.commands:
            for o in opts:
                with self.subTest(command=name, option=o['long']):
                    self.assertNotIn(o.get('short'), HELP_SHORT)

    def test_unique_names(self):
        for name, opts in self.commands:
            visible = [o for o in opts if not o.get('hidden')]
            for key in ('long', 'short'):
                counts = collections.Counter(o[key] for o in visible
                                             if o.get(key))
                for value, n in counts.items():
                    with self.subTest(command=name, name=value):
                        self.assertEqual(n, 1)
            # an old spelling must not hide a visible option either
            names = {o['long'] for o in visible}
            for o in opts:
                if o.get('hidden'):
                    with self.subTest(command=name, option=o['long']):
                        self.assertNotIn(o['long'], names)


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]])
