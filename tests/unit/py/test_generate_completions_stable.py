#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
# This file is part of nvme-cli.
"""Test that generate-completions.py output is invariant to input order.

The generated completion scripts must be a pure function of the command,
plugin, and option *set* -- not the order in which those appear in
`nvme utils dump-command-metadata` output. That order tracks C registration
and declaration order, which shifts as commands and options are added, moved,
or renamed; if the generator echoed it, every such C change would churn the
committed completion files. The generator defends against this by sorting
commands, plugins, and options, so a reordered model produces byte-identical
scripts.

This feeds the committed completion fixture, shuffles its commands, plugins,
sub-commands, and each command's options under several fixed seeds, and asserts
every shell's output matches the unshuffled baseline byte-for-byte.

Usage: test_generate_completions_stable.py <generate-completions.py> <fixture.json>
"""
import copy
import json
import random
import subprocess
import sys
import unittest

SHELLS = ("bash", "zsh", "powershell")
SEEDS = (1, 42, 6789, 99999)


def shuffle_model(model, seed):
    """Return a deep copy of `model` with every command, plugin, sub-command,
    and option list reordered under a seeded RNG."""
    rng = random.Random(seed)
    m = copy.deepcopy(model)

    def shuffle_options(command):
        if "options" in command:
            rng.shuffle(command["options"])

    rng.shuffle(m.get("commands", []))
    for command in m.get("commands", []):
        shuffle_options(command)

    rng.shuffle(m.get("plugins", []))
    for plugin in m.get("plugins", []):
        rng.shuffle(plugin.get("commands", []))
        for command in plugin.get("commands", []):
            shuffle_options(command)

    return m


class GenerateCompletionsStableTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(FIXTURE) as f:
            cls.model = json.load(f)
        cls.baseline = {shell: cls.generate(cls.model, shell) for shell in SHELLS}

    @staticmethod
    def generate(model, shell):
        """Generate `shell` completions from `model`, returning the script text."""
        r = subprocess.run(
            [sys.executable, GENERATOR, "-", "--%s" % shell, "-"],
            input=json.dumps(model),
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, r.stderr
        return r.stdout

    def test_baseline_is_nonempty(self):
        for shell in SHELLS:
            self.assertTrue(self.baseline[shell], msg="%s baseline empty" % shell)

    def test_output_is_order_invariant(self):
        for seed in SEEDS:
            shuffled = shuffle_model(self.model, seed)
            for shell in SHELLS:
                self.assertEqual(
                    self.generate(shuffled, shell),
                    self.baseline[shell],
                    msg="%s output changed under shuffle seed %d" % (shell, seed),
                )


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("usage: %s <generate-completions.py> <fixture.json>" % sys.argv[0])
    FIXTURE = sys.argv.pop(2)
    GENERATOR = sys.argv.pop(1)
    unittest.main()
