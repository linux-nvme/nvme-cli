#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Test that generate-completions.py completes what the metadata types say.

An option of the type file or directory completes paths, whatever its
metavar. An option with a small range offers its numbers, followed by its
names. Checked on the bash and PowerShell output for the fixture.

Usage: test_generate_completions_values.py <generate-completions.py> <fixture.json>
"""
import subprocess
import sys
import unittest

if len(sys.argv) < 3:
    print("usage: %s <generate-completions.py> <fixture.json>" % sys.argv[0])
    sys.exit(77)

GENERATOR, FIXTURE = sys.argv[1], sys.argv[2]


def generate(shell):
    return subprocess.run([sys.executable, GENERATOR, FIXTURE,
                           "--" + shell, "-"],
                          capture_output=True, text=True, check=True).stdout


class CompletionValuesTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.bash = generate("bash")
        cls.powershell = generate("powershell")

    def test_paths(self):
        self.assertIn('_nvme_opt_files "--in-file -f" "--out-dir"',
                      self.bash)
        self.assertIn("'zeta-plug report --out-dir' = $true",
                      self.powershell)

    def test_range(self):
        self.assertIn('"--sel -S" "0 1 2 3 current saved"', self.bash)
        self.assertIn('"--format-version" "1 2"', self.bash)
        self.assertIn("'zeta-plug report --sel' = "
                      "@('0', '1', '2', '3', 'current', 'saved')",
                      self.powershell)

    def test_no_guess_from_name(self):
        # a number without a range offers nothing
        self.assertNotIn('"--wait-time -w"', self.bash)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + sys.argv[3:])
