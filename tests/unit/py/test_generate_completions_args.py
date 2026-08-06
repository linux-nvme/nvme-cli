#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
# This file is part of nvme-cli.
"""Test generate-completions.py command-line argument handling.

The generator turns `nvme utils dump-command-metadata` JSON into shell
completion scripts.  This test covers only its CLI contract -- which
combinations of --bash/--zsh and output targets are accepted or rejected --
not the generated content (the test-*-completion.sh suites cover that).

The error paths fire before any model is read, and a valid model needs only
its schema version (the command/plugin lists default to empty), so the whole
test is hermetic: it feeds JSON on stdin and needs no nvme binary or device.

Usage: test_generate_completions_args.py <generate-completions.py>
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

# A model that passes the schema-version check; with no commands or plugins the
# generator still emits a valid (if command-less) script.
MINIMAL_MODEL = json.dumps({"schema_version": 1})


class GenerateCompletionsArgsTest(unittest.TestCase):
    def run_gen(self, *args):
        """Run the generator with MINIMAL_MODEL on stdin; return CompletedProcess."""
        return subprocess.run(
            [sys.executable, GENERATOR, *args],
            input=MINIMAL_MODEL,
            capture_output=True,
            text=True,
        )

    def test_no_shell_is_rejected(self):
        r = self.run_gen()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("specify at least one", r.stderr)

    def test_both_shells_sharing_stdout_is_rejected(self):
        r = self.run_gen("--bash", "-", "--zsh", "-")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("give each a FILE", r.stderr)

    def test_one_stdout_one_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.run_gen("--bash", "-", "--zsh", os.path.join(d, "z"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("give each a FILE", r.stderr)

    def test_both_shells_to_files_succeeds(self):
        with tempfile.TemporaryDirectory() as d:
            bash, zsh = os.path.join(d, "b"), os.path.join(d, "z")
            r = self.run_gen("--bash", bash, "--zsh", zsh)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertGreater(os.path.getsize(bash), 0)
            self.assertGreater(os.path.getsize(zsh), 0)

    def test_single_shell_to_stdout_succeeds(self):
        r = self.run_gen("--zsh", "-")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("#compdef", r.stdout)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: %s <generate-completions.py>" % sys.argv[0])
    GENERATOR = sys.argv.pop(1)
    unittest.main()
