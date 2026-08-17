#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
"""Validate `nvme utils dump-command-metadata` output against its JSON schema.

The command walks the live plugin/command tree and emits every command and its
options as JSON (see command-metadata.c).  This test runs it and checks:

  1. It conforms to command-metadata-schema.json (structural: required keys,
     value enums such as an option's "argument" and "values" sets).
  2. Known commands are present (the schema proves the shape is legal, not
     that any particular command was actually emitted).

The command needs no device, so this can run in every CI job.  It requires json-c
in the nvme build (the command is compiled out otherwise); when the output is
empty the test skips rather than fails.

Usage: test_command_metadata_schema.py <nvme-binary> <schema.json>

Exits 77 (meson "skip") when the jsonschema module is unavailable.
"""
import copy
import json
import subprocess
import sys
import unittest

try:
    import jsonschema
except ImportError:
    print("jsonschema module not available; skipping")
    sys.exit(77)

if len(sys.argv) < 3:
    print("usage: %s <nvme-binary> <schema-path>" % sys.argv[0])
    sys.exit(77)

NVME_BIN = sys.argv[1]
SCHEMA_PATH = sys.argv[2]


def json_c_available():
    """True if nvme was built with json-c. Its absence is the one legitimate
    reason to skip. Detected via --output-format help (lists 'json' only with
    json-c), not the dump command itself -- else a moved/renamed command would
    skip, not fail."""
    proc = subprocess.run(
        [NVME_BIN, "list", "--help"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True)
    return "json" in proc.stdout + proc.stderr


def dump_metadata():
    """Run `nvme utils dump-command-metadata` and return (parsed JSON, stderr).
    Returns (None, stderr) if it produced no usable output."""
    proc = subprocess.run(
        [NVME_BIN, "utils", "dump-command-metadata"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    text = proc.stdout.strip()
    if proc.returncode != 0 or not text:
        return None, proc.stderr
    return json.loads(text), proc.stderr


class TestCommandMetadataSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not json_c_available():
            raise unittest.SkipTest("nvme built without json-c")
        cls.data, stderr = dump_metadata()
        if cls.data is None:
            msg = "dump-command-metadata produced no output (built with json-c)"
            if stderr:
                msg += "\nstderr: " + stderr.rstrip()
            raise AssertionError(msg)
        with open(SCHEMA_PATH) as f:
            cls.schema = json.load(f)

    def test_conforms_to_schema(self):
        """Output validates against command-metadata-schema.json."""
        jsonschema.validate(self.data, self.schema)

    def test_schema_rejects_malformed(self):
        """The schema is strict: targeted corruptions of valid output fail.

        Guards against a schema edit that silently loosens a constraint
        (a dropped 'required' entry or additionalProperties) so malformed
        output would pass unnoticed."""
        cases = [
            lambda d: d["commands"][0]["options"][0].pop("long"),
            lambda d: d["commands"][0]["options"][0].update(argument="bogus"),
            lambda d: d["commands"][0]["options"][0].update(surprise=1),
        ]
        for mutate in cases:
            bad = copy.deepcopy(self.data)
            mutate(bad)
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(bad, self.schema)

    def test_expected_commands_present(self):
        """A few well-known builtin commands are emitted."""
        names = {c["name"] for c in self.data["commands"]}
        for expected in ("list", "list-subsys", "format", "get-log"):
            self.assertIn(expected, names)

    def test_plugins_have_commands(self):
        """Every emitted plugin carries at least one command."""
        for plugin in self.data["plugins"]:
            self.assertTrue(plugin["commands"],
                            msg="plugin '%s' emitted no commands" % plugin["name"])

    def test_stdout_is_pure_json(self):
        """The dump writes only JSON to stdout, nothing to stderr, rc 0.

        Some command fns print before parsing (e.g. gen-hostnqn); this guards
        against such output leaking into the machine-readable stream."""
        proc = subprocess.run(
            [NVME_BIN, "utils", "dump-command-metadata"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stderr, "")
        json.loads(proc.stdout)  # raises if stdout is not pure JSON

    def test_output_is_deterministic(self):
        """Two runs produce byte-identical output (needed for drift checks)."""
        runs = [
            subprocess.run(
                [NVME_BIN, "utils", "dump-command-metadata"],
                stdout=subprocess.PIPE, universal_newlines=True).stdout
            for _ in range(2)
        ]
        self.assertEqual(runs[0], runs[1])

    def test_schema_version(self):
        """schema_version is the expected 1; a change must be conscious."""
        self.assertEqual(self.data["schema_version"], 1)

    def test_global_output_format_option(self):
        """The shared output-format option carries its constrained value set."""
        cmd = next(c for c in self.data["commands"] if c["name"] == "list")
        opt = next(o for o in cmd["options"] if o["long"] == "output-format")
        self.assertTrue(opt.get("global"))
        self.assertEqual(opt["argument"], "required")
        self.assertIn("json", opt["values"])


if __name__ == "__main__":
    # argv[1:3] are consumed above; hand unittest only its own args.
    unittest.main(argv=[sys.argv[0]] + sys.argv[3:])
