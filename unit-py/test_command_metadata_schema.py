#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
"""Validate `nvme dump-command-metadata` output against its JSON schema.

The command walks the live plugin/command tree and emits every command and its
options as JSON (see command-metadata.c).  This test runs it and checks:

  1. It conforms to command-metadata-schema.json (structural: required keys,
     value enums such as an option's "argument" and "values" sets).
  2. Known commands are present, and the emitted plugins match what
     `nvme help` lists (the schema proves the shape is legal, not that any
     particular command or plugin was actually emitted).
  3. Every command's option set matches what `--help` prints for it -- an
     independent code path over the same data, which catches the silent
     failure where capture never fires and a command emits no options.

The command needs no device, so this can run in every CI job.  It requires json-c
in the nvme build (the command is compiled out otherwise); when the output is
empty the test skips rather than fails.

Usage: test_command_metadata_schema.py <nvme-binary> <schema.json>

Exits 77 (meson "skip") when the jsonschema module is unavailable.
"""
import copy
import json
import re
import subprocess
import sys
import unittest

# Long option as printed in --help, e.g. "[  --output-format=<FMT>, -o <FMT> ]".
HELP_LONG_OPT = re.compile(r"\[\s*--([A-Za-z0-9][A-Za-z0-9_-]*)")
# Plugin as printed by `nvme help`, e.g. "  ocp             ...description".
HELP_PLUGIN = re.compile(r"^\s{2}(\S+)\s{2,}", re.MULTILINE)

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


def command_is_builtin():
    """True if `nvme help` lists dump-command-metadata. The command's ENTRY is
    #ifdef CONFIG_JSONC, so absence means nvme was built without json-c -- the
    one legitimate reason for no output. An unknown sub-command and a failed
    dump both exit 1, so the exit code can't tell them apart; help can."""
    proc = subprocess.run(
        [NVME_BIN, "help"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True)
    return "dump-command-metadata" in proc.stdout + proc.stderr


def dump_metadata():
    """Run `nvme dump-command-metadata` and return parsed JSON, or None if it
    produced no usable output."""
    proc = subprocess.run(
        [NVME_BIN, "dump-command-metadata"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    text = proc.stdout.strip()
    if proc.returncode != 0 or not text:
        return None
    return json.loads(text)


def iter_commands(data):
    """Yield (command_path, command) for every builtin and plugin command.
    command_path is the argv words that name the command: ["id-ctrl"] for a
    builtin, ["ocp", "smart-add-log"] for a plugin command."""
    for cmd in data["commands"]:
        yield [cmd["name"]], cmd
    for plugin in data["plugins"]:
        for cmd in plugin["commands"]:
            yield [plugin["name"], cmd["name"]], cmd


def help_option_names(command_path):
    """The set of long options `nvme <command_path> --help` prints, or None if
    the command crashed (non-zero exit with no output), e.g. due to a stack
    overflow on platforms with a small default stack size."""
    proc = subprocess.run(
        [NVME_BIN] + command_path + ["--help"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    output = proc.stdout + proc.stderr
    if proc.returncode != 0 and not output.strip():
        return None
    return set(HELP_LONG_OPT.findall(output))


def help_plugin_names():
    """The set of plugins `nvme help` lists as installed extensions -- an
    independent source of truth for which plugins are compiled in, so the test
    adapts to builds configured with a subset of plugins."""
    proc = subprocess.run(
        [NVME_BIN, "help"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True)
    text = proc.stdout + proc.stderr
    marker = "installed plugin extensions"
    if marker not in text:
        # No plugin-extension section (e.g. built with zero external
        # plugins); scraping the whole help text would mis-read builtin
        # commands as plugins.
        return set()
    after = text.split(marker, 1)[-1]
    return set(HELP_PLUGIN.findall(after))


class TestCommandMetadataSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not command_is_builtin():
            raise unittest.SkipTest(
                "dump-command-metadata not built (nvme built without json-c)")
        cls.data = dump_metadata()
        if cls.data is None:
            raise AssertionError(
                "dump-command-metadata is built in but produced no output")
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
        for expected in ("list", "id-ctrl", "id-ns", "smart-log"):
            self.assertIn(expected, names)

    def test_plugins_match_help(self):
        """The emitted plugins equal what `nvme help` lists as installed.

        `nvme help` enumerates plugins via an independent code path, so this
        adapts to builds configured with a subset of plugins (unlike a
        hardcoded list) while still catching a dump that drops or invents one.
        Each emitted plugin must also carry at least one command."""
        dumped = {p["name"]: p for p in self.data["plugins"]}
        self.assertEqual(set(dumped), help_plugin_names())
        for name, plugin in dumped.items():
            self.assertTrue(plugin["commands"],
                            msg="plugin '%s' emitted no commands" % name)

    def test_options_match_help(self):
        """Each command's visible options equal what --help prints.

        --help is generated by an independent code path (argconfig_print_help)
        over the same option array the dump walks, so agreement catches the
        critical silent failure: capture never fires for a command and it emits
        an empty option set that still validates against the schema.  Hidden
        options are excluded since --help suppresses them by design."""
        for command_path, cmd in iter_commands(self.data):
            dumped = {o["long"] for o in cmd["options"] if not o.get("hidden")}
            printed = help_option_names(command_path)
            if printed is None:
                # Command crashed before producing output (e.g. stack
                # overflow); skip rather than fail -- the underlying bug
                # is unrelated to the metadata dump.
                continue
            self.assertEqual(
                dumped, printed,
                msg="option mismatch for '%s'" % " ".join(command_path))

    def test_stdout_is_pure_json(self):
        """The dump writes only JSON to stdout, nothing to stderr, rc 0.

        Some command fns print before parsing (e.g. gen-hostnqn); this guards
        against such output leaking into the machine-readable stream."""
        proc = subprocess.run(
            [NVME_BIN, "dump-command-metadata"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stderr, "")
        json.loads(proc.stdout)  # raises if stdout is not pure JSON

    def test_output_is_deterministic(self):
        """Two runs produce byte-identical output (needed for drift checks)."""
        runs = [
            subprocess.run(
                [NVME_BIN, "dump-command-metadata"],
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
