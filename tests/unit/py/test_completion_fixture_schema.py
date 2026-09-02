#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
# This file is part of nvme-cli.
"""Validate the completion test fixture against the command-metadata schema.

completions/test-command-metadata.json is a hand-written, synthetic model that
the bash/zsh completion test suites feed to generate-completions.py. It is not
real `nvme utils dump-command-metadata` output, so it can drift from the
metadata format the generator expects. This test is the tripwire: it validates
the fixture against the same command-metadata-schema.json that
test_command_metadata_schema.py checks the live command against. A schema change
the fixture no longer satisfies fails here, forcing the fixture to be updated.

Needs no nvme binary or json-c build -- both inputs are committed files.

Usage: test_completion_fixture_schema.py <fixture.json> <schema.json>

Exits 77 (meson "skip") when the jsonschema module is unavailable.
"""
import json
import sys
import unittest

try:
    import jsonschema
except ImportError:
    print("jsonschema module not available; skipping")
    sys.exit(77)

if len(sys.argv) < 3:
    sys.exit("usage: %s <fixture-path> <schema-path>" % sys.argv[0])

FIXTURE_PATH = sys.argv[1]
SCHEMA_PATH = sys.argv[2]


class TestCompletionFixtureSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(FIXTURE_PATH) as f:
            cls.data = json.load(f)
        with open(SCHEMA_PATH) as f:
            cls.schema = json.load(f)

    def test_conforms_to_schema(self):
        """The committed fixture validates against command-metadata-schema.json."""
        jsonschema.validate(self.data, self.schema)

    def test_not_empty(self):
        """The fixture still carries commands and plugins (guard against an
        edit that silently emptied it)."""
        self.assertTrue(self.data["commands"], msg="fixture has no commands")
        self.assertTrue(self.data["plugins"], msg="fixture has no plugins")


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
