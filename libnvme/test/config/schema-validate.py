#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
"""Validate config dump outputs against doc/config-schema.json.

The config-diff tests assert that a dumped config matches a committed .out
fixture; this test asserts those same .out fixtures conform to the published
JSON schema.  Together they guarantee the dump output follows the schema, so a
change to the dump format (or the schema) that breaks that agreement fails CI --
the gap that let the top-level shape drift from the schema unnoticed.

Usage: schema-validate.py <schema.json> <dump.out>...

Exits 77 (meson "skip") when the jsonschema module is unavailable.
"""
import json
import sys

try:
    import jsonschema
except ImportError:
    print("jsonschema module not available; skipping")
    sys.exit(77)

schema_path = sys.argv[1]
with open(schema_path) as f:
    schema = json.load(f)

failures = 0
for out_path in sys.argv[2:]:
    with open(out_path) as f:
        text = f.read().strip()
    if not text:
        # An empty dump (nothing to persist) is a valid degenerate case.
        print(f"SKIP {out_path} (empty)")
        continue
    data = json.loads(text)
    try:
        jsonschema.validate(data, schema)
        print(f"OK   {out_path}")
    except jsonschema.ValidationError as e:
        print(f"FAIL {out_path}: {e.message}")
        failures += 1

sys.exit(1 if failures else 0)
