# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
"""Test for OCP smart-add-log plugin command.

The C0 SMART / Health Information Extended log page grows with the OCP
datacenter NVMe SSD specification, and the page reports which layout it
carries in its own log page version field.  Three printers render it --
text, JSON format version 1, and JSON format version 2 (the default) --
and each gates the same fields on that version, so a field added to one
printer and not the others goes missing from some output modes only.

Tests in this module verify:
  * smart-add-log succeeds, and its JSON output parses.
  * The version 6 fields (form factor and die-in-use bad NAND blocks)
    appear in both JSON format versions, with a value agreeing with the
    text output.
  * Both JSON format versions report the same number of fields, so the
    two cannot drift apart again.
"""

import re

from .ocp_test import TestOCP

# Printed when the C0 log page was read successfully but doesn't look like
# OCP's SCAO format (GUID mismatch), or when reading it failed outright (e.g.
# the drive returns "Invalid Log Page" because it doesn't implement log ID
# 0xC0 at all) -- both indicate the drive isn't an OCP-compliant device
# rather than a genuine command failure.
_UNSUPPORTED_MSGS = (
    "ERROR : OCP : Unknown GUID in C0 Log Page data",
    "ERROR : OCP : Failure reading the C0 Log Page",
)

# First log page version carrying the form factor and die-in-use bad NAND
# block fields (OCP 2.7).
_FORM_FACTOR_VERSION = 6

# The version 6 fields as each printer spells them.
_V2_KEYS = (
    "form_factor",
    "die_in_use_bad_nand_block_raw",
    "die_in_use_bad_nand_block_normalized",
)
_V1_KEYS = (
    "Form factor",
    "Die use badnandblock raw",
    "Die use badnandblock normal",
)

_FORM_FACTOR_LABEL = "Form factor"

_V1_CONTEXT = "ocp smart-add-log -o json --output-format-version 1"
_V2_CONTEXT = "ocp smart-add-log -o json"


class TestOCPSmartAddLog(TestOCP):
    """Verify that the ocp smart-add-log command executes successfully."""

    def _run(self, args=""):
        """Run ocp smart-add-log and return the CompletedProcess result,
        skipping the calling test when the drive is not an OCP device."""
        result = self.run_plugin_cmd("smart-add-log", args=args)
        if result.returncode != 0 and any(
            msg in result.stderr for msg in _UNSUPPORTED_MSGS
        ):
            self.skipTest(
                f"ocp smart-add-log not supported on this drive "
                f"(stderr: {result.stderr!r})"
            )
        self.assertEqual(
            result.returncode, 0,
            f"Expected exit code 0, got {result.returncode}; "
            f"stderr={result.stderr!r}",
        )
        return result

    def _json_log(self, format_version=None):
        """Run smart-add-log with JSON output and return the parsed page."""
        args = "-o json"
        if format_version is not None:
            args += f" --output-format-version {format_version}"
        result = self._run(args=args)
        return self.parse_json_output(result.stdout,
                                      f"ocp smart-add-log {args}")

    def _skip_unless_version_6(self, log, version_key, context):
        """Skip the calling test unless the drive's C0 log page is new
        enough to carry the version 6 fields."""
        version = int(self.json_get(log, version_key, context=context,
                                    required=True))
        if version < _FORM_FACTOR_VERSION:
            self.skipTest(
                f"drive reports C0 log page version {version}; the form "
                f"factor and die-in-use bad NAND block fields are version "
                f"{_FORM_FACTOR_VERSION} and later"
            )

    def test_smart_add_log(self):
        """Run ocp smart-add-log and verify it returns success."""
        self._run()

    def test_smart_add_log_json_is_wellformed(self):
        """-o json produces a JSON object reporting its layout version."""
        log = self._json_log()
        self.json_get(log, "log_page_version", context=_V2_CONTEXT,
                      required=True)

    def test_json_v2_reports_version_6_fields(self):
        """The default JSON output must not drop version 6 fields that the
        text output prints."""
        log = self._json_log()
        self._skip_unless_version_6(log, "log_page_version", _V2_CONTEXT)
        missing = [key for key in _V2_KEYS if key not in log]
        self.assertEqual(
            missing, [],
            f"{_V2_CONTEXT} omits {missing}; keys present: {sorted(log)}")

    def test_json_v1_reports_version_6_fields(self):
        """The same fields under JSON format version 1's key spellings."""
        log = self._json_log(format_version=1)
        self._skip_unless_version_6(log, "Log page version", _V1_CONTEXT)
        missing = [key for key in _V1_KEYS if key not in log]
        self.assertEqual(
            missing, [],
            f"{_V1_CONTEXT} omits {missing}; keys present: {sorted(log)}")

    def test_json_v2_form_factor_matches_text_output(self):
        """The form factor value, not just its key, has to survive the trip
        through the JSON printer."""
        log = self._json_log()
        self._skip_unless_version_6(log, "log_page_version", _V2_CONTEXT)
        text = self._run().stdout
        match = re.search(rf"^\s*{re.escape(_FORM_FACTOR_LABEL)}\s+(\d+)\s*$",
                          text, re.MULTILINE)
        if match is None:
            self.fail(f"no {_FORM_FACTOR_LABEL!r} line in the text output "
                      f"of ocp smart-add-log: {text!r}")
        self.assertEqual(
            int(log["form_factor"]), int(match.group(1)),
            "form factor differs between the JSON and the text output")

    def test_json_format_versions_report_the_same_fields(self):
        """The two JSON format versions differ in key naming only, so a
        field reaching one printer but not the other is a bug -- that is
        how the version 6 fields went missing from version 2."""
        v1 = self._json_log(format_version=1)
        v2 = self._json_log(format_version=2)
        self.assertEqual(
            len(v1), len(v2),
            f"JSON format version 1 reports {len(v1)} fields and version 2 "
            f"reports {len(v2)}: v1={sorted(v1)}, v2={sorted(v2)}")
