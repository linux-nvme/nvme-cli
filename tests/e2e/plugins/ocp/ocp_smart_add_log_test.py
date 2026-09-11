# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
"""Test for OCP smart-add-log plugin command.

The C0 SMART / Health Information Extended log page grows with the OCP
datacenter NVMe SSD specification, and the page reports which layout it
carries in its own log page version field. Three printers render it --
text, JSON format version 1, and JSON format version 2 (the default) --
and each gates the same fields on that version.

Field values, version gating and the option surface at every log page version
are tested without hardware by ocp_smart_add_log_mock_test.py.
This tests in this module focus on the plugin's ability to read a real drive
and decode its C0 log page correctly.  Tests read the raw C0 log page using
`nvme get-log` and decode it against the spec-based field table in
ocp_c0_layout.py, then compare the decoded values against those reported by
the plugin's printers.

Tests in this module verify:
  * smart-add-log succeeds against a real controller, and its JSON
    output parses.
  * Every field each printer reports agrees with the same field decoded
    straight out of the raw log page.
  * All three printers report exactly the field set that the version the
    drive reports calls for -- no more and no less.
  * The page identifies itself with OCP's SCAO log page GUID.
"""

import json

from .ocp_c0_layout import (FIELDS, LOG_PAGE_SIZE, OCP_UUID, SCAO_GUID_BYTES,
                            by_name, coerce_json, decode, fields_for_version,
                            parse_stdout, parse_stdout_value, render_guid,
                            render_uuid)
from .ocp_test import TestOCP

# Printed when the C0 log page was read successfully but doesn't look like
# OCP's SCAO format (GUID mismatch), or when reading it failed outright (e.g.
# the drive returns "Invalid Log Page" because it doesn't implement log ID
# 0xC0 at all) -- both indicate the drive isn't an OCP-compliant device
# rather than a genuine command failure. In JSON output mode nvme-cli folds
# whichever of these was printed last into the "error" field of the JSON
# object on stdout (see _unsupported_reason below), so only the final,
# summary message ever shows up there; the first one is only ever seen in
# plain-text mode, ahead of the summary line, on stderr.
_UNSUPPORTED_MSGS = (
    "ERROR : OCP : Unknown GUID in C0 Log Page data",
    "ERROR : OCP : Failure reading the C0 Log Page",
)

_OCP_LID_SMART = 0xC0

_V1_CONTEXT = "ocp smart-add-log -o json --output-format-version 1"
_V2_CONTEXT = "ocp smart-add-log -o json"
_TEXT_CONTEXT = "ocp smart-add-log"


class TestOCPSmartAddLog(TestOCP):
    """Verify that ocp smart-add-log decodes the drive's C0 log page."""

    def _run(self, args=""):
        """Run ocp smart-add-log and return the CompletedProcess result,
        skipping the calling test when the drive is not an OCP device."""
        result = self.run_plugin_cmd("smart-add-log", args=args)
        if result.returncode != 0:
            reason = self._unsupported_reason(result)
            if reason is not None:
                self.skipTest(
                    f"ocp smart-add-log not supported on this drive: "
                    f"{reason!r}"
                )
        self.assertEqual(
            result.returncode, 0,
            f"Expected exit code 0, got {result.returncode}; "
            f"stdout={result.stdout!r}, stderr={result.stderr!r}",
        )
        return result

    @staticmethod
    def _unsupported_reason(result):
        """Return the unsupported-drive message from a failed run, or None
        when the failure doesn't look like an unsupported drive.

        -o json is meant to be parsed by machines, not scraped as text, so
        prefer reading its structured "error" field over guessing which
        stream carries the message: nvme-cli folds error text that would
        otherwise go to stderr into that field instead when JSON output was
        requested, so plain stdout/stderr text matching only ever applies to
        genuine plain-text output.
        """
        try:
            error = json.loads(result.stdout).get("error")
        except (TypeError, ValueError, AttributeError):
            error = None
        haystacks = (error,) if error is not None else (
            result.stdout, result.stderr)
        return next(
            (haystack for haystack in haystacks
             if any(msg in haystack for msg in _UNSUPPORTED_MSGS)),
            None,
        )

    def _json_log(self, format_version=None):
        """Run smart-add-log with JSON output and return the parsed page."""
        args = "-o json"
        if format_version is not None:
            args += f" --output-format-version {format_version}"
        result = self._run(args=args)
        return self.parse_json_output(result.stdout,
                                      f"ocp smart-add-log {args}")

    def _ocp_uuid_index(self):
        """Return the UUID index the plugin uses to request the C0 page.

        ocp_get_uuid_index() looks the OCP vendor UUID up in the drive's
        UUID list and uses its 1-based position, or 0 when the drive
        publishes no such entry. `nvme id uuid` walks the same list and
        stops at the same terminator, so enumerating its output
        reproduces the index without guessing.
        """
        cmd = (f"{self.nvme_bin} {self.command('id uuid')} {self.ctrl} "
               f"-o json")
        result = self.run_cmd(cmd, quiet=True)
        if result.returncode != 0:
            return 0
        try:
            entries = json.loads(result.stdout).get("UUID-list", [])
        except (TypeError, ValueError, AttributeError):
            return 0

        wanted = render_uuid(OCP_UUID)
        for position, entry in enumerate(entries):
            if str(entry.get("uuid", "")).lower() == wanted:
                return position + 1
        return 0

    def _raw_page(self, name):
        """Read the C0 log page with a generic get-log and return its
        512 raw bytes.

        Goes through a file rather than captured stdout for two reasons:
        the log page is binary and run_cmd() decodes output as UTF-8, and
        the normal-mode hex dump is lossy -- stdout_d() collapses runs of
        identical lines to a '*'.
        """
        path = self.test_log_dir / name
        uuid_index = self._ocp_uuid_index()
        args = [f"--log-id={_OCP_LID_SMART}",
                f"--log-len={LOG_PAGE_SIZE}",
                "--raw-binary"]
        if uuid_index:
            args.append(f"--uuid-index={uuid_index}")
        cmd = (f"{self.nvme_bin} get-log {self.ctrl} {' '.join(args)} "
               f"> \"{path}\"")
        result = self.run_cmd(cmd)
        self.assertEqual(
            result.returncode, 0,
            f"reference read of the C0 log page failed: "
            f"rc={result.returncode}, stderr={result.stderr!r}")

        page = path.read_bytes()
        self.assertEqual(
            len(page), LOG_PAGE_SIZE,
            f"reference read returned {len(page)} bytes, expected "
            f"{LOG_PAGE_SIZE}")

        guid = decode(page, by_name("log_page_guid"))
        self.assertEqual(
            guid, render_guid(SCAO_GUID_BYTES),
            f"the reference get-log read (uuid index {uuid_index}) did not "
            f"return OCP's C0 page; its GUID is {guid}. The plugin and this "
            f"test disagree about how to request the page.")
        return page

    def _bracketed_outputs(self):
        """Collect every printer's output, bracketed by two raw reads.

        The plugin and the reference get-log cannot read the drive at the
        same instant, and most C0 fields are live counters, so comparing
        against a single snapshot would fail whenever one ticked in
        between. Reading the page before and after brackets the true
        value of every field at the time the plugin read it: on a quiet
        drive both reads agree and the comparison is an exact one.
        """
        # _raw_page() asserts rather than skips, so establish that the
        # drive is an OCP device first -- _run() skips when it is not.
        self._run(args="-o json")
        before = self._raw_page("c0-before.bin")
        outputs = {
            _V1_CONTEXT: ('json', 1, self._json_log(format_version=1)),
            _V2_CONTEXT: ('json', 2, self._json_log(format_version=2)),
            _TEXT_CONTEXT: ('text', None, parse_stdout(self._run().stdout)),
        }
        after = self._raw_page("c0-after.bin")
        return before, outputs, after

    def _reported_key(self, field, mode, format_version):
        """Return the name @field goes by in a given output mode.

        None means that printer does not report the field at all.
        parse_stdout() keys its result by field name, so that is the
        lookup for text mode -- the label only decides whether the field
        is reported.
        """
        if mode == 'text':
            return field.name if field.stdout_label is not None else None
        return field.v1_key if format_version == 1 else field.v2_key

    def _reported_value(self, field, mode, reported):
        """Normalise one printer's value into decode()'s form."""
        if mode == 'text':
            return parse_stdout_value(field, reported)
        return coerce_json(field, reported)

    def _assert_matches_raw(self, field, value, before, after, context):
        """Assert @value is what the raw page says @field holds."""
        low = decode(before, field)
        high = decode(after, field)
        if isinstance(low, int) and isinstance(high, int):
            self.assertGreaterEqual(
                value, min(low, high),
                f"{context}: {field.name} reads {value}, below both raw "
                f"reads ({low}, {high}) at offset {field.offset} "
                f"({field.size} bytes, {field.kind})")
            self.assertLessEqual(
                value, max(low, high),
                f"{context}: {field.name} reads {value}, above both raw "
                f"reads ({low}, {high}) at offset {field.offset} "
                f"({field.size} bytes, {field.kind})")
        else:
            self.assertIn(
                value, {low, high},
                f"{context}: {field.name} reads {value!r}, but the raw log "
                f"page says {low!r} at offset {field.offset} "
                f"({field.size} bytes, {field.kind})")

    def test_smart_add_log(self):
        """Run ocp smart-add-log and verify it returns success."""
        self._run(args="-o json")

    def test_smart_add_log_json_is_wellformed(self):
        """-o json produces a JSON object reporting its layout version."""
        log = self._json_log()
        self.json_get(log, "log_page_version", context=_V2_CONTEXT,
                      required=True)

    def test_log_page_guid_is_the_ocp_guid(self):
        """The GUID is what marks the page as OCP's, so the plugin has to
        render the one the drive returned, not merely accept it."""
        log = self._json_log()
        self.assertEqual(
            str(self.json_get(log, "log_page_guid", context=_V2_CONTEXT,
                              required=True)).lower(),
            render_guid(SCAO_GUID_BYTES))

    def test_every_printer_matches_the_raw_log_page(self):
        """The decode itself: every field every printer reports has to
        agree with that field read straight out of the drive's bytes."""
        before, outputs, after = self._bracketed_outputs()
        version = decode(before, by_name("log_page_version"))

        for context, (mode, format_version, reported) in outputs.items():
            for field in fields_for_version(version):
                key = self._reported_key(field, mode, format_version)
                if key is None or key not in reported:
                    continue
                with self.subTest(context=context, field=field.name):
                    value = self._reported_value(field, mode, reported[key])
                    self._assert_matches_raw(field, value, before, after,
                                             context)

    def test_every_printer_reports_the_expected_field_set(self):
        """A field is either in the layout the drive's version calls for,
        or it is not reported at all. Nothing in between."""
        before, outputs, _after = self._bracketed_outputs()
        version = decode(before, by_name("log_page_version"))
        expected = set(fields_for_version(version))

        for context, (mode, format_version, reported) in outputs.items():
            for field in FIELDS:
                key = self._reported_key(field, mode, format_version)
                if key is None:
                    continue
                with self.subTest(context=context, field=field.name):
                    if field in expected:
                        self.assertIn(
                            key, reported,
                            f"{context} omits {key!r}, a version "
                            f"{field.min_version} field, from a version "
                            f"{version} page")
                    else:
                        self.assertNotIn(
                            key, reported,
                            f"{context} reports {key!r}, a version "
                            f"{field.min_version} field, for a version "
                            f"{version} page")
