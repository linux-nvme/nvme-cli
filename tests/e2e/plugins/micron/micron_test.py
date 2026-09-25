# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Base class for Micron plugin tests."""

import re

from ..plugin_test import TestPlugin
from .micron_checks import MicronChecksMixin

# The micron plugin gates most commands on the drive model, and sometimes on
# a customer ID in the vendor-specific identify data, so a command can be
# unreachable on an otherwise healthy Micron drive.  When a command fails
# due to an unsupported drive model, the test needs to be skipped.  The
# exit status can't be used to determine this behavior, so detection is by
# message rather than return code.
_UNSUPPORTED_DRIVE_PATTERNS = (
    "Unsupported drive model",
    "not supported for specified drive",
)

_INVALID_LOG_PAGE = "Invalid Log Page"

# Log pages per command that generate Invalid Log Page message if not supported.
_COMMAND_LOG_PAGES = {
    "vs-smart-ext-log": (0xE1, 0xD0),
    "vs-smart-add-log": (0xC0, 0xFB),
    "vs-nand-stats": (0xD0, 0xFB),
    "vs-fw-activate-history": (0xC2,),
    "latency-stats": (0xD0,),
    "latency-logs": (0xD1,),
    "vs-cloud-log": (0xC0,),
    "vs-work-load-log": (0xC5,),
    "vs-vendor-telemetry-log": (0xC6,),
}

# Log ID key pattern for extracting the supported log page IDs
_LID_KEY_RE = re.compile(r'"lid_0x([0-9a-fA-F]+) *"')

# Distinguishes "not probed yet" from a probe that found no Supported Log Pages
# log, since the latter caches as None.
_NOT_PROBED = object()


class TestMicron(MicronChecksMixin, TestPlugin):
    """Base class for Micron plugin tests.

    Provides the plugin_name and any Micron-specific helpers.
    """

    plugin_name = "micron"

    # Shared by every subclass: (command, args) -> unsupported reason or None.
    _support_cache = {}

    # Shared by every subclass: the drive's supported log page IDs, or None
    # when the Supported Log Pages log could not be read.
    _log_pages = _NOT_PROBED

    @staticmethod
    def _extract_error_message(output, pattern):
        """Find the first error message matching the pattern and return the message.

        If the message is formatted as JSON, just the message string is returned
        without the surrounding JSON formatting.
        """
        line = next(line for line in output.splitlines() if pattern in line)
        # A JSON-mode line is '"error":"<message>",'; keep just the message so
        # the reason reads the same whichever output format was used.
        return line.strip().strip(',').strip('"').removeprefix('error":"')

    @staticmethod
    def _lid_list(lids):
        """Format log page IDs for a message, e.g. '0xD0 or 0xFB'."""
        return " or ".join(f"0x{lid:02X}" for lid in lids)

    def supported_log_pages(self):
        """Return the log page IDs the drive advertises.

        Read from the Supported Log Pages log.  Returns None when that log
        cannot be read.  If no supported logs are listed, returns an empty set.
        """
        if TestMicron._log_pages is _NOT_PROBED:
            result = self.run_cmd(
                f"{self.nvme_bin} {self.command('log supported-pages')} "
                f"{self.ctrl} --output-format=json"
            )
            TestMicron._log_pages = frozenset(
                int(lid, 16) for lid in _LID_KEY_RE.findall(result.stdout)
            ) if result.returncode == 0 else None
        return TestMicron._log_pages

    def _log_page_unsupported_reason(self, command, result):
        """Return a reason if the tested log pages are not supported by this drive.

        A return value of None indicates that either no log page errors were
        detected, or that the log pages should be supported and any errors are
        valid failures and should not be skipped.
        """
        if _INVALID_LOG_PAGE not in result.stderr + result.stdout:
            return None

        lids = _COMMAND_LOG_PAGES.get(command)
        if lids is None:
            return None

        supported = self.supported_log_pages()
        if supported is None or supported.intersection(lids):
            return None

        return f"drive does not support log page {self._lid_list(lids)}"

    def _unsupported_reason(self, command, result):
        """Return the reason this drive cannot run command, else None.

        Both streams are searched: in normal mode the message goes to stderr,
        while in JSON mode it is reported as a JSON object on stdout.
        """
        output = result.stderr + result.stdout
        for pattern in _UNSUPPORTED_DRIVE_PATTERNS:
            if pattern in output:
                return self._extract_error_message(output, pattern)
        return self._log_page_unsupported_reason(command, result)

    def _probe_unsupported_reason(self, command, args=""):
        """Test whether the command is supported on this drive. Return reason if unsupported.

        If no cached results exist for the command, runs it and caches the result.
        Returns the unsupported reason, or None when the command is usable.
        """
        key = (command, args)
        if key not in TestMicron._support_cache:
            result = self.run_plugin_cmd(command, args=args)
            TestMicron._support_cache[key] = self._unsupported_reason(command, result)
        return TestMicron._support_cache[key]

    def skip_unless_command_supported(self, command, args=""):
        """Skip the test if the command is not supported on this drive.

        Pre-runs the command to verify support on the current drive.
        If the command is not supported, the test is skipped.  The result
        is cached for future checks on the same command.
        """
        reason = self._probe_unsupported_reason(command, args=args)
        if reason:
            self.skipTest(f"micron {command} unsupported on this drive: {reason}")

    def skip_if_result_unsupported(self, command, result):
        """Skip the current test if the result reports an unsupported drive."""

        reason = self._unsupported_reason(command, result)
        if reason:
            self.skipTest(f"micron {command} unsupported on this drive: {reason}")

    def run_supported_cmd(self, command, device=None, args=""):
        """Run a command and require it to succeed on a drive that supports it.

        Skips rather than fails when the command is unsupported on the current drive.
        Returns the CompletedProcess result when the command is supported and succeeds.
        """
        result = self.run_plugin_cmd(command, device=device, args=args)
        self.skip_if_result_unsupported(command, result)
        self.assertEqual(
            result.returncode, 0,
            f"micron {command} failed: rc={result.returncode}, "
            f"stderr={result.stderr!r}",
        )
        return result

    def run_supported_cmd_json(self, command, device=None, args="--output-format=json"):
        """Run a command in JSON mode and require it to succeed on a drive that supports it.

        Skips rather than fails when the command is unsupported on the current drive.
        Returns the parsed JSON object when the command is supported and succeeds.
        """
        result = self.run_supported_cmd(command, device=device, args=args)
        return self.parse_json_output(result.stdout, f"micron {command} {args}")

    def check_hex_fields_json(self, command, allowed_keys):
        """Run the command in JSON mode and assert that the output is a well-formed hex fields object."""
        self.hex_fields_from_json(
            self.run_supported_cmd_json(command), allowed_keys, command)

    def check_hex_fields_table(self, command):
        """Run the command and assert that the output is a well-formed hex fields table."""
        self.hex_fields_from_table(
            self.run_supported_cmd(command).stdout, command)

    def check_text_and_json_hex_fields_match(self, command, allowed_keys):
        """The text and JSON formats must report identical fields and values."""
        text_fields = self.hex_fields_from_table(
            self.run_supported_cmd(command).stdout, command)
        json_fields = self.hex_fields_from_json(
            self.run_supported_cmd_json(command), allowed_keys, command)

        self.assertEqual(
            set(text_fields), set(json_fields),
            f"micron {command} text and JSON field sets differ; "
            f"text-only={set(text_fields) - set(json_fields)}, "
            f"JSON-only={set(json_fields) - set(text_fields)}",
        )
        for label, value in json_fields.items():
            self.assertEqual(
                text_fields[label], value,
                f"micron {command} field {label!r} differs between text "
                f"({text_fields[label]!r}) and JSON ({value!r})",
            )

    def check_required_hex_fields_present(self, command, allowed_keys, required_labels):
        """Every field defined for the reported log page must be present.

        required_labels maps each top-level JSON key to the field labels its log
        page defines.
        """
        data = self.run_supported_cmd_json(command)
        key = next(iter(data))
        fields = self.hex_fields_from_json(data, allowed_keys, command)

        for label in required_labels[key]:
            self.assertIn(
                label, fields,
                f"Expected field {label!r} for log page {key!r}, "
                f"got: {list(fields)}",
            )

    def check_ns_hex_fields_match_ctrl(self, command, allowed_keys):
        """The namespace path must report the same fields as the controller.

        A namespace path resolves to its parent controller, so both read the
        same log.
        """
        ctrl_fields = self.hex_fields_from_json(
            self.run_supported_cmd_json(command, device=self.ctrl),
            allowed_keys, command)
        ns_fields = self.hex_fields_from_json(
            self.run_supported_cmd_json(command, device=self.ns1),
            allowed_keys, command)

        self.assertEqual(
            set(ctrl_fields), set(ns_fields),
            f"micron {command} field set differs between {self.ctrl} and "
            f"{self.ns1}",
        )
