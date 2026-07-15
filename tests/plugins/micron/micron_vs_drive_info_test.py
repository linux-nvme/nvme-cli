# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron vs-drive-info command.

The vs-drive-info command reports drive hardware information -- hardware
version, FTL unit size, boot-spec version, and drive-ownership status.
Which fields appear and how they are formatted depends on the drive model
and its customer ID, so several fields are optional and present only on
certain drives.  Output is human-readable text by default or JSON when
--format=json is passed.

Tests in this module verify:
  * Error handling for a non-existent device and an invalid --format value.
  * Text output by default and with --format=normal, and that --format=json
    switches the output to JSON.
  * Valid JSON shape: a one-element "Micron Drive HW Information" array
    holding a single info object.
  * The always-present "Drive Hardware Version" field, and the format of the
    optional FTL size, boot-spec, and ownership-status fields when present.
  * Consistency of the reported fields and values between JSON and text.
  * Equivalent results for the controller and namespace device paths.
"""

import json
import re

from tests.plugins.micron.micron_test import TestMicron

_MICRON_HW_INFORMATION_KEY = "Micron Drive HW Information"
_UNSUPPORTED_MSG = "Unsupported drive for vs-drive-info cmd"

# Field labels shared by the JSON (keys) and text ("Label: value") branches.
_DRIVE_HW_VERSION = "Drive Hardware Version"
_FTL_UNIT_SIZE = "FTL_unit_size"
_BOOT_SPEC_VERSION = "Boot Spec.Version"
_OWNERSHIP_STATUS = "Drive Ownership Status"

_ALL_LABELS = [
    _DRIVE_HW_VERSION,
    _FTL_UNIT_SIZE,
    _BOOT_SPEC_VERSION,
    _OWNERSHIP_STATUS,
]

_OWNERSHIP_VALUES = {"N/A", "UNSET", "SET", "BLOCKED"}


class TestMicronVsDriveInfo(TestMicron):
    """Test suite for the micron vs-drive-info plugin command."""

    # Cached result of the drive info availability probe.
    # None means "not yet probed".
    _drive_info_available = None

    def _run_drive_info(self, device=None, args=""):
        """Run vs-drive-info and return the CompletedProcess result."""
        return self.run_plugin_cmd("vs-drive-info", device=device, args=args)

    def _is_drive_info_available(self):
        """Return True if drive info is available for the current drive. """

        cls = type(self)
        if cls._drive_info_available is None:
            result = self._run_drive_info()
            cls._drive_info_available = not (
                result.returncode != 0 and _UNSUPPORTED_MSG in result.stderr
            )
        return cls._drive_info_available

    def _skip_if_unavailable(self):
        """Skip the calling test if the drive model is unsupported here."""
        if not self._is_drive_info_available():
            self.skipTest(
                f"vs-drive-info reports an unsupported drive on this platform "
                f"(stderr: {_UNSUPPORTED_MSG!r})"
            )

    def _drive_info_json(self, args="--format=json"):
        """Run vs-drive-info in JSON mode and return the parsed top-level dict.

        Skips the test if the drive is unsupported on this platform.
        """
        self._skip_if_unavailable()
        result = self.run_plugin_cmd_check("vs-drive-info", args=args)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"stdout is not valid JSON: {exc}\nstdout={result.stdout!r}")

    def _drive_info_object(self, args="--format=json"):
        """Return the single info object from the JSON array."""
        data = self._drive_info_json(args=args)
        self.assertIn(
            _MICRON_HW_INFORMATION_KEY, data,
            f"Expected top-level '{_MICRON_HW_INFORMATION_KEY}' key, "
            f"got: {list(data.keys())}",
        )
        array = data[_MICRON_HW_INFORMATION_KEY]
        self.assertIsInstance(
            array, list, f"'{_MICRON_HW_INFORMATION_KEY}' value must be a list"
        )
        self.assertEqual(
            len(array), 1,
            f"Expected exactly one info object, got {len(array)}",
        )
        return array[0]

    def _text_labels_present(self, stdout):
        """Return the set of known labels that appear as 'Label:' in text output."""
        present = set()
        for label in _ALL_LABELS:
            if re.search(r"^" + re.escape(label) + r"\s*:", stdout, re.MULTILINE):
                present.add(label)
        return present

    def test_bad_device_returns_error(self):
        """vs-drive-info fails with 'open failed' when the device does not exist.

        Exercises the parse_and_open failure branch.  Only the constant
        "open failed" prefix is asserted because the OS strerror text appended
        to it differs between Windows and Linux.
        """
        result = self._run_drive_info(device="/dev/nvme-nonexistent-test-device")

        self.assertNotEqual(
            result.returncode, 0,
            "Expected non-zero exit code for a non-existent device",
        )
        self.assertIn(
            "open failed", result.stderr,
            f"Expected 'open failed' in stderr, got: {result.stderr!r}",
        )

    def test_invalid_format_returns_error(self):
        """vs-drive-info fails for an unrecognised -f/--format value.

        Uses the command-local --format flag, which only accepts "normal" or
        "json".
        """
        result = self._run_drive_info(args="--format=notaformat")

        self.assertNotEqual(
            result.returncode, 0,
            "Expected non-zero exit code for an invalid --format value",
        )
        self.assertIn(
            "Invalid output format", result.stderr,
            f"Expected 'Invalid output format' in stderr, got: {result.stderr!r}",
        )

    def test_default_output_is_text(self):
        """vs-drive-info produces human-readable text by default.

        With no format flag the output is text, always includes the
        "Drive Hardware Version:" line, and must not parse as JSON.
        """
        self._skip_if_unavailable()
        result = self.run_plugin_cmd_check("vs-drive-info")

        self.assertRegex(
            result.stdout, r"Drive Hardware Version\s*:\s*\d+\.\d+",
            f"Expected 'Drive Hardware Version: <N.M>' in text output, "
            f"got: {result.stdout!r}",
        )
        with self.assertRaises((json.JSONDecodeError, ValueError),
                               msg="Default output must not be JSON"):
            json.loads(result.stdout)

    def test_explicit_normal_format_is_text(self):
        """vs-drive-info produces text output when --format=normal is passed."""
        self._skip_if_unavailable()
        result = self.run_plugin_cmd_check("vs-drive-info", args="--format=normal")

        self.assertRegex(
            result.stdout, r"Drive Hardware Version\s*:\s*\d+\.\d+",
            f"Expected 'Drive Hardware Version: <N.M>' with --format=normal, "
            f"got: {result.stdout!r}",
        )

    def test_format_json_produces_valid_json(self):
        """vs-drive-info produces valid JSON when --format=json is passed."""
        obj = self._drive_info_object(args="--format=json")
        self.assertIsInstance(obj, dict)

    def test_short_f_json_produces_valid_json(self):
        """vs-drive-info produces valid JSON when the short -f json flag is passed."""
        obj = self._drive_info_object(args="-f json")
        self.assertIsInstance(obj, dict)

    def test_json_top_level_is_single_element_array(self):
        """vs-drive-info wraps the info object in a one-element JSON array.

        The "Micron Drive HW Information" array holds exactly one object.
        """
        data = self._drive_info_json()
        array = data[_MICRON_HW_INFORMATION_KEY]

        self.assertIsInstance(array, list,
                              f"'{_MICRON_HW_INFORMATION_KEY}' must be a JSON array")
        self.assertEqual(len(array), 1,
                         f"Expected exactly one element, got {len(array)}")

    def test_json_always_has_drive_hardware_version(self):
        """vs-drive-info JSON output always contains 'Drive Hardware Version'.

        This field is emitted unconditionally as "<N>.<M>".
        """
        obj = self._drive_info_object()

        self.assertIn(
            _DRIVE_HW_VERSION, obj,
            f"Expected '{_DRIVE_HW_VERSION}' key, got: {list(obj.keys())}",
        )
        self.assertRegex(
            obj[_DRIVE_HW_VERSION], r"^\d+\.\d+$",
            f"Expected '<N>.<M>' HW version, got: {obj[_DRIVE_HW_VERSION]!r}",
        )

    def test_text_always_has_drive_hardware_version(self):
        """vs-drive-info text output always contains a 'Drive Hardware Version:' line."""
        self._skip_if_unavailable()
        result = self.run_plugin_cmd_check("vs-drive-info")

        self.assertRegex(
            result.stdout, r"Drive Hardware Version\s*:\s*\d+\.\d+",
            f"Expected 'Drive Hardware Version: <N.M>' line, got: {result.stdout!r}",
        )

    def test_json_has_no_unexpected_fields(self):
        """vs-drive-info JSON object contains only the documented fields.

        Any key outside the known label set indicates a regression where a
        new field was added without updating this test.
        """
        obj = self._drive_info_object()

        extra = set(obj.keys()) - set(_ALL_LABELS)
        self.assertFalse(
            extra,
            f"Unexpected extra keys in drive-info JSON object: {extra}",
        )

    def test_ftl_unit_size_format_if_present(self):
        """When present, 'FTL_unit_size' is formatted as '<N> B' or '<N> KB'.

        The units are model-dependent, and the field is emitted only when the
        FTL unit size is non-zero, so absence is acceptable.
        """
        obj = self._drive_info_object()
        if _FTL_UNIT_SIZE not in obj:
            self.skipTest("FTL_unit_size not reported by this drive (ftl_unit_size == 0)")

        self.assertRegex(
            obj[_FTL_UNIT_SIZE], r"^\d+ (B|KB)$",
            f"Expected FTL size as '<N> B' or '<N> KB', got: {obj[_FTL_UNIT_SIZE]!r}",
        )

    def test_boot_spec_version_present_in_both_or_neither(self):
        """'Boot Spec.Version' is emitted (or omitted) consistently in JSON and text.

        The field appears only on drives that report a boot-spec version; when
        present its value must be a non-empty string.
        """
        obj = self._drive_info_object()
        result_text = self.run_plugin_cmd_check("vs-drive-info")
        text_has = _BOOT_SPEC_VERSION in self._text_labels_present(result_text.stdout)
        json_has = _BOOT_SPEC_VERSION in obj

        self.assertEqual(
            json_has, text_has,
            f"'{_BOOT_SPEC_VERSION}' presence differs between JSON ({json_has}) "
            f"and text ({text_has})",
        )
        if json_has:
            self.assertTrue(
                obj[_BOOT_SPEC_VERSION].strip(),
                f"'{_BOOT_SPEC_VERSION}' JSON value must be non-empty, "
                f"got: {obj[_BOOT_SPEC_VERSION]!r}",
            )

    def test_ownership_status_value_if_present(self):
        """When present, 'Drive Ownership Status' is one of the four known states.

        This field is emitted only on certain drives; its value is one of
        N/A / UNSET / SET / BLOCKED.
        """
        obj = self._drive_info_object()
        if _OWNERSHIP_STATUS not in obj:
            self.skipTest("Drive Ownership Status not reported by this drive")

        self.assertIn(
            obj[_OWNERSHIP_STATUS], _OWNERSHIP_VALUES,
            f"Expected ownership status in {_OWNERSHIP_VALUES}, "
            f"got: {obj[_OWNERSHIP_STATUS]!r}",
        )

    def test_json_and_text_report_same_fields(self):
        """JSON keys and text 'Label:' lines expose the same set of fields.

        Both output formats are driven by the same data, so the set of emitted
        fields must match regardless of format.
        """
        obj = self._drive_info_object()
        json_labels = set(obj.keys())

        result_text = self.run_plugin_cmd_check("vs-drive-info")
        text_labels = self._text_labels_present(result_text.stdout)

        self.assertEqual(
            json_labels, text_labels,
            f"JSON and text output expose different fields:\n"
            f"  JSON: {sorted(json_labels)}\n"
            f"  text: {sorted(text_labels)}",
        )

    def test_hardware_version_matches_between_json_and_text(self):
        """The HW version value is identical in JSON and text output."""
        obj = self._drive_info_object()
        json_version = obj[_DRIVE_HW_VERSION]

        result_text = self.run_plugin_cmd_check("vs-drive-info")
        m = re.search(r"Drive Hardware Version\s*:\s*(\d+\.\d+)", result_text.stdout)
        self.assertIsNotNone(
            m,
            f"Could not parse HW version from text output: {result_text.stdout!r}",
        )

        self.assertEqual(
            json_version, m.group(1),
            f"HW version differs between JSON ({json_version!r}) and "
            f"text ({m.group(1)!r})",
        )

    def test_namespace_device_produces_same_fields_as_ctrl(self):
        """vs-drive-info yields the same JSON fields for the namespace path.

        A namespace path resolves to its parent controller, so the reported
        field set must match that of the controller path.
        """
        # Probe availability against the namespace path specifically.
        ns_probe = self.run_plugin_cmd("vs-drive-info", device=self.ns1)
        if ns_probe.returncode != 0 and _UNSUPPORTED_MSG in ns_probe.stderr:
            self.skipTest(
                f"vs-drive-info reports an unsupported drive on this platform "
                f"(stderr: {_UNSUPPORTED_MSG!r})"
            )

        result_ctrl = self.run_plugin_cmd_check(
            "vs-drive-info", device=self.ctrl, args="--format=json"
        )
        result_ns = self.run_plugin_cmd_check(
            "vs-drive-info", device=self.ns1, args="--format=json"
        )

        try:
            data_ctrl = json.loads(result_ctrl.stdout)
            data_ns = json.loads(result_ns.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"Output is not valid JSON: {exc}")

        keys_ctrl = set(data_ctrl[_MICRON_HW_INFORMATION_KEY][0].keys())
        keys_ns = set(data_ns[_MICRON_HW_INFORMATION_KEY][0].keys())

        self.assertEqual(
            keys_ctrl, keys_ns,
            f"Controller and namespace paths produced different field sets:\n"
            f"  ctrl ({self.ctrl}): {sorted(keys_ctrl)}\n"
            f"  ns1  ({self.ns1}):  {sorted(keys_ns)}",
        )
