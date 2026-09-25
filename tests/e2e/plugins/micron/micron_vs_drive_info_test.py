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
--output-format=json is passed.

Every model and customer-ID branch, each field's format and the option
surface are covered without hardware in micron_vs_drive_info_mock_test.py.
The tests here check that a real drive reports plausible values in both formats.

Tests in this module verify:
  * The always-present "Drive Hardware Version" field, and the format of the
    optional FTL size and ownership-status fields when present.
  * Consistency of the hardware version between JSON and text.
  * Equivalent results for the controller and namespace device paths.
"""

import re

from .micron_test import TestMicron

_COMMAND = "vs-drive-info"

_MICRON_HW_INFORMATION_KEY = "Micron Drive HW Information"
_UNSUPPORTED_MSG = f"Unsupported drive for {_COMMAND} cmd"

# Field labels shared by the JSON (keys) and text ("Label: value") branches.
_DRIVE_HW_VERSION = "Drive Hardware Version"
_FTL_UNIT_SIZE = "FTL_unit_size"
_OWNERSHIP_STATUS = "Drive Ownership Status"

_OWNERSHIP_VALUES = {"N/A", "UNSET", "SET", "BLOCKED"}


class TestMicronVsDriveInfo(TestMicron):
    """Test suite for the micron vs-drive-info plugin command."""

    # Cached result of the drive info availability probe.
    # None means "not yet probed".
    _drive_info_available = None

    def _run_drive_info(self, device=None, args=""):
        """Run vs-drive-info and return the CompletedProcess result."""
        return self.run_plugin_cmd(_COMMAND, device=device, args=args)

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

    def _drive_info_json(self, args="--output-format=json"):
        """Run vs-drive-info in JSON mode and return the parsed top-level dict.

        Skips the test if the drive is unsupported on this platform.
        """
        self._skip_if_unavailable()
        result = self.run_plugin_cmd_check(_COMMAND, args=args)
        return self.parse_json_output(result.stdout, f"micron {_COMMAND} {args}")

    def _drive_info_object(self, args="--output-format=json"):
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
        result = self.run_plugin_cmd_check(_COMMAND)

        self.assertRegex(
            result.stdout, r"Drive Hardware Version\s*:\s*\d+\.\d+",
            f"Expected 'Drive Hardware Version: <N.M>' line, got: {result.stdout!r}",
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

    def test_hardware_version_matches_between_json_and_text(self):
        """The HW version value is identical in JSON and text output."""
        obj = self._drive_info_object()
        json_version = obj[_DRIVE_HW_VERSION]

        result_text = self.run_plugin_cmd_check(_COMMAND)
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
        ns_probe = self.run_plugin_cmd(_COMMAND, device=self.ns1)
        if ns_probe.returncode != 0 and _UNSUPPORTED_MSG in ns_probe.stderr:
            self.skipTest(
                f"vs-drive-info reports an unsupported drive on this platform "
                f"(stderr: {_UNSUPPORTED_MSG!r})"
            )

        data_ctrl = self.run_supported_cmd_json(_COMMAND, device=self.ctrl)
        data_ns = self.run_supported_cmd_json(_COMMAND, device=self.ns1)

        keys_ctrl = set(data_ctrl[_MICRON_HW_INFORMATION_KEY][0].keys())
        keys_ns = set(data_ns[_MICRON_HW_INFORMATION_KEY][0].keys())

        self.assertEqual(
            keys_ctrl, keys_ns,
            f"Controller and namespace paths produced different field sets:\n"
            f"  ctrl ({self.ctrl}): {sorted(keys_ctrl)}\n"
            f"  ns1  ({self.ns1}):  {sorted(keys_ns)}",
        )
