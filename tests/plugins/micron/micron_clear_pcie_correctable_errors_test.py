# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron clear-pcie-correctable-errors command.

The clear-pcie-correctable-errors command resets the PCIe correctable
error status and has two model-dependent success paths:

  NVMe command path:
    Clears the correctable error status by issuing an NVMe command on
    drives that support it -- either an NVMe set-features command or a
    vendor-specific admin passthru command, depending on the model.
    This path does not read back or report a correctable-error value.

  AER/sysfs fallback path:
    Writes 0xffffffff to the correctable error status register (via the
    Linux AER sysfs interface) to clear all error bits, then reads the
    register back and prints the value to stdout.  On Windows, PCIe
    register writes are unsupported and drives without a dedicated clear
    command fail with -ENOTSUP.

Which path runs depends on the drive model present in the test
environment, so the tests probe for support and assert only the
behaviour common to whichever path is exercised.

Tests in this module verify:
  * Successful exit for controller and namespace device paths.
  * The verbose success message on stderr across every path, and the
    AER/sysfs read-back value on stdout.
  * A read-back correctable error count of zero after an AER clear.
  * Idempotency: clearing an already-cleared register still succeeds.
  * Error detection for a non-existent device (parse_and_open failure).
  * Graceful skipping when the platform does not support the command.
"""

import re

from tests.plugins.micron.micron_test import TestMicron

_WINDOWS_AER_UNSUPPORTED_MSG = "register writes not supported on the current platform"
_AER_STDOUT_MARKER = "Device correctable errors detected:"
_VERBOSE_CLEARED_MSG = "Device correctable errors cleared!"


class TestMicronClearPcieCorrectableErrors(TestMicron):
    """Test suite for the micron clear-pcie-correctable-errors plugin command."""

    def _run_clear(self, device=None, args=""):
        """Run clear-pcie-correctable-errors and return the CompletedProcess result."""
        return self.run_plugin_cmd(
            "clear-pcie-correctable-errors", device=device, args=args
        )

    def _is_clear_supported(self):
        """Return True if clear-pcie-correctable-errors is supported on this platform.

        On Windows, PCIE register writes are not supported, so drives without a
        dedicated command to clear the errors will fail with -ENOTSUP and the
        message "register writes not supported on the current platform".

        On Linux the AER sysfs path is always supported, so no probe is needed.
        """
        if not self.is_windows():
            return True
        result = self._run_clear()
        return not (
            result.returncode != 0 and _WINDOWS_AER_UNSUPPORTED_MSG in result.stderr
        )

    def _skip_if_clear_unavailable(self):
        """Skip the calling test if the clear command cannot succeed on this platform."""
        if not self._is_clear_supported():
            self.skipTest(
                "clear-pcie-correctable-errors is not supported on this platform "
                f"(stderr: {_WINDOWS_AER_UNSUPPORTED_MSG!r})"
            )

    def test_bad_device_returns_error(self):
        """clear-pcie-correctable-errors fails with a message when the device does not exist.

        Exercises the parse_and_open failure branch.
        """
        result = self._run_clear(device="/dev/nvme-nonexistent-test-device")

        self.assertNotEqual(
            result.returncode, 0,
            "Expected non-zero exit code for a non-existent device",
        )
        self.assertTrue(
            "open failed" in result.stderr,
            f"Expected 'open failed' in stderr, "
            f"got: {result.stderr!r}",
        )

    def test_command_exits_zero_on_success(self):
        """clear-pcie-correctable-errors exits 0 when the drive is reachable.

        Covers all hardware success paths. Which one is exercised depends on
        the drive model present in the test environment.
        """
        self._skip_if_clear_unavailable()
        result = self.run_plugin_cmd_check("clear-pcie-correctable-errors")

        self.assertEqual(
            result.returncode, 0,
            f"Expected exit code 0, got {result.returncode}; "
            f"stderr={result.stderr!r}",
        )

    def test_verbose_output_reports_cleared(self):
        """With --verbose, every code path reports success on stderr.

        All paths print the same verbose message to stderr.
        The AER/sysfs fallback path additionally prints the read-back
        correctable value to stdout.
        """
        self._skip_if_clear_unavailable()
        result = self.run_plugin_cmd_check(
            "clear-pcie-correctable-errors", args="--verbose"
        )
        stdout = result.stdout
        stderr = result.stderr

        # The verbose success message is emitted on every path.
        self.assertIn(
            _VERBOSE_CLEARED_MSG, stderr,
            f"Expected verbose message {_VERBOSE_CLEARED_MSG!r} in stderr, "
            f"got: {stderr!r}",
        )

        if _AER_STDOUT_MARKER in stdout:
            # AER/sysfs fallback path: read-back value is printed to stdout.
            self.assertRegex(
                stdout,
                rf"{re.escape(_AER_STDOUT_MARKER)}\s+[0-9a-fA-F]+",
                f"Expected '{_AER_STDOUT_MARKER} <hex>', got: {stdout!r}",
            )
        else:
            # NVMe command path: nothing is written to stdout.
            self.assertEqual(
                stdout, "",
                f"Expected no stdout on the NVMe command path, got: {stdout!r}",
            )

    def test_aer_path_reported_value_is_zero_after_clear(self):
        """After a clear, the read-back correctable error count is zero.

        The AER clear writes 0xffffffff to the correctable error status
        register, which clears all error bits.  Reading back
        the register immediately after should return 0x00000000.

        This test is skipped when the drive uses the NVMe command path
        (set-features or passthru) because that path does not read back and
        report a correctable-error value; success on those models is validated
        by test_verbose_output_reports_cleared instead.
        """
        self._skip_if_clear_unavailable()
        result = self.run_plugin_cmd_check("clear-pcie-correctable-errors")
        stdout = result.stdout

        if _AER_STDOUT_MARKER not in stdout:
            self.skipTest(
                "Drive uses the NVMe command path with no read-back value; "
                "post-clear value assertion applies only to the AER/sysfs path"
            )

        m = re.search(rf"{re.escape(_AER_STDOUT_MARKER)}\s+([0-9a-fA-F]+)", stdout)
        self.assertIsNotNone(
            m,
            f"Could not parse correctable error value from output: {stdout!r}",
        )
        reported = int(m.group(1), 16)
        self.assertEqual(
            reported, 0,
            f"Expected correctable error count to be 0x0 after clear, "
            f"got 0x{m.group(1)}",
        )

    def test_command_is_idempotent(self):
        """clear-pcie-correctable-errors can be called twice and both invocations succeed.

        Clearing an already-cleared register must not cause an error.  Both
        success paths (the NVMe command path and AER/sysfs) should behave
        idempotently.
        """
        self._skip_if_clear_unavailable()
        result1 = self.run_plugin_cmd_check("clear-pcie-correctable-errors")
        result2 = self.run_plugin_cmd_check("clear-pcie-correctable-errors")

        self.assertEqual(
            result1.returncode, 0,
            f"First invocation failed: rc={result1.returncode}, "
            f"stderr={result1.stderr!r}",
        )
        self.assertEqual(
            result2.returncode, 0,
            f"Second invocation failed: rc={result2.returncode}, "
            f"stderr={result2.stderr!r}",
        )

    def test_namespace_device_succeeds(self):
        """clear-pcie-correctable-errors exits 0 when given a namespace path.

        micron_parse_options resolves the namespace device to its parent
        controller, so the clear operation should succeed regardless of whether
        a controller or namespace path is passed.
        """
        if self.is_windows():
            ns_probe = self._run_clear(device=self.ns1)
            if (
                ns_probe.returncode != 0
                and _WINDOWS_AER_UNSUPPORTED_MSG in ns_probe.stderr
            ):
                self.skipTest(
                    "clear-pcie-correctable-errors is not supported on this platform "
                    f"(stderr: {_WINDOWS_AER_UNSUPPORTED_MSG!r})"
                )
            self.assertEqual(
                ns_probe.returncode, 0,
                f"Expected exit code 0 for namespace device, "
                f"got {ns_probe.returncode}; stderr={ns_probe.stderr!r}",
            )
        else:
            result = self.run_plugin_cmd_check(
                "clear-pcie-correctable-errors", device=self.ns1
            )
            self.assertEqual(
                result.returncode, 0,
                f"Expected exit code 0 for namespace device, "
                f"got {result.returncode}; stderr={result.stderr!r}",
            )
