# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
"""Test for OCP smart-add-log plugin command."""

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


class TestOCPSmartAddLog(TestOCP):
    """Verify that the ocp smart-add-log command executes successfully."""

    def test_smart_add_log(self):
        """Run ocp smart-add-log and verify it returns success."""
        result = self.run_plugin_cmd("smart-add-log")
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
