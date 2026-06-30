# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
"""Test for Micron vs-drive-info plugin command."""

from tests.plugins.micron.micron_test import TestMicron


class TestMicronDriveInfo(TestMicron):
    """Verify that the micron vs-drive-info command executes successfully."""

    def test_vs_drive_info(self):
        """Run micron vs-drive-info and verify it returns success."""
        self.run_plugin_cmd_check("vs-drive-info")
