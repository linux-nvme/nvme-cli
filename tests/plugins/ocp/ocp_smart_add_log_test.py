# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
"""Test for OCP smart-add-log plugin command."""

from tests.plugins.ocp.ocp_test import TestOCP


class TestOCPSmartAddLog(TestOCP):
    """Verify that the ocp smart-add-log command executes successfully."""

    def test_smart_add_log(self):
        """Run ocp smart-add-log and verify it returns success."""
        self.run_plugin_cmd_check("smart-add-log")
