# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Base class for plugin tests."""

import logging

from tests.nvme_test import TestNVMe

logger = logging.getLogger(__name__)


class TestPlugin(TestNVMe):
    """Base class for all plugin tests.

    Subclasses must set the `plugin_name` class attribute to the plugin
    name as registered with nvme-cli (e.g., "micron", "ocp").
    """

    plugin_name = None

    def setUp(self):
        if self.plugin_name is None:
            self.fail("TestPlugin subclass must set plugin_name")
        super().setUp()
        self.setup_log_dir(self.__class__.__name__)
        # Verify the plugin is available
        ret = self.exec_cmd(f"{self.nvme_bin} {self.plugin_name} help")
        if ret != 0:
            self.skipTest(f"Plugin '{self.plugin_name}' not available")

    def run_plugin_cmd(self, command, device=None, args=""):
        """Run a plugin command and return the CompletedProcess result.

        Usage:
            result = self.run_plugin_cmd("vs-drive-info")
            result = self.run_plugin_cmd("smart-add-log", args="-o json")
            result = self.run_plugin_cmd("id-ctrl", device=self.ctrl)

        Args:
            command: The plugin subcommand name.
            device: Device path to operate on (defaults to self.ctrl).
            args: Additional arguments string.

        Returns:
            subprocess.CompletedProcess with returncode, stdout, stderr.
        """
        if device is None:
            device = self.ctrl
        cmd = f"{self.nvme_bin} {self.plugin_name} {command} {device} {args}".strip()
        return self.run_cmd(cmd)

    def run_plugin_cmd_check(self, command, device=None, args=""):
        """Run a plugin command and assert it succeeds (returncode == 0).

        Returns the CompletedProcess result on success.
        """
        result = self.run_plugin_cmd(command, device=device, args=args)
        self.assertEqual(result.returncode, 0,
                         f"Plugin command '{self.plugin_name} {command}' failed: "
                         f"rc={result.returncode}, stderr={result.stderr}")
        return result
