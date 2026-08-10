# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Base class for OCP plugin tests."""

from ..plugin_test import TestPlugin


class TestOCP(TestPlugin):
    """Base class for OCP plugin tests.

    Provides the plugin_name and any OCP-specific helpers.
    """

    plugin_name = "ocp"
