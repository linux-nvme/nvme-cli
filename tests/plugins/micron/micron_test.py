# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Base class for Micron plugin tests."""

from tests.plugins.plugin_test import TestPlugin


class TestMicron(TestPlugin):
    """Base class for Micron plugin tests.

    Provides the plugin_name and any Micron-specific helpers.
    """

    plugin_name = "micron"
