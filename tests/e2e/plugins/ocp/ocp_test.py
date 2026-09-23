# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Base class for OCP plugin tests."""

import json
import logging

from ..plugin_test import TestPlugin

logger = logging.getLogger(__name__)

_NO_UUID_ARG = "--no-uuid"

# ocp_get_uuid_index() fails when the OCP vendor UUID is not in the drive's
# UUID list -- OCP 1.0 drives publish no such entry at all. The affected
# commands can still be read using UUID index 0 by specifying --no-uuid.
#
# The lookup's own message is only ever seen in plain-text output: JSON output
# keeps just the last error written, which is the command's own summary line.
# That line carries the -ENOENT the lookup returned, so match its errno too.
_MISSING_UUID_INDEX_MSGS = (
    "ERROR : OCP : No OCP UUID index found",
    "ret = -2",
)

# Whether an OCP subcommand needs --no-uuid on a given drive, keyed by
# (nvme_bin, plugin_name, command, device) so each is probed at most once per
# process -- see run_ocp_cmd().
_no_uuid_cache = {}


class TestOCP(TestPlugin):
    """Base class for OCP plugin tests.

    Provides the plugin_name and any OCP-specific helpers.
    """

    plugin_name = "ocp"

    def run_ocp_cmd(self, command, device=None, args=""):
        """Run an OCP command, falling back to --no-uuid when the drive has
        no usable OCP UUID index, and return the CompletedProcess result.

        The fallback is decided once per command and drive: later runs go
        straight to the form that works. A failure that is not the UUID
        lookup's, or one that --no-uuid does not cure, is reported as the
        plain run left it.
        """
        if device is None:
            device = self.ctrl
        key = (self.nvme_bin, self.plugin_name, command, device)

        if _no_uuid_cache.get(key):
            return self.run_plugin_cmd(command, device=device,
                                       args=f"{args} {_NO_UUID_ARG}".strip())

        result = self.run_plugin_cmd(command, device=device, args=args)
        if result.returncode == 0:
            _no_uuid_cache[key] = False
            return result
        if not self.missing_uuid_index(result):
            return result

        retry = self.run_plugin_cmd(command, device=device,
                                    args=f"{args} {_NO_UUID_ARG}".strip())
        if retry.returncode != 0:
            # --no-uuid is not what stands in the way, so don't run the
            # drive through it twice for every later call.
            _no_uuid_cache[key] = False
            return result

        if not _no_uuid_cache.get(key):
            logger.info("%s %s: no usable OCP UUID index on %s, retrying "
                        "with %s", self.plugin_name, command, device,
                        _NO_UUID_ARG)
        _no_uuid_cache[key] = True
        return retry

    def ocp_uses_no_uuid(self, command, device=None):
        """Return whether @command needs --no-uuid on this drive.

        False until run_ocp_cmd() has probed it. Callers that read the same
        page themselves have to request it with the UUID index the plugin
        used, so they need this answer.
        """
        if device is None:
            device = self.ctrl
        return bool(_no_uuid_cache.get(
            (self.nvme_bin, self.plugin_name, command, device)))

    @staticmethod
    def ocp_error_text(result):
        """Return the error text a failed OCP command reported.

        -o json is meant to be parsed by machines, not scraped as text, so
        prefer reading its structured "error" field over guessing which
        stream carries the message: nvme-cli folds error text that would
        otherwise go to stderr into that field instead when JSON output was
        requested, and keeps only the last message written. Plain-text runs
        put every message on stderr.
        """
        try:
            error = json.loads(result.stdout).get("error")
        except (TypeError, ValueError, AttributeError):
            error = None
        if error is not None:
            return error
        return "\n".join(part for part in (result.stdout, result.stderr)
                         if part)

    @classmethod
    def missing_uuid_index(cls, result):
        """Return whether a failed run failed for want of a UUID index."""
        text = cls.ocp_error_text(result)
        return any(msg in text for msg in _MISSING_UUID_INDEX_MSGS)
