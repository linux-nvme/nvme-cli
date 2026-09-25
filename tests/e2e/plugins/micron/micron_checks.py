# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Output-shape assertions shared by the Micron mock and e2e test layers.

These only inspect what a command printed, so despite living beside the
hardware suites they need no drive: the hardware-free suites under
tests/cli/micron/ import the mixin from here too.  The mixin expects the
host class to provide run_plugin_cmd(), run_plugin_cmd_check() and
parse_json_output().
"""

import re

# A device path no drive can have, used to exercise the open failure path.
BAD_DEVICE = "/dev/nvme-nonexistent-test-device"

INVALID_FORMAT_MSG = "Invalid output format"

# generic_structure_parser() renders every field as "0x<hex>", except version
# fields such as "DSSD Spec Version", which are dotted hex ("2.5.0.0").
_FIELD_VALUE_RE = re.compile(
    r"^(?:0x[0-9a-fA-F]+|[0-9a-fA-F]+(?:\.[0-9a-fA-F]+)+)$"
)


class MicronChecksMixin:
    """Assertions on micron plugin output that need no particular drive."""

    def hex_fields_from_table(self, stdout, context=""):
        """Return the {label: value} pairs of a named hex field table.

        Expects print_log() style text output: one "%-40s : %-4s" line per
        field, optionally preceded by a header line with no " : " separator
        (for example "SMART Extended Log:0xE1").
        """
        where = f" ({context})" if context else ""
        fields = {}
        for line in stdout.splitlines():
            if " : " not in line:
                continue
            label, _, value = line.partition(" : ")
            label, value = label.strip(), value.strip()
            self.assertRegex(
                value, _FIELD_VALUE_RE,
                f"Field {label!r} value is not hex or dotted hex{where}: "
                f"{value!r}",
            )
            self.assertNotIn(
                label, fields,
                f"Duplicate field label {label!r} in output{where}",
            )
            fields[label] = value
        self.assertGreater(
            len(fields), 0,
            f"Expected at least one 'label : value' field line{where}, "
            f"got: {stdout!r}",
        )
        return fields

    def hex_fields_from_json(self, data, allowed_keys, context=""):
        """Return the {label: value} pairs of a hex field JSON object.

        Expects print_log() style JSON output. The JSON format is a single
        top-level key mapping to a one-element array of field objects.
        """
        where = f" ({context})" if context else ""
        self.assertEqual(
            len(data), 1,
            f"Expected exactly one top-level JSON key{where}, "
            f"got: {list(data.keys())}",
        )
        key = next(iter(data))
        self.assertIn(
            key, allowed_keys,
            f"Unexpected top-level JSON key {key!r}{where}, "
            f"expected one of: {list(allowed_keys)}",
        )

        log_pages = data[key]
        self.assertIsInstance(
            log_pages, list,
            f"Expected {key!r} to hold an array{where}, "
            f"got: {type(log_pages)}",
        )
        self.assertEqual(
            len(log_pages), 1,
            f"Expected exactly one entry under {key!r}{where}, "
            f"got {len(log_pages)}",
        )

        fields = log_pages[0]
        self.assertIsInstance(
            fields, dict,
            f"Expected an object under {key!r}{where}, got: {type(fields)}",
        )
        self.assertGreater(
            len(fields), 0,
            f"Expected at least one field under {key!r}{where}",
        )
        for label, value in fields.items():
            self.assertRegex(
                value, _FIELD_VALUE_RE,
                f"Field {label!r} value is not hex or dotted hex{where}: "
                f"{value!r}",
            )
        return fields

    def check_bad_device_name(self, command, args=""):
        """A non-existent device must fail and name the device.

        Only the device path is asserted; the OS strerror text appended to it
        differs between Windows and Linux.
        """
        result = self.run_plugin_cmd(command, device=BAD_DEVICE, args=args)

        self.assertNotEqual(
            result.returncode, 0,
            f"Expected non-zero exit from micron {command} for a "
            f"non-existent device",
        )
        self.assertIn(
            BAD_DEVICE, result.stderr,
            f"Expected {BAD_DEVICE!r} in stderr of micron {command}, "
            f"got: {result.stderr!r}",
        )
        return result

    def check_output_format_rejected(self, command, value):
        """An --output-format the command lacks must be rejected."""
        result = self.run_plugin_cmd(command, args=f"--output-format={value}")

        self.assertNotEqual(
            result.returncode, 0,
            f"Expected micron {command} to reject --output-format={value}",
        )
        self.assertIn(
            INVALID_FORMAT_MSG, result.stderr,
            f"Expected {INVALID_FORMAT_MSG!r} in stderr of micron {command}, "
            f"got: {result.stderr!r}",
        )
        return result
