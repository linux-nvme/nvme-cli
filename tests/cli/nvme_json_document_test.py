#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for the JSON document of a command line: nvme_main() prints it
once at the end, also for a command which parses its options twice.

Usage: python3 nvme_json_document_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
import json

from tests.cli.nvme_mock import MockTestCase, main


class JSONDocumentTest(MockTestCase):
    """Every command succeeds with zeroed data: an unknown drive."""

    def test_parsed_twice(self):
        # sndk vs-fw-activate-history falls back to the wdc command for a
        # drive without the C2 log, which parses the options again
        result = self.nvme('sndk', 'vs-fw-activate-history', self.ctrl,
                           '-o', 'json')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout),
                         {'error': 'ERROR: WDC: unsupported device for this command'},
                         result.stderr)


if __name__ == '__main__':
    main()
