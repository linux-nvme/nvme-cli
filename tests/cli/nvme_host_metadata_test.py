#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the printing of the Controller Metadata feature: the element
descriptors are walked within the 4096 byte structure, whatever lengths
the device reports, and each value is printed with its length.

Usage: python3 nvme_host_metadata_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
import json
import struct

from tests.cli.nvme_mock import HAVE_JSON, MockTestCase, main

_FID_HOST_METADATA = 0x7e
_HOST_METADATA_SIZE = 4096


def element(etype, value, length=None):
    """An element descriptor: type, revision, length and value."""
    return struct.pack('<BBH', etype, 1,
                       len(value) if length is None else length) + value


class HostMetadataCLITest(MockTestCase):

    def _get_feature(self, *args):
        return self.assertOk(self.nvme('get-feature', self.ctrl,
                                       '--feature-id=0x7e', '--verbose',
                                       *args)).stdout

    def _metadata(self, *elements):
        metadata = bytes([len(elements), 0]) + b''.join(elements)
        self.server.features[_FID_HOST_METADATA] = metadata.ljust(
            _HOST_METADATA_SIZE, b'\xaa')

    def test_values(self):
        """Each value is printed with its length, not up to a NUL."""
        self._metadata(element(1, b'host'), element(2, b'abc'))
        out = self._get_feature()
        self.assertIn('host\n', out)
        self.assertIn('abc\n', out)
        self.assertNotIn('hostabc', out)

    def test_length_past_the_end(self):
        """A length beyond the structure stops the walk at its end."""
        self._metadata(element(1, b'first'),
                       element(2, b'second', length=0xffff),
                       element(3, b'never'))
        formats = [[]]
        if HAVE_JSON:
            formats.append(['--output-format=json'])
        for fmt in formats:
            with self.subTest(fmt=fmt):
                out = self._get_feature(*fmt)
                self.assertIn('first', out)
                self.assertIn('second', out)
                self.assertNotIn('never', out)
                if fmt:
                    descs = json.loads(out)['Feature: 0x7e'][0][
                        'Metadata Element Descriptors']
                    self.assertEqual(len(descs), 2)
                    self.assertEqual(descs[1]['Length'], 0xffff)


if __name__ == '__main__':
    main()
