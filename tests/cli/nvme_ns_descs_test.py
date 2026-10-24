#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for "nvme id ns-descs" against a mocked controller.

The Namespace Identification Descriptor list is a 4 KiB page of
descriptors, each a 4 byte header and NIDL bytes of identifier. The tests
check that every descriptor of the list is printed, whatever its order,
and that a descriptor which does not fit into the page ends the list.

Usage: python3 nvme_ns_descs_test.py <nvme-binary> <mock-lib>
"""
import json

from tests.cli.nvme_mock import CNS_NS_DESC_LIST, MockTestCase, main

_PAGE_SIZE = 4096

_NIDT_EUI64 = 1
_NIDT_NGUID = 2
_NIDT_UUID = 3
_NIDT_CSI = 4

_EUI64 = bytes(range(0x10, 0x18))
_NGUID = bytes(range(0x20, 0x30))
_UUID = bytes(range(0x30, 0x40))
_UUID_STR = '30313233-3435-3637-3839-3a3b3c3d3e3f'


def _desc(nidt, nid):
    return bytes([nidt, len(nid), 0, 0]) + nid


def _filler(size):
    """Descriptors of an unknown type, which are skipped, of @size bytes"""
    out = b''
    while size:
        n = min(size, 4 + 255)
        if size - n and size - n < 4:
            n -= 4
        out += _desc(0xff, bytes(n - 4))
        size -= n
    return out


class NsDescsTest(MockTestCase):
    """A controller which returns the descriptor list of a test."""

    def _set_page(self, descs):
        page = bytearray(_PAGE_SIZE)
        page[:len(descs)] = descs
        self.server.identify[CNS_NS_DESC_LIST] = page

    def _run(self, *args):
        return self.assertOk(self.nvme('id', 'ns-descs', self.ctrl, '-n',
                                       '1', *args)).stdout

    def _json(self):
        # Without a descriptor, there is no JSON document
        out = self._run('-o', 'json')
        return json.loads(out).get('ns-descs', []) if out.strip() else []

    def test_all_types(self):
        """Every descriptor is printed, also one behind a CSI descriptor."""
        self._set_page(_desc(_NIDT_EUI64, _EUI64) +
                       _desc(_NIDT_NGUID, _NGUID) +
                       _desc(_NIDT_CSI, b'\x02') +
                       _desc(_NIDT_UUID, _UUID))

        descs = self._json()
        self.assertEqual([(d['loc'], d['Type']) for d in descs],
                         [(0, 'eui64'), (12, 'nguid'), (32, 'csi'),
                          (37, 'uuid')])
        self.assertEqual(descs[0]['eui64'], _EUI64.hex())
        self.assertEqual(descs[1]['nguid'], _NGUID.hex())
        self.assertEqual(descs[2]['csi'], '0x2')
        self.assertEqual(descs[3]['uuid'], _UUID_STR)

        out = self._run()
        self.assertIn(_EUI64.hex(), out)
        self.assertIn(_NGUID.hex(), out)
        self.assertIn(_UUID_STR, out)

    def test_desc_past_end(self):
        """A descriptor whose identifier reaches past the page ends the
        list."""
        at = _PAGE_SIZE - 4 - 8
        uuid = bytearray(_desc(_NIDT_UUID, _UUID[:8]))
        uuid[1] = len(_UUID)
        self._set_page(_filler(at) + uuid)

        self.assertEqual(self._json(), [])
        self.assertNotIn('uuid', self._run())

    def test_wrong_length_skipped(self):
        """A known type of another length is skipped by its length."""
        self._set_page(_desc(_NIDT_UUID, _UUID[:8]) +
                       _desc(_NIDT_EUI64, _EUI64))

        self.assertEqual([(d['loc'], d['Type']) for d in self._json()],
                         [(12, 'eui64')])


if __name__ == '__main__':
    main()
