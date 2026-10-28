# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
"""Tests of vm_create without a VM: the seed, the checksum, the image
check and the refusals."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from dvm_mcp import create as cr
from dvm_mcp.server import Server
from dvm_mcp.vm import VM, VMError

CHECKSUM = """\
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

# Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2: 583729152 bytes
SHA256 (Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2) = {sum}
SHA256 (Fedora-Cloud-Base-UEFI-UKI-44-1.7.x86_64.qcow2) = {other}
"""

NAME = 'Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2'


class TestSeed(unittest.TestCase):
    def test_user_data(self) -> None:
        ud = cr.user_data('ssh-ed25519 AAAA test')
        self.assertTrue(ud.startswith('#cloud-config\n'))
        self.assertIn('      - ssh-ed25519 AAAA test\n', ud)
        self.assertIn('  - xfsprogs\n', ud)
        self.assertIn('kernel-modules-extra', ud)

    @mock.patch('shutil.which', lambda t: None)
    def test_no_iso_tool(self) -> None:
        with self.assertRaises(VMError):
            cr.seed_cmd(Path('s.iso'), [Path('user-data')])

    @mock.patch('shutil.which', lambda t: '/usr/bin/' + t)
    def test_xorriso_first(self) -> None:
        cmd = cr.seed_cmd(Path('s.iso'), [Path('user-data')])
        self.assertEqual(cmd[0], 'xorriso')
        self.assertIn('cidata', cmd)


class TestChecksum(unittest.TestCase):
    def test_parse(self) -> None:
        text = CHECKSUM.format(sum='a' * 64, other='b' * 64)
        self.assertEqual(cr.parse_checksum(text, NAME), 'a' * 64)

    def test_missing(self) -> None:
        with self.assertRaises(VMError):
            cr.parse_checksum('nothing here\n', NAME)

    def _image(self, data: bytes, want: str) -> Path:
        def fetch(url: str, dest: Path) -> None:
            if url.endswith('CHECKSUM'):
                dest.write_text(CHECKSUM.format(sum=want, other='b' * 64))
            else:
                dest.write_bytes(data)

        with mock.patch.object(cr, 'fetch', fetch):
            return cr.image(self.dir, cr.IMAGE_URL, cr.CHECKSUM_URL)

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_image_ok(self) -> None:
        img = self._image(b'qcow2', hashlib.sha256(b'qcow2').hexdigest())
        self.assertEqual(img.name, NAME)
        self.assertTrue(img.exists())

    def test_image_bad_sum(self) -> None:
        with self.assertRaises(VMError):
            self._image(b'qcow2', 'c' * 64)
        self.assertFalse((self.dir / 'img' / NAME).exists())


class TestRefusals(unittest.TestCase):
    def test_existing_disk(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'disk.qcow2').write_text('')
            with self.assertRaises(VMError) as e:
                cr.create(VM(Path(d)), Path('/src'))
            self.assertIn('remove', str(e.exception))

    def test_running_vm(self) -> None:
        vm = mock.create_autospec(VM, instance=True)
        vm.running.return_value = True
        server = Server(vm, Path('/src'), True)
        resp = server.handle(
            {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'tools/call',
                'params': {'name': 'vm_create', 'arguments': {}},
            }
        )
        assert resp is not None
        result: dict[str, Any] = resp['result']
        self.assertTrue(result['isError'])
        self.assertIn('vm_stop', result['content'][0]['text'])


if __name__ == '__main__':
    unittest.main()
