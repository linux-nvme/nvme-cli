#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
"""CLI integration tests for the 'nvme registry' plugin.

Tests invoke the nvme binary directly with NVME_REGISTRY_DIR pointing at a
temporary directory, so no real NVMe hardware is needed.

Usage: python3 nvme_registry_test.py <path-to-nvme-binary>
"""
import os
import subprocess
import sys
import tempfile
import unittest


# Capture the nvme binary path from argv before unittest.main() strips it.
_NVME_BIN = sys.argv[1] \
    if len(sys.argv) > 1 and not sys.argv[1].startswith('-') \
    else 'nvme'


class RegistryCLITest(unittest.TestCase):

    def setUp(self):
        # dir='/tmp' is required: nvme confines NVME_REGISTRY_DIR to /tmp.
        self.tmpdir = tempfile.mkdtemp(prefix='nvme-registry-cli-test-', dir='/tmp')
        self.env = os.environ.copy()
        self.env['NVME_REGISTRY_DIR'] = self.tmpdir

    def tearDown(self):
        for entry in os.scandir(self.tmpdir):
            if entry.is_dir(follow_symlinks=False):
                for attr in os.scandir(entry.path):
                    os.unlink(attr.path)
                os.rmdir(entry.path)
        os.rmdir(self.tmpdir)

    def _run(self, *args, expect_fail=False):
        cmd = [_NVME_BIN] + list(args)
        # stdin is /dev/null so the owner-change confirmation prompt sees a
        # non-interactive caller and proceeds without asking.
        result = subprocess.run(cmd, env=self.env,
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                encoding='utf-8')
        if not expect_fail:
            self.assertEqual(result.returncode, 0,
                             f'Command {cmd} failed:\n{result.stderr}')
        return result

    def _populate(self, device, attr, value):
        dev_dir = os.path.join(self.tmpdir, device)
        os.makedirs(dev_dir, exist_ok=True)
        with open(os.path.join(dev_dir, attr), 'w') as f:
            f.write(value + '\n')

    # ------------------------------------------------------------------ #
    # retrieve                                                             #
    # ------------------------------------------------------------------ #

    def test_retrieve_returns_value(self):
        self._populate('nvme3', 'owner', 'stas')
        result = self._run('registry', 'retrieve', 'nvme3', '-a', 'owner')
        self.assertEqual(result.stdout.strip(), 'stas')

    def test_retrieve_requires_attr(self):
        self._populate('nvme3', 'owner', 'nbft')
        result = self._run('registry', 'retrieve', 'nvme3', expect_fail=True)
        self.assertNotEqual(result.returncode, 0)

    def test_retrieve_strips_dev_prefix(self):
        self._populate('nvme3', 'owner', 'stas')
        result = self._run('registry', 'retrieve', '/dev/nvme3', '-a', 'owner')
        self.assertEqual(result.stdout.strip(), 'stas')

    def test_retrieve_missing_device_fails(self):
        result = self._run('registry', 'retrieve', 'nvme99', '-a', 'owner',
                           expect_fail=True)
        self.assertNotEqual(result.returncode, 0)

    def test_retrieve_missing_device_arg_fails(self):
        result = self._run('registry', 'retrieve', '-a', 'owner',
                           expect_fail=True)
        self.assertNotEqual(result.returncode, 0)

    # ------------------------------------------------------------------ #
    # update                                                               #
    # ------------------------------------------------------------------ #

    def test_update_creates_entry(self):
        self._run('registry', 'update', 'nvme5',
                  '-a', 'note', '-V', 'boot-path SAN connection')
        result = self._run('registry', 'retrieve', 'nvme5', '-a', 'note')
        self.assertEqual(result.stdout.strip(), 'boot-path SAN connection')

    def test_update_overwrites_entry(self):
        self._populate('nvme5', 'note', 'old note')
        self._run('registry', 'update', 'nvme5',
                  '-a', 'note', '-V', 'new note')
        result = self._run('registry', 'retrieve', 'nvme5', '-a', 'note')
        self.assertEqual(result.stdout.strip(), 'new note')

    def test_update_owner_succeeds_noninteractive(self):
        # Writing the owner attribute is gated by a confirmation prompt, but a
        # non-interactive caller proceeds without asking.
        self._run('registry', 'update', 'nvme5', '-a', 'owner', '-V', 'stas')
        result = self._run('registry', 'retrieve', 'nvme5', '-a', 'owner')
        self.assertEqual(result.stdout.strip(), 'stas')

    def test_update_missing_args_fails(self):
        result = self._run('registry', 'update', 'nvme5',
                           expect_fail=True)
        self.assertNotEqual(result.returncode, 0)

    # ------------------------------------------------------------------ #
    # delete                                                               #
    # ------------------------------------------------------------------ #

    def test_delete_removes_entry(self):
        self._populate('nvme5', 'owner', 'stas')
        self._run('registry', 'delete', 'nvme5')
        result = self._run('registry', 'retrieve', 'nvme5', '-a', 'owner',
                           expect_fail=True)
        self.assertNotEqual(result.returncode, 0)

    def test_delete_nonexistent_fails(self):
        result = self._run('registry', 'delete', 'nvme99',
                           expect_fail=True)
        self.assertNotEqual(result.returncode, 0)

    def test_delete_missing_device_arg_fails(self):
        result = self._run('registry', 'delete', expect_fail=True)
        self.assertNotEqual(result.returncode, 0)

    # ------------------------------------------------------------------ #
    # list                                                                 #
    # ------------------------------------------------------------------ #

    def test_list_empty_registry_succeeds(self):
        result = self._run('registry', 'list')
        self.assertEqual(result.returncode, 0)

    def test_list_runs_without_error_with_entries(self):
        # Entries exist but /dev/nvmeN nodes don't, so list skips them.
        # Verify the command exits 0 regardless.
        self._populate('nvme1', 'owner', 'stas')
        self._populate('nvme2', 'owner', 'nbft')
        result = self._run('registry', 'list')
        self.assertEqual(result.returncode, 0)


if __name__ == '__main__':
    # Remove the binary path from argv so unittest.main() doesn't see it.
    if len(sys.argv) >= 2 and not sys.argv[1].startswith('-'):
        del sys.argv[1]
    unittest.main()
