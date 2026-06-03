#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Unit tests for the registry Python bindings.

NVME_REGISTRY_DIR must be set before importing libnvme so that _registry_dir
is cached with the test path at module load time.  This module sets it at the
top level before the import.
"""
import multiprocessing
import os
import tempfile
import unittest

# meson sets VALGRIND_OPTS when running under valgrind.  Forked child
# processes under valgrind can behave unexpectedly; the parallel write
# test is already covered by the C test suite (libnvme/test/registry.c).
_under_valgrind = 'VALGRIND_OPTS' in os.environ

_tmpdir = tempfile.mkdtemp(prefix='nvme-registry-test-')
os.environ['NVME_REGISTRY_DIR'] = _tmpdir

from libnvme import nvme  # noqa: E402  (import after env var set intentionally)


def _teardown_tmpdir():
    """Remove the test registry directory tree."""
    for entry in os.scandir(_tmpdir):
        if entry.is_dir():
            for attr in os.scandir(entry.path):
                os.unlink(attr.path)
            os.rmdir(entry.path)
    os.rmdir(_tmpdir)


class TestRegistryUpdate(unittest.TestCase):

    def tearDown(self):
        nvme.registry_delete('nvme5')

    def test_update_creates_entry(self):
        nvme.registry_update('nvme5', 'owner', 'stas')
        value = nvme.registry_retrieve('nvme5', 'owner')
        self.assertEqual(value, 'stas')

    def test_update_steals_ownership(self):
        nvme.registry_update('nvme5', 'owner', 'nbft')
        nvme.registry_update('nvme5', 'owner', 'stas')
        value = nvme.registry_retrieve('nvme5', 'owner')
        self.assertEqual(value, 'stas')

    def test_update_multiple_attrs(self):
        nvme.registry_update('nvme5', 'owner', 'stas')
        nvme.registry_update('nvme5', 'extra', 'hello')
        self.assertEqual(nvme.registry_retrieve('nvme5', 'owner'), 'stas')
        self.assertEqual(nvme.registry_retrieve('nvme5', 'extra'), 'hello')


class TestRegistryRetrieve(unittest.TestCase):

    def test_retrieve_unregistered_returns_none(self):
        value = nvme.registry_retrieve('nvme99', 'owner')
        self.assertIsNone(value)

    def test_retrieve_missing_attr_returns_none(self):
        nvme.registry_update('nvme6', 'owner', 'stas')
        value = nvme.registry_retrieve('nvme6', 'nosuchattr')
        nvme.registry_delete('nvme6')
        self.assertIsNone(value)


class TestRegistryDelete(unittest.TestCase):

    def test_delete_removes_entry(self):
        nvme.registry_update('nvme7', 'owner', 'stas')
        nvme.registry_delete('nvme7')
        self.assertIsNone(nvme.registry_retrieve('nvme7', 'owner'))

    def test_delete_nonexistent_raises(self):
        with self.assertRaises(FileNotFoundError):
            nvme.registry_delete('nvme99')


class TestRegistryEntries(unittest.TestCase):
    """registry_entries() skips entries with no /dev/nvmeN node (all of them
    in a test environment), so we verify it runs without error and returns
    an iterable."""

    def setUp(self):
        nvme.registry_update('nvme1', 'owner', 'stas')
        nvme.registry_update('nvme2', 'owner', 'nbft')

    def tearDown(self):
        nvme.registry_delete('nvme1')
        nvme.registry_delete('nvme2')

    def test_entries_returns_iterable(self):
        entries = list(nvme.registry_entries())
        # All entries are stale (no /dev/nvme* in test environment) — list is empty.
        self.assertIsInstance(entries, list)

    def test_entries_skips_stale(self):
        for device, attrs in nvme.registry_entries():
            self.assertTrue(os.path.exists('/dev/' + device))


def _writer(device, owner, iterations):
    """Child process: repeatedly update the owner attribute."""
    for _ in range(iterations):
        nvme.registry_update(device, 'owner', owner)


class TestRegistryParallelWrites(unittest.TestCase):
    """Verify that concurrent writes from multiple processes do not corrupt
    the registry.  The atomic tmp->rename write protocol must ensure the
    final value is always one of the two written strings."""

    @unittest.skipIf(_under_valgrind, "skipped under valgrind — covered by C test")
    def test_parallel_writes_no_corruption(self):
        nprocs = 10
        owners = [f'proc{i}' for i in range(nprocs)]

        nvme.registry_update('nvme10', 'owner', 'parent')

        procs = [multiprocessing.Process(target=_writer, args=('nvme10', owner, 200))
                 for owner in owners]
        for p in procs:
            p.start()
        for p in procs:
            p.join()

        value = nvme.registry_retrieve('nvme10', 'owner')
        nvme.registry_delete('nvme10')

        self.assertIn(value, owners, f'corrupted value: {value!r}')


if __name__ == '__main__':
    try:
        unittest.main()
    finally:
        _teardown_tmpdir()
