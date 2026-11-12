#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Unit tests for the registry Python bindings.

All tests share a single /tmp sandbox directory, applied to each GlobalCtx via
ctx.set_test_base_dir().  This mirrors production, where there is exactly one
registry directory.  The registry reads only the entries of controllers in
sysfs, so the sandbox also holds sys/class/nvme/nvme0..nvme10
(ctx.set_test_sysfs_dir()).
"""
import multiprocessing
import os
import shutil
import tempfile
import unittest

from libnvme3 import nvme

# meson sets VALGRIND_OPTS when running under valgrind.  Forked child
# processes under valgrind can behave unexpectedly; the parallel write
# test is already covered by the C test suite (libnvme/test/registry.c).
_under_valgrind = 'VALGRIND_OPTS' in os.environ

# A single sandbox shared by every test (one registry dir, as in production).
# dir='/tmp' is required: libnvme confines the test base dir to /tmp.
_tmpdir = None
_regdir = None
_ctrldir = None


def setUpModule():
    global _tmpdir, _regdir, _ctrldir
    _tmpdir = tempfile.mkdtemp(prefix='nvme-registry-test-', dir='/tmp')
    _regdir = os.path.join(_tmpdir, 'registry')
    _ctrldir = os.path.join(_tmpdir, 'sys/class/nvme')
    for i in range(11):
        os.makedirs(os.path.join(_ctrldir, f'nvme{i}'))


def tearDownModule():
    """Remove the test registry directory tree."""
    if _tmpdir:
        shutil.rmtree(os.path.join(_tmpdir, 'sys'), ignore_errors=True)
    if _regdir and os.path.isdir(_regdir):
        for entry in os.scandir(_regdir):
            if entry.is_dir():
                for attr in os.scandir(entry.path):
                    os.unlink(attr.path)
                os.rmdir(entry.path)
        os.rmdir(_regdir)
    if _tmpdir:
        os.rmdir(_tmpdir)


def _new_ctx(tmpdir):
    """Create a GlobalCtx pointed at the shared /tmp sandbox."""
    ctx = nvme.GlobalCtx()
    assert ctx.set_test_base_dir(tmpdir) == 0
    assert ctx.set_test_sysfs_dir(tmpdir) == 0
    return ctx


class TestRegistryUpdate(unittest.TestCase):
    def setUp(self):
        self.ctx = _new_ctx(_tmpdir)

    def tearDown(self):
        nvme.registry_delete(self.ctx, 'nvme5')
        self.ctx = None

    def test_update_creates_entry(self):
        nvme.registry_update(self.ctx, 'nvme5', 'owner', 'stas')
        value = nvme.registry_retrieve(self.ctx, 'nvme5', 'owner')
        self.assertEqual(value, 'stas')

    def test_update_steals_ownership(self):
        nvme.registry_update(self.ctx, 'nvme5', 'owner', 'nbft')
        nvme.registry_update(self.ctx, 'nvme5', 'owner', 'stas')
        value = nvme.registry_retrieve(self.ctx, 'nvme5', 'owner')
        self.assertEqual(value, 'stas')

    def test_update_multiple_attrs(self):
        nvme.registry_update(self.ctx, 'nvme5', 'owner', 'stas')
        nvme.registry_update(self.ctx, 'nvme5', 'extra', 'hello')
        self.assertEqual(nvme.registry_retrieve(self.ctx, 'nvme5', 'owner'), 'stas')
        self.assertEqual(nvme.registry_retrieve(self.ctx, 'nvme5', 'extra'), 'hello')


class TestRegistryRetrieve(unittest.TestCase):
    def setUp(self):
        self.ctx = _new_ctx(_tmpdir)

    def tearDown(self):
        self.ctx = None

    def test_retrieve_unregistered_returns_none(self):
        value = nvme.registry_retrieve(self.ctx, 'nvme99', 'owner')
        self.assertIsNone(value)

    def test_retrieve_missing_attr_returns_none(self):
        nvme.registry_update(self.ctx, 'nvme6', 'owner', 'stas')
        value = nvme.registry_retrieve(self.ctx, 'nvme6', 'nosuchattr')
        nvme.registry_delete(self.ctx, 'nvme6')
        self.assertIsNone(value)


class TestRegistryDelete(unittest.TestCase):
    def setUp(self):
        self.ctx = _new_ctx(_tmpdir)

    def tearDown(self):
        self.ctx = None

    def test_delete_removes_entry(self):
        nvme.registry_update(self.ctx, 'nvme7', 'owner', 'stas')
        nvme.registry_delete(self.ctx, 'nvme7')
        self.assertIsNone(nvme.registry_retrieve(self.ctx, 'nvme7', 'owner'))

    def test_delete_nonexistent_raises(self):
        with self.assertRaises(FileNotFoundError):
            nvme.registry_delete(self.ctx, 'nvme99')


class TestRegistryEntries(unittest.TestCase):
    """registry_entries() and registry_retrieve() skip the entry of a
    controller that is not in sysfs: nvme2's controller is removed."""

    def setUp(self):
        self.ctx = _new_ctx(_tmpdir)
        nvme.registry_update(self.ctx, 'nvme1', 'owner', 'stas')
        nvme.registry_update(self.ctx, 'nvme2', 'owner', 'nbft')
        os.rmdir(os.path.join(_ctrldir, 'nvme2'))

    def tearDown(self):
        os.makedirs(os.path.join(_ctrldir, 'nvme2'), exist_ok=True)
        nvme.registry_delete(self.ctx, 'nvme1')
        nvme.registry_delete(self.ctx, 'nvme2')
        self.ctx = None

    def test_entries_skips_stale(self):
        devices = [device for device, attrs in
                   nvme.registry_entries(self.ctx)]
        self.assertEqual(devices, ['nvme1'])

    def test_retrieve_stale_returns_none(self):
        self.assertIsNone(nvme.registry_retrieve(self.ctx, 'nvme2', 'owner'))


def _writer(device, owner, iterations, tmpdir):
    """Child process: repeatedly update the owner attribute.

    Each process creates its own GlobalCtx pointed at the shared sandbox.  A
    libnvme context must not be shared across a process boundary: passing it as
    a Process argument is not picklable under the spawn/forkserver start
    methods, and even under fork a context is not designed to be used
    concurrently from two processes.  The sandbox path is passed explicitly so
    the child writes into the same registry directory as the parent.
    """
    ctx = _new_ctx(tmpdir)
    for _ in range(iterations):
        nvme.registry_update(ctx, device, 'owner', owner)


class TestRegistryParallelWrites(unittest.TestCase):
    """Verify that concurrent writes from multiple processes do not corrupt
    the registry.  The atomic tmp->rename write protocol must ensure the
    final value is always one of the two written strings."""
    def setUp(self):
        self.ctx = _new_ctx(_tmpdir)

    def tearDown(self):
        self.ctx = None

    @unittest.skipIf(_under_valgrind, "skipped under valgrind — covered by C test")
    def test_parallel_writes_no_corruption(self):
        nprocs = 10
        owners = [f'proc{i}' for i in range(nprocs)]

        nvme.registry_update(self.ctx, 'nvme10', 'owner', 'parent')

        procs = [multiprocessing.Process(target=_writer,
                                         args=('nvme10', owner, 200, _tmpdir))
                 for owner in owners]
        for p in procs:
            p.start()
        for p in procs:
            p.join()

        value = nvme.registry_retrieve(self.ctx, 'nvme10', 'owner')
        nvme.registry_delete(self.ctx, 'nvme10')

        self.assertIn(value, owners, f'corrupted value: {value!r}')


if __name__ == '__main__':
    unittest.main()
