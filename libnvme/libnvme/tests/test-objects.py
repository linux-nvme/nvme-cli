#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Unit tests for the libnvme Python bindings.

These tests cover object creation, property access, and error handling.
They do not require real NVMe hardware to run.
"""
import gc
import unittest
from libnvme import nvme


class TestConstants(unittest.TestCase):
    """Verify that well-known constants are accessible and have correct values."""

    def test_disc_subsys_name_is_string(self):
        self.assertIsInstance(nvme.NVME_DISC_SUBSYS_NAME, str)

    def test_disc_subsys_name_value(self):
        self.assertEqual(nvme.NVME_DISC_SUBSYS_NAME, 'nqn.2014-08.org.nvmexpress.discovery')

    def test_log_lid_discovery_is_int(self):
        self.assertIsInstance(nvme.NVME_LOG_LID_DISCOVERY, int)



class TestGlobalCtx(unittest.TestCase):

    def test_creation_no_args(self):
        ctx = nvme.global_ctx()
        self.assertIsNotNone(ctx)

    def test_context_manager(self):
        with nvme.global_ctx() as ctx:
            self.assertIsNotNone(ctx)

    def test_hosts_iterator_returns_list(self):
        ctx = nvme.global_ctx()
        hosts = list(ctx.hosts())
        self.assertIsInstance(hosts, list)

    def test_refresh_topology_does_not_raise(self):
        ctx = nvme.global_ctx()
        ctx.refresh_topology()

    def test_log_level_all_valid_levels(self):
        ctx = nvme.global_ctx()
        for level in ('debug', 'info', 'notice', 'warning', 'err', 'crit', 'alert', 'emerg'):
            with self.subTest(level=level):
                ctx.log_level(level)


class TestHost(unittest.TestCase):

    def setUp(self):
        self.ctx = nvme.global_ctx()

    def tearDown(self):
        self.ctx = None
        gc.collect()

    def test_creation_default(self):
        host = nvme.host(self.ctx)
        self.assertIsNotNone(host)

    def test_creation_with_explicit_hostnqn(self):
        hostnqn = 'nqn.2014-08.com.example:test-host-creation'
        host = nvme.host(self.ctx, hostnqn=hostnqn)
        self.assertIsNotNone(host)
        self.assertEqual(host.hostnqn, hostnqn)

    def test_creation_with_hostsymname(self):
        hostnqn = 'nqn.2014-08.com.example:test-host-symname'
        symname = 'my-storage-host'
        host = nvme.host(self.ctx, hostnqn=hostnqn, hostsymname=symname)
        self.assertEqual(host.hostsymname, symname)

    def test_set_symname(self):
        hostnqn = 'nqn.2014-08.com.example:test-host-set-symname'
        host = nvme.host(self.ctx, hostnqn=hostnqn)
        host.set_symname('updated-symname')
        self.assertEqual(host.hostsymname, 'updated-symname')

    def test_dhchap_host_key_is_none_by_default(self):
        hostnqn = 'nqn.2014-08.com.example:test-host-dhchap'
        host = nvme.host(self.ctx, hostnqn=hostnqn)
        self.assertIsNone(host.dhchap_host_key)

    def test_subsystems_iterator_returns_list(self):
        host = nvme.host(self.ctx)
        subsystems = list(host.subsystems())
        self.assertIsInstance(subsystems, list)

    def test_str_contains_class_name(self):
        host = nvme.host(self.ctx)
        self.assertIn('nvme.host', str(host))

    def test_context_manager(self):
        with nvme.host(self.ctx) as h:
            self.assertIsNotNone(h)


class TestCtrl(unittest.TestCase):

    def setUp(self):
        self.ctx = nvme.global_ctx()
        self.subsysnqn = nvme.NVME_DISC_SUBSYS_NAME

    def tearDown(self):
        self.ctx = None
        gc.collect()

    def _make_loop_ctrl(self):
        return nvme.ctrl(self.ctx, subsysnqn=self.subsysnqn, transport='loop')

    def test_creation_loop_transport(self):
        ctrl = self._make_loop_ctrl()
        self.assertIsNotNone(ctrl)

    def test_creation_tcp_transport_with_traddr(self):
        ctrl = nvme.ctrl(
            self.ctx,
            subsysnqn=self.subsysnqn,
            transport='tcp',
            traddr='192.168.1.1',
            trsvcid='4420',
        )
        self.assertIsNotNone(ctrl)

    def test_transport_property(self):
        ctrl = self._make_loop_ctrl()
        self.assertEqual(ctrl.transport, 'loop')

    def test_subsysnqn_property(self):
        ctrl = self._make_loop_ctrl()
        self.assertEqual(ctrl.subsysnqn, self.subsysnqn)

    def test_traddr_property(self):
        ctrl = nvme.ctrl(
            self.ctx,
            subsysnqn=self.subsysnqn,
            transport='tcp',
            traddr='10.0.0.1',
        )
        self.assertEqual(ctrl.traddr, '10.0.0.1')

    def test_trsvcid_property(self):
        ctrl = nvme.ctrl(
            self.ctx,
            subsysnqn=self.subsysnqn,
            transport='tcp',
            traddr='10.0.0.1',
            trsvcid='8009',
        )
        self.assertEqual(ctrl.trsvcid, '8009')

    def test_connected_returns_false_before_connect(self):
        ctrl = self._make_loop_ctrl()
        self.assertFalse(ctrl.connected())

    def test_name_is_none_before_connect(self):
        ctrl = self._make_loop_ctrl()
        self.assertIsNone(ctrl.name)

    def test_str_contains_transport(self):
        ctrl = self._make_loop_ctrl()
        s = str(ctrl)
        self.assertIn('loop', s)

    def test_context_manager(self):
        with nvme.ctrl(self.ctx, subsysnqn=self.subsysnqn, transport='loop') as c:
            self.assertIsNotNone(c)

    def test_namespaces_iterator_returns_list(self):
        ctrl = self._make_loop_ctrl()
        nss = list(ctrl.namespaces())
        self.assertIsInstance(nss, list)

    def test_discovery_ctrl_flag_default_false(self):
        ctrl = self._make_loop_ctrl()
        self.assertFalse(ctrl.discovery_ctrl)

    def test_discovery_ctrl_flag_set_and_clear(self):
        ctrl = self._make_loop_ctrl()
        ctrl.discovery_ctrl = True
        self.assertTrue(ctrl.discovery_ctrl)
        ctrl.discovery_ctrl = False
        self.assertFalse(ctrl.discovery_ctrl)

    def test_persistent_flag_default_false(self):
        ctrl = self._make_loop_ctrl()
        self.assertFalse(ctrl.persistent)

    def test_persistent_flag_set(self):
        ctrl = self._make_loop_ctrl()
        ctrl.persistent = True
        self.assertTrue(ctrl.persistent)

    def test_unique_discovery_ctrl_flag(self):
        ctrl = self._make_loop_ctrl()
        ctrl.unique_discovery_ctrl = True
        self.assertTrue(ctrl.unique_discovery_ctrl)

    def test_multiple_ctrls_same_ctx(self):
        """Multiple controllers can be created under the same context."""
        ctrls = [self._make_loop_ctrl() for _ in range(5)]
        self.assertEqual(len(ctrls), 5)
        for c in ctrls:
            self.assertFalse(c.connected())


class TestCtrlErrorHandling(unittest.TestCase):
    """Error paths that can be exercised without real hardware."""

    def setUp(self):
        self.ctx = nvme.global_ctx()
        self.ctrl = nvme.ctrl(
            self.ctx,
            subsysnqn=nvme.NVME_DISC_SUBSYS_NAME,
            transport='loop',
        )

    def tearDown(self):
        self.ctrl = None
        self.ctx = None
        gc.collect()

    def test_disconnect_unconnected_raises_attribute_error(self):
        with self.assertRaises(AttributeError):
            self.ctrl.disconnect()

    def test_discover_unconnected_raises_attribute_error(self):
        with self.assertRaises(AttributeError):
            self.ctrl.discover()


class TestHelperFunctions(unittest.TestCase):
    """Module-level helper functions exposed by the bindings."""

    def test_read_hostnqn_returns_string_or_none(self):
        hostnqn = nvme.read_hostnqn()
        self.assertIsInstance(hostnqn, (str, type(None)))


if __name__ == '__main__':
    unittest.main()
