#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Unit tests for the connection configuration read-side Python bindings
(nvme.config_read() / nvme.config_validate()).

Each test points at a throwaway file under /tmp -- the config file is reached
by an explicit path, so no sandbox rerouting (set_test_base_dir()) is needed,
per libnvme/design/CONFIG.md.
"""
import os
import tempfile
import unittest

from libnvme3 import nvme


def _write(path, text):
    with open(path, 'w') as f:
        f.write(text)


class TestConfigRead(unittest.TestCase):
    def setUp(self):
        self.ctx = nvme.GlobalCtx()
        self.tmpdir = tempfile.TemporaryDirectory(prefix='nvme-config-test-',
                                                    dir='/tmp')
        self.conf = os.path.join(self.tmpdir.name, 'nvme-fabrics.conf')

    def tearDown(self):
        self.tmpdir.cleanup()
        self.ctx = None

    def test_absent_config_returns_empty_list(self):
        missing = os.path.join(self.tmpdir.name, 'does-not-exist.conf')
        self.assertEqual(nvme.config_read(self.ctx, missing), [])

    def test_read_dc_and_subsystem(self):
        _write(self.conf, """
[Discovery Controller Defaults]
keep-alive-tmo = 30
ctrl-loss-tmo  = 600

[I/O Controller Defaults]
keep-alive-tmo = 5
ctrl-loss-tmo  = 600

[Host]
hostsymname = lab-host-01

[Discovery Controller]
controller = transport=tcp;traddr=192.168.1.10;trsvcid=8009

[Subsystem]
nqn        = nqn.2024-01.com.example:data.vol1
controller = transport=tcp;traddr=192.168.1.20;trsvcid=4420
""")
        conns = nvme.config_read(self.ctx, self.conf)
        self.assertEqual(len(conns), 2)

        dc, ioc = conns
        self.assertTrue(dc['is_dc'])
        self.assertEqual(dc['transport'], 'tcp')
        self.assertEqual(dc['traddr'], '192.168.1.10')
        self.assertEqual(dc['trsvcid'], '8009')
        self.assertEqual(dc['subsysnqn'], 'nqn.2014-08.org.nvmexpress.discovery')
        self.assertEqual(dc['hostsymname'], 'lab-host-01')
        self.assertEqual(dc['source'], self.conf)
        self.assertEqual(dc['params'], {'ctrl-loss-tmo': '600',
                                        'keep-alive-tmo': '30'})

        self.assertFalse(ioc['is_dc'])
        self.assertEqual(ioc['subsysnqn'], 'nqn.2024-01.com.example:data.vol1')
        self.assertEqual(ioc['params'], {'ctrl-loss-tmo': '600',
                                         'keep-alive-tmo': '5'})

    def test_unset_optional_fields_are_omitted(self):
        _write(self.conf, """
[Subsystem]
nqn        = nqn.2024-01.com.example:data.vol1
controller = transport=tcp;traddr=192.168.1.20;trsvcid=4420
""")
        conn, = nvme.config_read(self.ctx, self.conf)
        for key in ('host_traddr', 'host_iface', 'hostnqn', 'hostid',
                    'hostsymname', 'params'):
            self.assertNotIn(key, conn)

    def test_drop_in_adds_a_persona(self):
        os.mkdir(self.conf + '.d')
        _write(self.conf, """
[Host]
hostsymname = default-persona

[Subsystem]
nqn        = nqn.2024-01.com.example:data.vol1
controller = transport=tcp;traddr=192.168.1.20;trsvcid=4420
""")
        _write(os.path.join(self.conf + '.d', 'prod.conf'), """
[Host]
hostnqn     = nqn.2014-08.org.nvmexpress:uuid:1111
hostid      = 46ba5037-7ce5-41fa-9452-48477bf00080
hostsymname = prod-persona

[Subsystem]
nqn        = nqn.2024-01.com.example:prod.vol1
controller = transport=tcp;traddr=10.0.0.9;trsvcid=4420
""")
        conns = nvme.config_read(self.ctx, self.conf)
        self.assertEqual(len(conns), 2)
        self.assertEqual(conns[0]['hostsymname'], 'default-persona')
        self.assertEqual(conns[1]['hostsymname'], 'prod-persona')
        self.assertEqual(conns[1]['hostnqn'],
                         'nqn.2014-08.org.nvmexpress:uuid:1111')
        self.assertTrue(conns[1]['source'].endswith('prod.conf'))

    def test_multipath_yields_one_connection_per_controller_line(self):
        _write(self.conf, """
[Subsystem]
nqn        = nqn.2024-01.com.example:data.vol1
controller = transport=tcp;traddr=10.0.0.9;trsvcid=4420;host-iface=eth0
controller = transport=tcp;traddr=10.0.0.10;trsvcid=4420;host-iface=eth1
""")
        conns = nvme.config_read(self.ctx, self.conf)
        self.assertEqual(len(conns), 2)
        self.assertEqual(conns[0]['host_iface'], 'eth0')
        self.assertEqual(conns[1]['host_iface'], 'eth1')

    def test_invalid_file_raises_oserror(self):
        _write(self.conf, """
[Subsystem]
controller = transport=tcp;traddr=192.168.1.20;trsvcid=4420
""")
        with self.assertRaises(OSError):
            nvme.config_read(self.ctx, self.conf)


class TestConfigValidate(unittest.TestCase):
    def setUp(self):
        self.ctx = nvme.GlobalCtx()
        self.tmpdir = tempfile.TemporaryDirectory(prefix='nvme-config-test-',
                                                    dir='/tmp')
        self.conf = os.path.join(self.tmpdir.name, 'nvme-fabrics.conf')

    def tearDown(self):
        self.tmpdir.cleanup()
        self.ctx = None

    def test_validate_absent_config_returns_none(self):
        missing = os.path.join(self.tmpdir.name, 'does-not-exist.conf')
        self.assertIsNone(nvme.config_validate(self.ctx, missing))

    def test_validate_valid_config_returns_none(self):
        _write(self.conf, """
[Subsystem]
nqn        = nqn.2024-01.com.example:data.vol1
controller = transport=tcp;traddr=192.168.1.20;trsvcid=4420
""")
        self.assertIsNone(nvme.config_validate(self.ctx, self.conf))

    def test_validate_invalid_config_raises_oserror(self):
        _write(self.conf, """
[Subsystem]
controller = transport=tcp;traddr=192.168.1.20;trsvcid=4420
""")
        with self.assertRaises(OSError):
            nvme.config_validate(self.ctx, self.conf)


if __name__ == '__main__':
    unittest.main()
