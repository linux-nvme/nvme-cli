# SPDX-License-Identifier: LGPL-2.1-or-later
# This file is part of libnvme.
"""Tests that the crypto keys given to Ctrl() land on the controller.

Regression: libnvmf_create_ctrl() forwarded only ctrl_params, so 'keyring',
'tls_key', 'tls_key_identity', 'hostkey' and 'ctrlkey' were accepted by the
constructor, stored on the fabrics context, and then silently dropped -- the
connect went out without a key and failed with ENOKEY.
"""

import unittest
from libnvme3 import nvme


class TestCtrlCrypto(unittest.TestCase):

    def setUp(self):
        self.ctx = nvme.GlobalCtx()
        (hostnqn, hostid) = nvme.host_get_ids(self.ctx)
        self.ctx.hostnqn = hostnqn
        self.ctx.hostid = hostid
        self.ctrl = nvme.Ctrl(self.ctx, {
            'subsysnqn': 'nqn.2014-08.org.nvmexpress:uuid:subsys',
            'transport': 'tcp',
            'traddr': '192.168.1.100',
            'trsvcid': '4420',
            'tls': True,
            'hostkey': 'hostkey',
            'ctrlkey': 'ctrlkey',
            'keyring': '.nvme',
            'tls_key': 'tlskey',
            'tls_key_identity': 'identity',
        })

    def test_tls_key(self):
        """'tls_key' must reach the controller."""
        self.assertEqual(self.ctrl.tls_key, 'tlskey')

    def test_tls_key_identity(self):
        """'tls_key_identity' must reach the controller."""
        self.assertEqual(self.ctrl.tls_key_identity, 'identity')

    def test_keyring(self):
        """'keyring' must reach the controller."""
        self.assertEqual(self.ctrl.keyring, '.nvme')

    def test_kxchap_keys(self):
        """'hostkey' and 'ctrlkey' must reach the controller."""
        self.assertEqual(self.ctrl.kxchap_host_key, 'hostkey')
        self.assertEqual(self.ctrl.kxchap_ctrl_key, 'ctrlkey')

    def test_unset_keys_stay_unset(self):
        """A controller built without keys must not grow any."""
        ctrl = nvme.Ctrl(self.ctx, {
            'subsysnqn': 'nqn.2014-08.org.nvmexpress:uuid:subsys',
            'transport': 'tcp',
            'traddr': '192.168.1.100',
            'trsvcid': '4420',
        })
        self.assertIsNone(ctrl.tls_key)
        self.assertIsNone(ctrl.tls_key_identity)
        self.assertIsNone(ctrl.keyring)
        self.assertIsNone(ctrl.kxchap_host_key)
        self.assertIsNone(ctrl.kxchap_ctrl_key)


if __name__ == '__main__':
    unittest.main()
