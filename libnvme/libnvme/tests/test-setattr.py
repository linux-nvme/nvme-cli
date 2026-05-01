# SPDX-License-Identifier: LGPL-2.1-or-later
# This file is part of libnvme.
# Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
# Authors: Martin Belanger <Martin.Belanger@dell.com>
"""Tests that __setattr__ guards on SWIG-generated classes raise on bad names."""

import unittest
from libnvme import nvme


class TestCtrlSetattr(unittest.TestCase):

    def setUp(self):
        self.ctx = nvme.GlobalCtx()
        self.ctrl = nvme.Ctrl(self.ctx, {
            'subsysnqn': nvme.NVME_DISC_SUBSYS_NAME,
            'transport': 'loop',
        })

    def test_valid_writable_property(self):
        """Writing a valid writable property must not raise."""
        self.ctrl.discovery_ctrl = True

    def test_typo_raises(self):
        """A typo in a property name must raise AttributeError immediately."""
        with self.assertRaises(AttributeError):
            self.ctrl.dhchap_key = 'somekey'   # correct name is dhchap_ctrl_key

    def test_readonly_raises(self):
        """Writing a read-only (%immutable) property must raise AttributeError."""
        with self.assertRaises(AttributeError):
            self.ctrl.transport = 'tcp'

    def test_unknown_attr_raises(self):
        """A completely unknown attribute name must raise AttributeError."""
        with self.assertRaises(AttributeError):
            self.ctrl.does_not_exist = 42


class TestCtrlDictValidation(unittest.TestCase):

    def setUp(self):
        self.ctx = nvme.GlobalCtx()

    def test_unknown_dict_key_raises(self):
        """An unknown key in the constructor dict must raise KeyError."""
        with self.assertRaises(KeyError):
            nvme.Ctrl(self.ctx, {
                'subsysnqn': nvme.NVME_DISC_SUBSYS_NAME,
                'transport': 'loop',
                'typo_key': 'value',
            })

    def test_missing_required_key_raises(self):
        """Omitting a required key (subsysnqn or transport) must raise KeyError."""
        with self.assertRaises(KeyError):
            nvme.Ctrl(self.ctx, {'transport': 'loop'})
        with self.assertRaises(KeyError):
            nvme.Ctrl(self.ctx, {'subsysnqn': nvme.NVME_DISC_SUBSYS_NAME})


if __name__ == '__main__':
    unittest.main()
