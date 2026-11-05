#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for explicitly selected NetApp namespaces, hardware-free.

Usage: python3 netapp_explicit_device_mock_test.py <nvme-binary> <mock-lib>
"""

import json
import os

from tests.cli.nvme_mock import (CNS_CTRL, CNS_NS, HAVE_JSON,
                                 NVME_IOCTL_ID, OPC_IDENTIFY, MockTestCase,
                                 Reply, id_ctrl, id_ns, main)


_DEVICE = '/dev/nvme999n7'
_CTRL_INSTANCE = 999
_NSID = 7
_SUBNQN_OFFSET = 768
_SUBNQN_SIZE = 256


def controller(model):
    data = id_ctrl(mn=model, fr='TESTFW')
    subnqn = b'nqn.2014-08.org.nvmexpress:mock.netapp-subsystem'
    data[_SUBNQN_OFFSET:_SUBNQN_OFFSET + _SUBNQN_SIZE] = \
        subnqn.ljust(_SUBNQN_SIZE, b' ')
    return data


class TestNetappExplicitDevice(MockTestCase):
    """NetApp commands must query only the namespace named by the user."""

    def setUp(self):
        super().setUp()
        self.assertFalse(os.path.exists(_DEVICE),
                         f'test device unexpectedly exists: {_DEVICE}')
        self.server.ioctls[NVME_IOCTL_ID] = Reply(status=_NSID)
        self.server.identify[CNS_NS] = id_ns(
            lbaf=[(0, 12, 0)], nsze=100, nuse=25)

    def run_netapp(self, command, *args, device=_DEVICE, exists=True):
        if exists:
            self.env['MOCK_NVME_STAT_PATH'] = device
        else:
            self.env.pop('MOCK_NVME_STAT_PATH', None)
        return self.nvme('netapp', command, device, *args)

    def reset_requests(self):
        self.server.raw_ioctls.clear()
        self.server.commands.clear()

    def assert_smdevice_requests(self):
        self.assertEqual([ioctl.nr for ioctl in self.server.raw_ioctls],
                         [NVME_IOCTL_ID])
        self.assertEqual(
            [(command.instance, command.opcode, command.cns, command.nsid)
             for command in self.server.commands],
            [(_CTRL_INSTANCE, OPC_IDENTIFY, CNS_CTRL, 0),
             (_CTRL_INSTANCE, OPC_IDENTIFY, CNS_NS, _NSID)])

    def test_smdevices_queries_only_explicit_namespace(self):
        self.server.identify[CNS_CTRL] = controller('NetApp E-Series')

        result = self.assertOk(self.run_netapp('smdevices'))

        self.assertIn(_DEVICE, result.stdout)
        self.assert_smdevice_requests()

    def test_smdevices_output_formats_use_selected_namespace(self):
        self.server.identify[CNS_CTRL] = controller('NetApp E-Series')

        for args, expected in (
                (('-o', 'column'), ('Device', _DEVICE)),
                (('-v',), ('Version TESTFW', _DEVICE)),
                (('-v', '-o', 'column'), ('Version', 'TESTFW', _DEVICE))):
            with self.subTest(args=args):
                self.reset_requests()
                result = self.assertOk(self.run_netapp('smdevices', *args))
                for text in expected:
                    self.assertIn(text, result.stdout)
                self.assert_smdevice_requests()

        if HAVE_JSON:
            self.reset_requests()
            result = self.assertOk(
                self.run_netapp('smdevices', '-o', 'json'))
            data = json.loads(result.stdout)
            self.assertEqual(len(data['SMdevices']), 1)
            self.assertEqual(data['SMdevices'][0]['Device'], _DEVICE)
            self.assertEqual(data['SMdevices'][0]['NSID'], _NSID)
            self.assertEqual(data['SMdevices'][0]['Version'], 'TESTFW')
            self.assert_smdevice_requests()

    def test_smdevices_preserves_missing_device_error(self):
        device = '/dev/nvme999n8'

        result = self.run_netapp('smdevices', device=device, exists=False)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f'{device} does not exist', result.stderr)
        self.assertNotIn('Unable to open', result.stderr)
        self.assertFalse(self.server.raw_ioctls)
        self.assertFalse(self.server.commands)

    def test_smdevices_rejects_invalid_device_name(self):
        result = self.run_netapp('smdevices', device='/dev/not-nvme')

        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Invalid device name not-nvme', result.stderr)
        self.assertFalse(self.server.raw_ioctls)
        self.assertFalse(self.server.commands)


if __name__ == '__main__':
    main()
