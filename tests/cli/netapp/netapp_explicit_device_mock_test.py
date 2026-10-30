#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for explicitly selected NetApp namespaces, hardware-free.

Usage: python3 netapp_explicit_device_mock_test.py <nvme-binary> <mock-lib>
"""

import os

from tests.cli.nvme_mock import (CNS_CTRL, CNS_NS, CNS_NS_DESC_LIST,
                                 ID_CTRL_SIZE, NVME_IOCTL_ID,
                                 OPC_GET_LOG_PAGE, OPC_IDENTIFY, MockTestCase,
                                 Reply, id_ctrl, id_ns, main)


_DEVICE = '/dev/nvme999n7'
_CTRL_INSTANCE = 999
_NSID = 7
_ONTAP_LOG_ID = 0xc2
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

    def run_netapp(self, command, device=_DEVICE):
        return self.nvme('netapp', command, device)

    def assert_commands_use_selected_device(self):
        self.assertEqual([ioctl.nr for ioctl in self.server.raw_ioctls],
                         [NVME_IOCTL_ID])
        self.assertTrue(self.server.commands)
        for command in self.server.commands:
            self.assertEqual(command.instance, _CTRL_INSTANCE)

        namespace_commands = [command for command in self.server.commands
                              if command.cns in (CNS_NS, CNS_NS_DESC_LIST)
                              or command.opcode == OPC_GET_LOG_PAGE]
        self.assertTrue(namespace_commands)
        for command in namespace_commands:
            self.assertEqual(command.nsid, _NSID)

    def test_smdevices_queries_only_explicit_namespace(self):
        self.server.identify[CNS_CTRL] = controller('NetApp E-Series')

        result = self.assertOk(self.run_netapp('smdevices'))

        self.assertIn(_DEVICE, result.stdout)
        self.assertEqual(
            [(command.opcode, command.cns, command.nsid)
             for command in self.server.commands],
            [(OPC_IDENTIFY, CNS_CTRL, 0),
             (OPC_IDENTIFY, CNS_NS, _NSID)])
        self.assert_commands_use_selected_device()

    def test_ontapdevices_queries_only_explicit_namespace(self):
        self.server.identify[CNS_CTRL] = controller(
            'NetApp ONTAP Controller')
        self.server.identify[CNS_NS_DESC_LIST] = bytearray(ID_CTRL_SIZE)
        self.server.logs[_ONTAP_LOG_ID] = bytearray(ID_CTRL_SIZE)

        result = self.assertOk(self.run_netapp('ontapdevices'))

        self.assertIn(_DEVICE, result.stdout)
        self.assertEqual(
            [(command.opcode, command.cns, command.nsid)
             for command in self.server.commands],
            [(OPC_IDENTIFY, CNS_CTRL, 0),
             (OPC_IDENTIFY, CNS_NS, _NSID),
             (OPC_IDENTIFY, CNS_NS_DESC_LIST, _NSID),
             (OPC_GET_LOG_PAGE, _ONTAP_LOG_ID, _NSID)])
        self.assert_commands_use_selected_device()

    def test_accepts_multi_digit_controller_and_namespace(self):
        device = '/dev/nvme10n23'
        self.assertFalse(os.path.exists(device),
                         f'test device unexpectedly exists: {device}')
        self.server.ioctls[NVME_IOCTL_ID] = Reply(status=23)
        self.server.identify[CNS_CTRL] = controller('NetApp E-Series')

        result = self.assertOk(self.run_netapp('smdevices', device))

        self.assertIn(device, result.stdout)
        self.assertEqual(
            [(command.instance, command.opcode, command.cns, command.nsid)
             for command in self.server.commands],
            [(10, OPC_IDENTIFY, CNS_CTRL, 0),
             (10, OPC_IDENTIFY, CNS_NS, 23)])
        self.assertEqual([ioctl.nr for ioctl in self.server.raw_ioctls],
                         [NVME_IOCTL_ID])

    def test_rejects_non_namespace_device_names(self):
        invalid_names = (
            '/dev/nvme0n0',
            '/dev/nvme999n7p4',
            '/dev/nvme999n7junk',
            '/dev/nvme999',
        )
        for netapp_command in ('smdevices', 'ontapdevices'):
            for device in invalid_names:
                with self.subTest(command=netapp_command, device=device):
                    result = self.run_netapp(netapp_command, device)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('Invalid device name', result.stderr)
                    self.assertFalse(self.server.raw_ioctls)
                    self.assertFalse(self.server.commands)


if __name__ == '__main__':
    main()
