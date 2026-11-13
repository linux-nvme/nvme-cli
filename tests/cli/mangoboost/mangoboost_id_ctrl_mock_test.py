#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Hardware-free tests for the MangoBoost id-ctrl command.

The MangoBoost version is the first six bytes (major, minor, tertiary) of
the 1024-byte vendor-specific area of a 4096-byte Identify Controller
response.  It is formatted as 0x%04x%04x%04x (e.g. 0x000100020003).

Usage: python3 mangoboost_id_ctrl_mock_test.py <nvme-binary> <mock-lib>
"""

import struct

from tests.cli.nvme_mock import (CNS_CTRL, HAVE_JSON, ID_CTRL_SIZE,
                                 OPC_IDENTIFY, SC_INVALID_FIELD,
                                 MockTestCase, id_ctrl, main)

# nvme_id_ctrl ends in vs[1024], so the vendor area starts at 4096 - 1024.
_VENDOR_SPECIFIC_SIZE = 1024
_VENDOR_OFFSET = ID_CTRL_SIZE - _VENDOR_SPECIFIC_SIZE

_VERSION_SIZE = 3 * 2  # three adjacent 16-bit little-endian fields


def identify_with_mangoboost_data(version_bytes):
    """Build a controller response with literal MangoBoost vendor fields."""
    if len(version_bytes) != _VERSION_SIZE:
        raise ValueError(f'MangoBoost version must be {_VERSION_SIZE} bytes')

    data = id_ctrl()
    ver_end = _VENDOR_OFFSET + _VERSION_SIZE
    data[_VENDOR_OFFSET:ver_end] = version_bytes
    return data


class TestMangoBoostIdCtrl(MockTestCase):
    """Run mangoboost id-ctrl against a simulated Identify response."""

    def run_id_ctrl(self, *args):
        return self.nvme('mangoboost', 'id-ctrl', self.ctrl, *args)

    def assert_identify_requests(self, expected_count):
        requests = self.server.identifies(CNS_CTRL)

        self.assertEqual(len(requests), expected_count)
        self.assertEqual(self.server.opcodes(),
                         [OPC_IDENTIFY] * expected_count)
        for request in requests:
            self.assertTrue(request.admin)
            self.assertEqual(request.opcode, OPC_IDENTIFY)
            self.assertEqual(request.cns, CNS_CTRL)
            self.assertEqual(request.data_len, ID_CTRL_SIZE)

    def assert_mangoboost_outputs(self, version_bytes, expected_ver):
        identify = identify_with_mangoboost_data(version_bytes)
        ver_end = _VENDOR_OFFSET + _VERSION_SIZE

        self.assertEqual(len(identify), ID_CTRL_SIZE)
        self.assertEqual(_VENDOR_OFFSET, 3072)
        self.assertEqual(identify[_VENDOR_OFFSET:ver_end], version_bytes)
        self.server.identify[CNS_CTRL] = identify

        normal = self.assertOk(self.run_id_ctrl())
        self.assertIn(f'json_rpc_2_0_ver : {expected_ver}',
                      normal.stdout.splitlines())

        expected_count = 1
        if HAVE_JSON:
            json_result = self.assertOk(self.run_id_ctrl('-o', 'json'))
            output = self.parse_json_output(json_result.stdout,
                                            'mangoboost id-ctrl -o json')
            self.assertIn('json_rpc_2_0_ver', output)
            self.assertEqual(output['json_rpc_2_0_ver'], expected_ver)
            expected_count += 1

        self.assert_identify_requests(expected_count=expected_count)

    def test_zero_version(self):
        """All zero fields are formatted with leading zeroes."""
        self.assert_mangoboost_outputs(
            bytes.fromhex('00 00 00 00 00 00'),
            '0x000000000000')

    def test_small_nonzero_version(self):
        """Fields 1, 2, and 3 retain their four-digit hex width."""
        self.assert_mangoboost_outputs(
            bytes.fromhex('01 00 02 00 03 00'),
            '0x000100020003')

    def test_endian_sensitive_version(self):
        """Little-endian bytes become 0x1234, 0x5678, and 0x9abc."""
        self.assert_mangoboost_outputs(
            bytes.fromhex('34 12 78 56 bc 9a'),
            '0x123456789abc')

    def test_max_u16_version(self):
        """0xffff for major, minor, and tertiary fields."""
        self.assert_mangoboost_outputs(
            bytes.fromhex('ff ff ff ff ff ff'),
            '0xffffffffffff')

    def test_packed_version_helper(self):
        """Verify struct packing matches manual byte fixtures."""
        ver_bytes = struct.pack('<HHH', 0x000a, 0x0014, 0x001e)
        self.assert_mangoboost_outputs(ver_bytes, '0x000a0014001e')

    def test_identify_failure_is_reported(self):
        """A controller status error must fail instead of printing data."""
        self.server.identify[CNS_CTRL] = SC_INVALID_FIELD

        result = self.run_id_ctrl()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn('NVMe status: Invalid Field in Command', result.stderr)
        self.assert_identify_requests(expected_count=1)


if __name__ == '__main__':
    main()
