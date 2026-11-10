#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Hardware-free tests for the DELL id-ctrl command.

The DELL version is the first six bytes (major, minor, tertiary) of the
1024-byte vendor-specific area of a 4096-byte Identify Controller response.
The array name is an 80-byte field starting 16 bytes into the vendor area.
The fixtures below are literal bytes and the expected text is literal too,
keeping the test oracle independent from the production parser.

Usage: python3 dell_id_ctrl_mock_test.py <nvme-binary> <mock-lib>
"""

from tests.cli.nvme_mock import (CNS_CTRL, ID_CTRL_SIZE, OPC_IDENTIFY,
                                 SC_INVALID_FIELD, MockTestCase, id_ctrl,
                                 main)


# nvme_id_ctrl ends in vs[1024], so the vendor area starts at 4096 - 1024.
_VENDOR_SPECIFIC_SIZE = 1024
_VENDOR_OFFSET = ID_CTRL_SIZE - _VENDOR_SPECIFIC_SIZE

# Three adjacent 16-bit fields occupy three times two bytes.
_VERSION_SIZE = 3 * 2
_ARRAY_NAME_OFFSET = _VENDOR_OFFSET + 16
_ARRAY_NAME_SIZE = 80


def identify_with_dell_data(version_bytes, array_name_bytes=None):
    """Build a controller response with literal DELL vendor fields."""
    if len(version_bytes) != _VERSION_SIZE:
        raise ValueError(f'DELL version must be {_VERSION_SIZE} bytes')

    data = id_ctrl()
    ver_end = _VENDOR_OFFSET + _VERSION_SIZE
    data[_VENDOR_OFFSET:ver_end] = version_bytes

    if array_name_bytes is not None:
        if len(array_name_bytes) > _ARRAY_NAME_SIZE:
            raise ValueError(
                f'DELL array name exceeds {_ARRAY_NAME_SIZE} bytes'
            )
        name_end = _ARRAY_NAME_OFFSET + len(array_name_bytes)
        data[_ARRAY_NAME_OFFSET:name_end] = array_name_bytes

    return data


class TestDellIdCtrl(MockTestCase):
    """Run dell id-ctrl against a simulated Identify response."""

    def run_id_ctrl(self, *args):
        return self.nvme('dell', 'id-ctrl', self.ctrl, *args)

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

    def assert_dell_outputs(self, version_bytes, expected_ver,
                            array_name_bytes=None,
                            expected_name='NULL'):
        identify = identify_with_dell_data(version_bytes, array_name_bytes)
        ver_end = _VENDOR_OFFSET + _VERSION_SIZE

        self.assertEqual(len(identify), ID_CTRL_SIZE)
        self.assertEqual(_VENDOR_OFFSET, 3072)
        self.assertEqual(identify[_VENDOR_OFFSET:ver_end], version_bytes)
        self.server.identify[CNS_CTRL] = identify

        normal = self.assertOk(self.run_id_ctrl())
        lines = normal.stdout.splitlines()
        self.assertIn(f'array_name : {expected_name}', lines)
        self.assertIn(f'array_ver  : {expected_ver}', lines)

        json_result = self.assertOk(self.run_id_ctrl('-o', 'json'))
        output = self.parse_json_output(json_result.stdout,
                                        'dell id-ctrl -o json')
        self.assertIn('array_name', output)
        self.assertEqual(output['array_name'], expected_name)
        self.assertIn('array_ver', output)
        self.assertEqual(output['array_ver'], expected_ver)

        self.assert_identify_requests(expected_count=2)

    def test_small_nonzero_version_without_name(self):
        """Fields 1, 2 and 3 retain all leading zeroes; empty name is NULL."""
        self.assert_dell_outputs(
            bytes.fromhex('01 00 02 00 03 00'),
            '0x000100020003',
            array_name_bytes=None,
            expected_name='NULL')

    def test_endian_sensitive_version_with_name(self):
        """Little-endian bytes become 0x1234, 0xabcd and 0x0102 with name."""
        name = b'PowerEdge-NVMe-Array'
        self.assert_dell_outputs(
            bytes.fromhex('34 12 cd ab 02 01'),
            '0x1234abcd0102',
            array_name_bytes=name,
            expected_name='PowerEdge-NVMe-Array')

    def test_zero_version_and_single_char_name(self):
        """Zero fields are formatted and 1-char name falls back to NULL."""
        self.assert_dell_outputs(
            bytes.fromhex('00 00 00 00 00 00'),
            '0x000000000000',
            array_name_bytes=b'X',
            expected_name='NULL')

    def test_identify_failure_is_reported(self):
        """A controller status error must fail instead of printing data."""
        self.server.identify[CNS_CTRL] = SC_INVALID_FIELD

        result = self.run_id_ctrl()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn('NVMe status: Invalid Field in Command', result.stderr)
        self.assert_identify_requests(expected_count=1)


if __name__ == '__main__':
    main()
