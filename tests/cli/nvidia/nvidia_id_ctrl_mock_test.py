#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Hardware-free tests for the NVIDIA id-ctrl command.

The NVIDIA version is the first six bytes of the 1024-byte vendor-specific
area of a 4096-byte Identify Controller response.  The fixtures below are
literal bytes and the expected text is literal too, keeping the test oracle
independent from the production parser.

Usage: python3 nvidia_id_ctrl_mock_test.py <nvme-binary> <mock-lib>
"""

from tests.cli.nvme_mock import (CNS_CTRL, ID_CTRL_SIZE, OPC_IDENTIFY,
                                 SC_INVALID_FIELD, MockTestCase, id_ctrl,
                                 main)


# nvme_id_ctrl ends in vs[1024], so the vendor area starts at 4096 - 1024.
_VENDOR_SPECIFIC_SIZE = 1024
_VERSION_OFFSET = ID_CTRL_SIZE - _VENDOR_SPECIFIC_SIZE

# Three adjacent 16-bit fields occupy three times two bytes.
_VERSION_SIZE = 3 * 2
_VERSION_KEY = 'json_rpc_2_0_ver'


def identify_with_version(version_bytes):
    """Build a controller response with literal NVIDIA version bytes."""
    if len(version_bytes) != _VERSION_SIZE:
        raise ValueError(f'NVIDIA version must be {_VERSION_SIZE} bytes')

    data = id_ctrl()
    end = _VERSION_OFFSET + _VERSION_SIZE
    data[_VERSION_OFFSET:end] = version_bytes
    return data


class TestNvidiaIdCtrl(MockTestCase):
    """Run nvidia id-ctrl against a simulated Identify response."""

    def run_id_ctrl(self, *args):
        return self.nvme('nvidia', 'id-ctrl', self.ctrl, *args)

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

    def assert_version_outputs(self, version_bytes, expected):
        identify = identify_with_version(version_bytes)
        end = _VERSION_OFFSET + _VERSION_SIZE

        self.assertEqual(len(identify), ID_CTRL_SIZE)
        self.assertEqual(_VERSION_OFFSET, 3072)
        self.assertEqual(identify[_VERSION_OFFSET:end], version_bytes)
        self.server.identify[CNS_CTRL] = identify

        normal = self.assertOk(self.run_id_ctrl())
        self.assertIn(f'{_VERSION_KEY} : {expected}',
                      normal.stdout.splitlines())

        json_result = self.assertOk(self.run_id_ctrl('-o', 'json'))
        output = self.parse_json_output(json_result.stdout,
                                        'nvidia id-ctrl -o json')
        self.assertIn(_VERSION_KEY, output)
        self.assertEqual(output[_VERSION_KEY], expected)

        self.assert_identify_requests(expected_count=2)

    def test_small_nonzero_version(self):
        """Fields 1, 2 and 3 retain all leading zeroes."""
        self.assert_version_outputs(
            bytes.fromhex('01 00 02 00 03 00'),
            '0x000100020003')

    def test_endian_sensitive_version(self):
        """Little-endian bytes become 0x1234, 0xabcd and 0x0102."""
        self.assert_version_outputs(
            bytes.fromhex('34 12 cd ab 02 01'),
            '0x1234abcd0102')

    def test_zero_version(self):
        """Zero fields are still printed as three four-digit values."""
        self.assert_version_outputs(
            bytes.fromhex('00 00 00 00 00 00'),
            '0x000000000000')

    def test_identify_failure_is_reported(self):
        """A controller status error must fail instead of printing data."""
        self.server.identify[CNS_CTRL] = SC_INVALID_FIELD

        result = self.run_id_ctrl()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn('NVMe status: Invalid Field in Command', result.stderr)
        self.assert_identify_requests(expected_count=1)


if __name__ == '__main__':
    main()
