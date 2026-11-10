#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Hardware-free tests for the HUAWEI id-ctrl command.

The HUAWEI array name is an 80-byte field starting at the beginning of the
1024-byte vendor-specific area of a 4096-byte Identify Controller response.
The fixtures below are literal bytes and the expected text is literal too,
keeping the test oracle independent from the production parser.

Usage: python3 huawei_id_ctrl_mock_test.py <nvme-binary> <mock-lib>
"""

from tests.cli.nvme_mock import (CNS_CTRL, ID_CTRL_SIZE, OPC_IDENTIFY,
                                 SC_INVALID_FIELD, MockTestCase, id_ctrl,
                                 main)


# nvme_id_ctrl ends in vs[1024], so the vendor area starts at 4096 - 1024.
_VENDOR_SPECIFIC_SIZE = 1024
_VENDOR_OFFSET = ID_CTRL_SIZE - _VENDOR_SPECIFIC_SIZE
_ARRAY_NAME_SIZE = 80


def identify_with_huawei_array_name(array_name_bytes=None):
    """Build a controller response with literal HUAWEI vendor fields."""
    data = id_ctrl()

    if array_name_bytes is not None:
        if len(array_name_bytes) > _ARRAY_NAME_SIZE:
            raise ValueError(
                f'HUAWEI array name exceeds {_ARRAY_NAME_SIZE} bytes'
            )
        name_end = _VENDOR_OFFSET + len(array_name_bytes)
        data[_VENDOR_OFFSET:name_end] = array_name_bytes

    return data


class TestHuaweiIdCtrl(MockTestCase):
    """Run huawei id-ctrl against a simulated Identify response."""

    def run_id_ctrl(self, *args):
        return self.nvme('huawei', 'id-ctrl', self.ctrl, *args)

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

    def assert_huawei_outputs(self, array_name_bytes=None,
                              expected_name='NULL'):
        identify = identify_with_huawei_array_name(array_name_bytes)

        self.assertEqual(len(identify), ID_CTRL_SIZE)
        self.assertEqual(_VENDOR_OFFSET, 3072)
        self.server.identify[CNS_CTRL] = identify

        normal = self.assertOk(self.run_id_ctrl())
        lines = normal.stdout.splitlines()
        self.assertIn(f'array name : {expected_name}', lines)

        json_result = self.assertOk(self.run_id_ctrl('-o', 'json'))
        output = self.parse_json_output(json_result.stdout,
                                        'huawei id-ctrl -o json')
        self.assertIn('array name', output)
        self.assertEqual(output['array name'], expected_name)

        self.assert_identify_requests(expected_count=2)

    def test_default_empty_array_name(self):
        """Zeroed vendor-specific area outputs NULL array name."""
        self.assert_huawei_outputs(
            array_name_bytes=None,
            expected_name='NULL')

    def test_single_char_array_name_falls_back(self):
        """Single-character name (length <= 1) falls back to NULL."""
        self.assert_huawei_outputs(
            array_name_bytes=b'A',
            expected_name='NULL')

    def test_valid_array_name(self):
        """Valid multi-character array name is parsed verbatim."""
        name = b'OceanStor-NVMe-Pool'
        self.assert_huawei_outputs(
            array_name_bytes=name,
            expected_name='OceanStor-NVMe-Pool')

    def test_identify_failure_is_reported(self):
        """A controller status error must fail instead of printing data."""
        self.server.identify[CNS_CTRL] = SC_INVALID_FIELD

        result = self.run_id_ctrl()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn('NVMe status: Invalid Field in Command', result.stderr)
        self.assert_identify_requests(expected_count=1)


if __name__ == '__main__':
    main()
