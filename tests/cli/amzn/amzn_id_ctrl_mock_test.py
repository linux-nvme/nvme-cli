#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Hardware-free tests for the Amazon (amzn) id-ctrl command.

The Amazon VU identify controller field has a 32-byte block device name
field (bdev) at the start of the 1024-byte vendor-specific area of a
4096-byte Identify Controller response. The fixtures below are literal
bytes and the expected text is literal too, keeping the test oracle
independent from the production parser.

Usage: python3 amzn_id_ctrl_mock_test.py <nvme-binary> <mock-lib>
"""

from tests.cli.nvme_mock import (CNS_CTRL, HAVE_JSON, ID_CTRL_SIZE,
                                 OPC_IDENTIFY, SC_INVALID_FIELD,
                                 MockTestCase, id_ctrl, main)

# nvme_id_ctrl ends in vs[1024], so the vendor area starts at 4096 - 1024.
_VENDOR_SPECIFIC_SIZE = 1024
_VENDOR_OFFSET = ID_CTRL_SIZE - _VENDOR_SPECIFIC_SIZE
_BDEV_SIZE = 32


def identify_with_bdev(bdev_bytes):
    """Build a controller response with literal Amazon bdev bytes."""
    if len(bdev_bytes) > _BDEV_SIZE:
        raise ValueError(f'Amazon bdev exceeds {_BDEV_SIZE} bytes')

    data = id_ctrl()
    end = _VENDOR_OFFSET + len(bdev_bytes)
    data[_VENDOR_OFFSET:end] = bdev_bytes
    return data


class TestAmznIdCtrl(MockTestCase):
    """Run amzn id-ctrl against a simulated Identify response."""

    def run_id_ctrl(self, *args):
        return self.nvme('amzn', 'id-ctrl', self.ctrl, *args)

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

    def assert_bdev_outputs(self, bdev_bytes, expected_bdev):
        identify = identify_with_bdev(bdev_bytes)
        self.assertEqual(len(identify), ID_CTRL_SIZE)
        self.assertEqual(_VENDOR_OFFSET, 3072)
        self.server.identify[CNS_CTRL] = identify

        normal = self.assertOk(self.run_id_ctrl())
        self.assertIn(f'bdev      : {expected_bdev}',
                      normal.stdout.splitlines())

        expected_count = 1
        if HAVE_JSON:
            json_result = self.assertOk(self.run_id_ctrl('-o', 'json'))
            output = self.parse_json_output(json_result.stdout,
                                            'amzn id-ctrl -o json')
            self.assertIn('bdev', output)
            self.assertEqual(output['bdev'], expected_bdev)
            expected_count += 1

        self.assert_identify_requests(expected_count=expected_count)

    def test_bdev_space_padded(self):
        """Standard trailing space padding terminates the block device name."""
        self.assert_bdev_outputs(
            b'/dev/xvda' + b' ' * 23,
            '/dev/xvda')

    def test_bdev_nvme_device(self):
        """Standard NVMe device path is extracted up to space delimiter."""
        self.assert_bdev_outputs(
            b'/dev/nvme0n1' + b' ' * 20,
            '/dev/nvme0n1')

    def test_bdev_full_length(self):
        """Without space padding, up to 31 characters are read."""
        self.assert_bdev_outputs(
            b'x' * 32,
            'x' * 31)

    def test_identify_failure_is_reported(self):
        """A controller status error must fail instead of printing data."""
        self.server.identify[CNS_CTRL] = SC_INVALID_FIELD
        result = self.run_id_ctrl()
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    main()
