#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Hardware-free tests for the Amazon (amzn) stats command.

Tests Amazon EBS volume and EC2 instance local storage latency statistics
log page (0xD0) retrieval, histogram parsing, and normal / JSON output.

Usage: python3 amzn_stats_mock_test.py <nvme-binary> <mock-lib>
"""

import os
import struct
import sys

from tests.cli.nvme_mock import (CNS_CTRL, HAVE_JSON, MOCK_LIB, NVME_BIN,
                                 SC_INVALID_LOG_PAGE, MockTestCase, id_ctrl,
                                 main)

_LID_AMZN_STATS = 0xD0
_MAGIC_EBS = 0x3C23B510
_MAGIC_LOCAL = 0xEC2C0D7E
_LOCAL_PREFIX = b'Amazon EC2 NVMe Instance Storage'


def _detect_endian():
    """Detect byte order of the target binary or mock library (e.g. on cross-endian CI)."""
    for path in (NVME_BIN, MOCK_LIB):
        try:
            with open(os.path.realpath(path), 'rb') as f:
                header = f.read(6)
                if header[:4] == b'\x7fELF':
                    return '>' if header[5] == 2 else '<'
        except Exception:
            pass
    return '>' if sys.byteorder == 'big' else '<'


_ENDIAN = _detect_endian()


def pack_histogram(num_bins, bins):
    """Pack an amzn_latency_histogram structure (1544 bytes)."""
    buf = bytearray(1544)
    struct.pack_into(f'{_ENDIAN}Q', buf, 0, num_bins)
    for i, (lower, upper, count) in enumerate(bins[:64]):
        struct.pack_into(f'{_ENDIAN}QQII', buf, 8 + i * 24, lower, upper, count, 0)
    return bytes(buf)


def pack_stats_log(magic=_MAGIC_EBS, version=1, read_ops=100, write_ops=200,
                   read_bytes=409600, write_bytes=819200, read_time=1000,
                   write_time=2000, ebs_iops=10, ebs_tp=20, ec2_iops=30,
                   ec2_tp=40, q_len=5, r_bins=None, w_bins=None,
                   is_local=False):
    """Pack an amzn_latency_log_page structure (4096 or 8192 bytes)."""
    total_len = 8192 if is_local else 4096
    buf = bytearray(total_len)
    struct.pack_into(f'{_ENDIAN}II', buf, 0, magic, version)
    struct.pack_into(f'{_ENDIAN}11Q', buf, 8,
                     read_ops, write_ops, read_bytes, write_bytes,
                     read_time, write_time, ebs_iops, ebs_tp,
                     ec2_iops, ec2_tp, q_len)
    if r_bins:
        buf[512:512 + 1544] = pack_histogram(len(r_bins), r_bins)
    if w_bins:
        buf[2056:2056 + 1544] = pack_histogram(len(w_bins), w_bins)
    return bytes(buf)


class TestAmznStats(MockTestCase):
    """Run amzn stats against a simulated Amazon NVMe controller."""

    def run_stats(self, *args):
        return self.nvme('amzn', 'stats', self.ctrl, *args)

    def test_ebs_stats_normal(self):
        """Standard EBS stats output shows ops, bytes, times, and limits."""
        r_bins = [(0, 10, 45)]
        w_bins = [(10, 20, 80)]
        self.server.identify[CNS_CTRL] = id_ctrl()
        self.server.logs[_LID_AMZN_STATS] = pack_stats_log(
            magic=_MAGIC_EBS, read_ops=100, write_ops=200,
            read_bytes=409600, write_bytes=819200, read_time=1000,
            write_time=2000, ebs_iops=10, ebs_tp=20, ec2_iops=30,
            ec2_tp=40, q_len=5, r_bins=r_bins, w_bins=w_bins)

        result = self.assertOk(self.run_stats())
        lines = result.stdout.splitlines()

        self.assertIn('Total Ops:', lines)
        self.assertIn('  Read: 100', lines)
        self.assertIn('  Write: 200', lines)
        self.assertIn('Total Bytes:', lines)
        self.assertIn('  Read: 409600', lines)
        self.assertIn('  Write: 819200', lines)
        self.assertIn('Total Time (us):', lines)
        self.assertIn('  Read: 1000', lines)
        self.assertIn('  Write: 2000', lines)
        self.assertIn('EBS Volume Performance Exceeded (us):', lines)
        self.assertIn('EC2 Instance EBS Performance Exceeded (us):', lines)
        self.assertIn('Queue Length (point in time): 5', lines)
        self.assertIn('Read IO Latency Histogram', lines)
        self.assertIn('Write IO Latency Histogram', lines)

    def test_ebs_stats_json(self):
        """JSON output contains all counters and histogram objects."""
        if not HAVE_JSON:
            self.skipTest('built without json-c')

        r_bins = [(0, 10, 45)]
        w_bins = [(10, 20, 80)]
        self.server.identify[CNS_CTRL] = id_ctrl()
        self.server.logs[_LID_AMZN_STATS] = pack_stats_log(
            magic=_MAGIC_EBS, read_ops=123, write_ops=456,
            read_bytes=100000, write_bytes=200000, read_time=500,
            write_time=800, ebs_iops=15, ebs_tp=25, ec2_iops=35,
            ec2_tp=45, q_len=3, r_bins=r_bins, w_bins=w_bins)

        result = self.assertOk(self.run_stats('-o', 'json'))
        data = self.parse_json_output(result.stdout, 'amzn stats -o json')

        self.assertEqual(data['total_read_ops'], 123)
        self.assertEqual(data['total_write_ops'], 456)
        self.assertEqual(data['total_read_bytes'], 100000)
        self.assertEqual(data['total_write_bytes'], 200000)
        self.assertEqual(data['total_read_time'], 500)
        self.assertEqual(data['total_write_time'], 800)
        self.assertEqual(data['ebs_volume_performance_exceeded_iops'], 15)
        self.assertEqual(data['ebs_volume_performance_exceeded_tp'], 25)
        self.assertEqual(data['ec2_instance_performance_exceeded_iops'], 35)
        self.assertEqual(data['ec2_instance_performance_exceeded_tp'], 45)
        self.assertEqual(data['volume_queue_length'], 3)
        self.assertEqual(data['read_io_latency_histogram']['num_bins'], 1)
        self.assertEqual(data['write_io_latency_histogram']['num_bins'], 1)

    def test_local_storage_stats(self):
        """Local storage output omits EBS lines and shows local storage."""
        self.server.identify[CNS_CTRL] = id_ctrl(mn=_LOCAL_PREFIX)
        self.server.logs[_LID_AMZN_STATS] = pack_stats_log(
            magic=_MAGIC_LOCAL, read_ops=50, write_ops=60,
            ec2_iops=12, ec2_tp=24, is_local=True)

        result = self.assertOk(self.run_stats())
        lines = result.stdout.splitlines()

        self.assertIn('EC2 Instance Local Storage Performance Exceeded (us):',
                      lines)
        self.assertNotIn('EBS Volume Performance Exceeded (us):', lines)

        if HAVE_JSON:
            json_res = self.assertOk(self.run_stats('-o', 'json'))
            data = self.parse_json_output(json_res.stdout,
                                          'amzn stats -o json')
            self.assertEqual(data['ec2_instance_performance_exceeded_iops'],
                             12)
            self.assertEqual(data['ec2_instance_performance_exceeded_tp'],
                             24)

    def test_not_ec2_device_rejected(self):
        """Invalid log magic must fail and report non-EC2 device."""
        self.server.identify[CNS_CTRL] = id_ctrl()
        self.server.logs[_LID_AMZN_STATS] = pack_stats_log(magic=0xdeadbeef)

        result = self.run_stats()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Not an EC2 device', result.stderr)

    def test_stats_log_page_failure(self):
        """A failure to retrieve the log page is reported."""
        self.server.identify[CNS_CTRL] = id_ctrl()
        self.server.logs[_LID_AMZN_STATS] = SC_INVALID_LOG_PAGE

        result = self.run_stats()
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    main()
