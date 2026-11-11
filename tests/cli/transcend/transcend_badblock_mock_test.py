#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Hardware-free tests for the Transcend badblock command.

Tests vendor admin passthru command (opcode 0xc2, cdw10 0x400, cdw12 0x5a)
retrieval and reporting of bad block count.

Usage: python3 transcend_badblock_mock_test.py <nvme-binary> <mock-lib>
"""

from tests.cli.nvme_mock import MockTestCase, SC_INVALID_FIELD, main

_OP_BAD_BLOCK = 0xc2
_DW10_BAD_BLOCK = 0x400
_DW12_BAD_BLOCK = 0x5a


class TestTranscendBadblock(MockTestCase):
    """Run transcend badblock against a simulated controller."""

    def test_badblock_count(self):
        """A drive with bad blocks reports the byte value returned."""
        self.server.admin[_OP_BAD_BLOCK] = bytes([42])
        result = self.assertOk(self.nvme('transcend', 'badblock', self.ctrl))
        self.assertIn('Transcend NVME badblock count: 42', result.stdout)

        cmd, = self.server.admin_cmds(_OP_BAD_BLOCK)
        self.assertTrue(cmd.admin)
        self.assertEqual(cmd.opcode, _OP_BAD_BLOCK)
        self.assertEqual(cmd.cdw10, _DW10_BAD_BLOCK)
        self.assertEqual(cmd.cdw12, _DW12_BAD_BLOCK)
        self.assertEqual(cmd.data_len, 1)

    def test_badblock_zero(self):
        """A drive with 0 bad blocks reports 0."""
        self.server.admin[_OP_BAD_BLOCK] = bytes([0])
        result = self.assertOk(self.nvme('transcend', 'badblock', self.ctrl))
        self.assertIn('Transcend NVME badblock count: 0', result.stdout)

    def test_badblock_failure(self):
        """Failing the admin passthru command exits non-zero."""
        self.server.admin[_OP_BAD_BLOCK] = SC_INVALID_FIELD
        result = self.nvme('transcend', 'badblock', self.ctrl)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    main()
