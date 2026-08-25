#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.com>
"""Tests for get_pif_sts()/get_pif_sts_via_qpif() and invalid_tags() in
src/nvme-cmds-io.c.

Usage: python3 nvme_pif_sts_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
import os
import shutil
import struct
import sys
import tempfile
import unittest

from nvme_mock_ipc import MockIPCServer, make_mock_env, resolve_mock_lib_path, run_nvme

_NVME_BIN = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else 'nvme'
_MOCK_LIB = resolve_mock_lib_path("./libmock_nvme.so")

_NVME_OPCODE_IDENTIFY = 0x06
_NVME_IDENTIFY_CNS_NS = 0x00
_NVME_IDENTIFY_CNS_CSI_NS = 0x05

NVME_SC_INVALID_FIELD = 0x2
NVME_SC_INTERNAL = 0x6

PIF_16B_GUARD = 0
PIF_32B_GUARD = 1
PIF_64B_GUARD = 2
PIF_QTYPE = 3

PIFA_BIT_GRANULARITY_MASKING = 0x0
PIFA_BYTE_GRANULARITY_MASKING = 0x1
PIFA_MASKING_NOT_SUPPORTED = 0x2

_ID_NS_SIZE = 4096
_NVM_ID_NS_SIZE = 4096


def _pack_id_ns(lba_index=0):
    """Pack a struct nvme_id_ns (4096 bytes). FLBAS (offset 26) selects
    @lba_index as the in-use LBA format. Every other field stays 0:
    get_pif_sts() only reads FLBAS out of this struct."""
    buf = bytearray(_ID_NS_SIZE)
    buf[26] = lba_index & 0xff  # lba_index <= 15 here, so HIGHER stays 0
    return bytes(buf)


def _pack_elbaf(sts, pif, qpif=0):
    return (sts & 0x7f) | ((pif & 0x3) << 7) | ((qpif & 0xf) << 9)


def _pack_nvm_id_ns(lba_index=0, sts=0, pif=0, qpif=0, qpifs=False, pifa=0, lbstm=0):
    """Pack a struct nvme_nvm_id_ns (4096 bytes): LBSTM (offset 0),
    PIC.QPIFS (offset 8, bit 3), PIFA.STMLA (offset 9), and
    ELBAF[@lba_index] (offset 12 + 4*index), encoding (@sts, @pif, @qpif)."""
    buf = bytearray(_NVM_ID_NS_SIZE)
    struct.pack_into("<Q", buf, 0, lbstm)
    buf[8] = 0x8 if qpifs else 0
    buf[9] = pifa & 0xf
    struct.pack_into("<I", buf, 12 + 4 * lba_index, _pack_elbaf(sts, pif, qpif))
    return bytes(buf)


class PIFMockIPCServer(MockIPCServer):

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.id_ns = _pack_id_ns()
        self.nvm_id_ns = _pack_nvm_id_ns()
        self.nvm_id_ns_sc_status = 0

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                      cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        if opcode == _NVME_OPCODE_IDENTIFY:
            cns = cdw10 & 0xff
            if cns == _NVME_IDENTIFY_CNS_NS:
                self.send_response(conn, 0, payload=self.id_ns[:req_len])
            elif cns == _NVME_IDENTIFY_CNS_CSI_NS:
                if self.nvm_id_ns_sc_status:
                    self.send_response(conn, 0, sc_status=self.nvm_id_ns_sc_status)
                else:
                    self.send_response(conn, 0, payload=self.nvm_id_ns[:req_len])
            else:
                self.send_response(conn, 0, payload=b"\x00" * req_len)
        else:
            self.send_response(conn, 0)


class PIFStsCLITest(unittest.TestCase):

    DEVICE = '/dev/nvme0n1'
    NSID = '1'

    def setUp(self):
        self.sysfs_dir = tempfile.mkdtemp(prefix='nvme-pif-sysfs-', dir='/tmp')
        self.base_dir = tempfile.mkdtemp(prefix='nvme-pif-base-', dir='/tmp')
        self.ipc_dir = tempfile.mkdtemp(prefix='nvme-pif-ipc-', dir='/tmp')
        self.ipc_sock_path = os.path.join(self.ipc_dir, "ipc.sock")

        self.server = PIFMockIPCServer(self.ipc_sock_path)
        self.server.start()

        self.env = make_mock_env(_MOCK_LIB, self.ipc_sock_path)

    def tearDown(self):
        self.server.shutdown()
        self.server.join()

        shutil.rmtree(self.sysfs_dir, ignore_errors=True)
        shutil.rmtree(self.base_dir, ignore_errors=True)
        shutil.rmtree(self.ipc_dir, ignore_errors=True)

    def _verify(self, ref_tag=0, storage_tag=0, expect_fail=False, lba_index=0,
               nvm_id_ns_sc_status=0, **ns_kwargs):
        self.server.id_ns = _pack_id_ns(lba_index=lba_index)
        self.server.nvm_id_ns = _pack_nvm_id_ns(lba_index=lba_index, **ns_kwargs)
        self.server.nvm_id_ns_sc_status = nvm_id_ns_sc_status

        result = run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                          'verify', self.DEVICE, '-n', self.NSID,
                          '--ref-tag', hex(ref_tag), '--storage-tag', hex(storage_tag),
                          '--verbose')

        desc = f"ref_tag={hex(ref_tag)}, storage_tag={hex(storage_tag)}, lba_index={lba_index}, {ns_kwargs}"
        if expect_fail:
            self.assertNotEqual(result.returncode, 0,
                                f'verify ({desc}) was expected to fail but succeeded')
        else:
            self.assertEqual(result.returncode, 0,
                             f'verify ({desc}) failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}')
            self.assertIn("NVME Verify Success", result.stdout)
        return result

    # ------------------------------------------------------------------ #
    # Static PIFs (ELBAF.PIF selects 16B/32B/64B Guard directly): ref-tag #
    # and storage-tag width bounds from invalid_tags().                  #
    # ------------------------------------------------------------------ #

    def test_16b_guard_ref_tag_at_boundary_succeeds(self):
        """16B Guard: ref tag is (32 - STS) bits. STS=8 -> 24 bits.
        Largest valid ref tag: 2**24-1."""
        self._verify(sts=8, pif=PIF_16B_GUARD, ref_tag=0xffffff, storage_tag=0xff)

    def test_16b_guard_ref_tag_over_boundary_fails(self):
        res = self._verify(sts=8, pif=PIF_16B_GUARD,
                           ref_tag=0x1000000, storage_tag=0, expect_fail=True)
        self.assertIn("Reference tag larger than allowed by PIF", res.stdout + res.stderr)

    def test_16b_guard_storage_tag_over_boundary_fails(self):
        res = self._verify(sts=8, pif=PIF_16B_GUARD,
                           ref_tag=0, storage_tag=0x100, expect_fail=True)
        self.assertIn("Storage tag larger than storage tag size", res.stdout + res.stderr)

    def test_32b_guard_ref_tag_at_boundary_succeeds(self):
        """32B Guard: ref tag is (80 - STS) bits, checked only for STS>16.
        STS=64 -> 16 bits. Largest valid ref tag: 2**16-1."""
        self._verify(sts=64, pif=PIF_32B_GUARD, ref_tag=0xffff, storage_tag=0)

    def test_32b_guard_ref_tag_over_boundary_fails(self):
        res = self._verify(sts=64, pif=PIF_32B_GUARD,
                           ref_tag=0x10000, storage_tag=0, expect_fail=True)
        self.assertIn("Reference tag larger than allowed by PIF", res.stdout + res.stderr)

    def test_64b_guard_ref_tag_at_boundary_succeeds(self):
        """64B Guard: ref tag is (48 - STS) bits. STS=40 -> 8 bits.
        Largest valid ref tag: 2**8-1."""
        self._verify(sts=40, pif=PIF_64B_GUARD, ref_tag=0xff, storage_tag=0)

    def test_64b_guard_ref_tag_over_boundary_fails(self):
        res = self._verify(sts=40, pif=PIF_64B_GUARD,
                           ref_tag=0x100, storage_tag=0, expect_fail=True)
        self.assertIn("Reference tag larger than allowed by PIF", res.stdout + res.stderr)

    def test_elbaf_uses_the_in_use_lba_format_index(self):
        """get_pif_sts() must index ELBAF by the FLBAS-selected format, not
        always slot 0. Slot 0 stays all-zero (STS=0, 16B Guard: ref tags
        unchecked up to 2**32-1); the boundary-testing format goes in
        slot 2. A get_pif_sts() that ignores FLBAS would let this
        over-boundary ref tag through."""
        self._verify(lba_index=2, sts=8, pif=PIF_16B_GUARD,
                     ref_tag=0x1000000, storage_tag=0, expect_fail=True)

    # ------------------------------------------------------------------ #
    # QPIF (ELBAF.PIF == QTYPE, PIC.QPIFS set): PIF comes from ELBAF.QPIF #
    # instead. LBSTM must agree with PIFA.STMLA's masking level --        #
    # get_pif_sts_via_qpif()'s job.                                       #
    # ------------------------------------------------------------------ #

    def test_qpif_bit_granularity_masking_ignores_lbstm(self):
        """STMLA=Bit Granularity Masking: any LBSTM value is valid."""
        self._verify(sts=8, pif=PIF_QTYPE, qpif=PIF_16B_GUARD, qpifs=True,
                     pifa=PIFA_BIT_GRANULARITY_MASKING, lbstm=0x1234,
                     ref_tag=0xffffff, storage_tag=0xff)

    def test_qpif_byte_granularity_masking_valid_lbstm_succeeds(self):
        """STMLA=Byte Granularity Masking, STS=16 (2 full bytes): each
        LBSTM byte covered by STS must be all-0 or all-1."""
        self._verify(sts=16, pif=PIF_QTYPE, qpif=PIF_16B_GUARD, qpifs=True,
                     pifa=PIFA_BYTE_GRANULARITY_MASKING, lbstm=0x00ff)

    def test_qpif_byte_granularity_masking_invalid_lbstm_fails(self):
        res = self._verify(sts=16, pif=PIF_QTYPE, qpif=PIF_16B_GUARD, qpifs=True,
                           pifa=PIFA_BYTE_GRANULARITY_MASKING, lbstm=0x01ff,
                           expect_fail=True)
        self.assertIn("Logical Block Storage Tag Mask is inconsistent", res.stdout + res.stderr)

    def test_qpif_masking_not_supported_fully_masked_succeeds(self):
        """STMLA=Masking Not Supported: LBSTM must be all-ones across STS.
        The controller can't mask, so the host must not ask for it."""
        self._verify(sts=8, pif=PIF_QTYPE, qpif=PIF_16B_GUARD, qpifs=True,
                     pifa=PIFA_MASKING_NOT_SUPPORTED, lbstm=0xff)

    def test_qpif_masking_not_supported_partially_masked_fails(self):
        res = self._verify(sts=8, pif=PIF_QTYPE, qpif=PIF_16B_GUARD, qpifs=True,
                           pifa=PIFA_MASKING_NOT_SUPPORTED, lbstm=0xfe,
                           expect_fail=True)
        self.assertIn("Logical Block Storage Tag Mask is inconsistent", res.stdout + res.stderr)

    def test_qpif_reserved_pif_value_rejected(self):
        """ELBAF.QPIF outside {16B,32B,64B Guard} must be rejected by
        invalid_tags()'s default case, not silently accepted."""
        res = self._verify(sts=8, pif=PIF_QTYPE, qpif=5, qpifs=True,
                           pifa=PIFA_BIT_GRANULARITY_MASKING, lbstm=0,
                           expect_fail=True)
        self.assertIn("Invalid PIF", res.stdout + res.stderr)

    # ------------------------------------------------------------------ #
    # Identify NVM CS NS itself failing: init_pi_tags()'s "skip           #
    # get_pif_sts() on Invalid Field" fallback -- a controller that does  #
    # not support the NVM Command Set Identify Namespace data structure   #
    # at all (e.g. pre-TP4068).                                           #
    # ------------------------------------------------------------------ #

    def test_nvm_cs_ns_invalid_field_falls_back_and_succeeds(self):
        """Invalid Field means "not supported": get_pif_sts() is skipped,
        PIF/STS default to 16B Guard/0, and the command proceeds."""
        self._verify(nvm_id_ns_sc_status=NVME_SC_INVALID_FIELD, ref_tag=0, storage_tag=0)

    def test_nvm_cs_ns_other_status_error_propagates(self):
        """Any other failure (Internal Error here) is a real error, not
        "not supported". It must not be swallowed: the command fails."""
        self._verify(nvm_id_ns_sc_status=NVME_SC_INTERNAL, ref_tag=0, storage_tag=0,
                     expect_fail=True)


if __name__ == '__main__':
    # Standalone run: strip the args parsed above, hand the rest to unittest.
    unittest_args = [sys.argv[0]]
    if len(sys.argv) > 3:
        unittest_args.extend(sys.argv[3:])
    unittest.main(argv=unittest_args)
