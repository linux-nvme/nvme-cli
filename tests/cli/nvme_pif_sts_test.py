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

from tests.cli.nvme_mock import (CNS_CSI_NS, CNS_NS, PIC_QPIFS,
                                 SC_INTERNAL, SC_INVALID_FIELD, MockTestCase,
                                 id_ns, main, nvm_id_ns)

PIF_16B_GUARD = 0
PIF_32B_GUARD = 1
PIF_64B_GUARD = 2
PIF_QTYPE = 3

PIFA_BIT_GRANULARITY_MASKING = 0x0
PIFA_BYTE_GRANULARITY_MASKING = 0x1
PIFA_MASKING_NOT_SUPPORTED = 0x2


def _nvm_id_ns(lba_index, sts=0, pif=0, qpif=0, qpifs=False, pifa=0,
               lbstm=0):
    """ELBAF[@lba_index] encodes (@sts, @pif, @qpif)"""
    return nvm_id_ns(elbaf={lba_index: (sts, pif, qpif)}, lbstm=lbstm,
                     pic=PIC_QPIFS if qpifs else 0, pifa=pifa)


class PIFStsCLITest(MockTestCase):

    NSID = '1'

    def _verify(self, ref_tag=0, storage_tag=0, expect_fail=False, lba_index=0,
               nvm_id_ns_sc_status=0, **ns_kwargs):
        # get_pif_sts() only reads FLBAS of Identify Namespace
        self.server.identify[CNS_NS] = id_ns(flbas=lba_index)
        self.server.identify[CNS_CSI_NS] = (
            nvm_id_ns_sc_status or _nvm_id_ns(lba_index, **ns_kwargs))

        result = self.nvme('verify', self.ns, '-n', self.NSID,
                           '--ref-tag', hex(ref_tag),
                           '--storage-tag', hex(storage_tag), '--verbose')

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
        self.assertIn("Reference tag larger than the 24-bit width allowed by 16b Guard PIF (STS=8)",
                     res.stdout + res.stderr)

    def test_16b_guard_storage_tag_over_boundary_fails(self):
        res = self._verify(sts=8, pif=PIF_16B_GUARD,
                           ref_tag=0, storage_tag=0x100, expect_fail=True)
        self.assertIn("Storage tag larger than the STS-defined 8-bit width", res.stdout + res.stderr)

    def test_32b_guard_ref_tag_at_boundary_succeeds(self):
        """32B Guard: ref tag is (80 - STS) bits, checked only for STS>16.
        STS=64 -> 16 bits. Largest valid ref tag: 2**16-1."""
        self._verify(sts=64, pif=PIF_32B_GUARD, ref_tag=0xffff, storage_tag=0)

    def test_32b_guard_ref_tag_over_boundary_fails(self):
        res = self._verify(sts=64, pif=PIF_32B_GUARD,
                           ref_tag=0x10000, storage_tag=0, expect_fail=True)
        self.assertIn("Reference tag larger than the 16-bit width allowed by 32b Guard PIF (STS=64)",
                     res.stdout + res.stderr)

    def test_64b_guard_ref_tag_at_boundary_succeeds(self):
        """64B Guard: ref tag is (48 - STS) bits. STS=40 -> 8 bits.
        Largest valid ref tag: 2**8-1."""
        self._verify(sts=40, pif=PIF_64B_GUARD, ref_tag=0xff, storage_tag=0)

    def test_64b_guard_ref_tag_over_boundary_fails(self):
        res = self._verify(sts=40, pif=PIF_64B_GUARD,
                           ref_tag=0x100, storage_tag=0, expect_fail=True)
        self.assertIn("Reference tag larger than the 8-bit width allowed by 64b Guard PIF (STS=40)",
                     res.stdout + res.stderr)

    # ------------------------------------------------------------------ #
    # STS outside the PIF's spec-mandated range (NVM Command Set spec,   #
    # Figure 119): invalid_tags() used to only reject STS values beyond  #
    # the PIF's full field width, which both let spec-invalid values     #
    # through and (for 32B Guard, before its fix) computed a negative/   #
    # oversized shift amount for some of them.                          #
    # ------------------------------------------------------------------ #

    def test_16b_guard_sts_at_new_limit_succeeds(self):
        """16B Guard: STS=32 leaves a 0-bit ref tag, still valid."""
        self._verify(sts=32, pif=PIF_16B_GUARD, ref_tag=0, storage_tag=0)

    def test_16b_guard_sts_over_new_limit_fails(self):
        res = self._verify(sts=33, pif=PIF_16B_GUARD,
                           ref_tag=0, storage_tag=0, expect_fail=True)
        self.assertIn("Storage tag size (STS=33) larger than the 32-bit maximum allowed by 16b Guard PIF",
                     res.stdout + res.stderr)

    def test_32b_guard_sts_at_new_limit_succeeds(self):
        """32B Guard: STS=64 is the spec-mandated maximum, still valid."""
        self._verify(sts=64, pif=PIF_32B_GUARD, ref_tag=0, storage_tag=0)

    def test_32b_guard_sts_over_new_limit_fails(self):
        """32B Guard's field is 80 bits wide, but the spec caps STS at 64,
        not 80: STS in (64, 80] must be rejected, not silently encoded."""
        res = self._verify(sts=65, pif=PIF_32B_GUARD,
                           ref_tag=0, storage_tag=0, expect_fail=True)
        self.assertIn("Storage tag size (STS=65) outside the 16-64 range allowed by 32b Guard PIF",
                     res.stdout + res.stderr)

    def test_32b_guard_sts_at_new_min_succeeds(self):
        """32B Guard: STS=16 is the spec-mandated minimum, still valid."""
        self._verify(sts=16, pif=PIF_32B_GUARD, ref_tag=0, storage_tag=0)

    def test_32b_guard_sts_below_new_min_fails(self):
        """Unlike 16B/64B Guard, 32B Guard's STS may not go below 16."""
        res = self._verify(sts=15, pif=PIF_32B_GUARD,
                           ref_tag=0, storage_tag=0, expect_fail=True)
        self.assertIn("Storage tag size (STS=15) outside the 16-64 range allowed by 32b Guard PIF",
                     res.stdout + res.stderr)

    def test_64b_guard_sts_at_new_limit_succeeds(self):
        """64B Guard: STS=48 leaves a 0-bit ref tag, still valid."""
        self._verify(sts=48, pif=PIF_64B_GUARD, ref_tag=0, storage_tag=0)

    def test_64b_guard_sts_over_new_limit_fails(self):
        res = self._verify(sts=49, pif=PIF_64B_GUARD,
                           ref_tag=0, storage_tag=0, expect_fail=True)
        self.assertIn("Storage tag size (STS=49) larger than the 48-bit maximum allowed by 64b Guard PIF",
                     res.stdout + res.stderr)

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
        self._verify(nvm_id_ns_sc_status=SC_INVALID_FIELD, ref_tag=0,
                     storage_tag=0)

    def test_nvm_cs_ns_other_status_error_propagates(self):
        """Any other failure (Internal Error here) is a real error, not
        "not supported". It must not be swallowed: the command fails."""
        self._verify(nvm_id_ns_sc_status=SC_INTERNAL, ref_tag=0, storage_tag=0,
                     expect_fail=True)


if __name__ == '__main__':
    main()
