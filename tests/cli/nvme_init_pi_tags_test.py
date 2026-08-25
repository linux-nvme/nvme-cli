#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.com>
"""Test for a PI tags initialization

Usage: python3 nvme_init_pi_tags_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
import errno
import os
import shutil
import signal
import struct
import sys
import tempfile
import unittest

from nvme_mock_ipc import MockIPCServer, make_mock_env, resolve_mock_lib_path, run_nvme

_NVME_BIN = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else 'nvme'
_MOCK_LIB = resolve_mock_lib_path("./libmock_nvme.so")

_NVME_OPCODE_READ = 0x02
_NVME_OPCODE_IDENTIFY = 0x06
_NVME_IDENTIFY_CNS_NS = 0x00
_NVME_IDENTIFY_CNS_CSI_NS = 0x05

NVME_SC_INVALID_FIELD = 0x2
NVME_SC_INTERNAL = 0x6

PIF_16B_GUARD = 0
PIF_QTYPE = 3

PIFA_BYTE_GRANULARITY_MASKING = 0x1

_ID_NS_SIZE = 4096
_NVM_ID_NS_SIZE = 4096


_FLBAS_META_EXT = 0x10


def _pack_id_ns(lba_index=0, ds=9, ms=0, meta_ext=False):
    """Pack a struct nvme_id_ns (4096 bytes). FLBAS (offset 26) selects
    @lba_index as the in-use LBA format, and its META_EXT bit (0x10) says
    whether @ms bytes of metadata are transferred as part of the extended
    LBA. LBAF[@lba_index] (offset 128 + 4*index) encodes a 2**@ds byte
    logical block with @ms bytes of metadata. This is everything
    get_pi_info() reads out of the base Identify Namespace response."""
    buf = bytearray(_ID_NS_SIZE)
    buf[26] = (lba_index & 0xff) | (_FLBAS_META_EXT if meta_ext else 0)
    struct.pack_into("<HBB", buf, 128 + 4 * lba_index, ms, ds, 0)
    return bytes(buf)


def _expected_buffer_size(data_size, logical_block_size):
    """Mirrors submit_io()'s sizing math when --block-count is not given:
    round the block count up to fit @data_size, then re-derive the buffer
    size from that (zero-based) block count."""
    nblocks = (data_size + logical_block_size - 1) // logical_block_size - 1
    return (nblocks + 1) * logical_block_size


def _pack_nvm_id_ns(lba_index=0, sts=0, pif=PIF_16B_GUARD, qpif=0, qpifs=False,
                     pifa=0, lbstm=0):
    """Pack struct nvme_nvm_id_ns: LBSTM (offset 0), PIC.QPIFS (offset 8,
    bit 3), PIFA.STMLA (offset 9), and ELBAF[@lba_index] (offset
    12 + 4*index), encoding (@sts, @pif, @qpif)."""
    buf = bytearray(_NVM_ID_NS_SIZE)
    struct.pack_into("<Q", buf, 0, lbstm)
    buf[8] = 0x8 if qpifs else 0
    buf[9] = pifa & 0xf
    elbaf = (sts & 0x7f) | ((pif & 0x3) << 7) | ((qpif & 0xf) << 9)
    struct.pack_into("<I", buf, 12 + 4 * lba_index, elbaf)
    return bytes(buf)


class PITagsMockIPCServer(MockIPCServer):

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.id_ns = _pack_id_ns()
        self.id_ns_sc_status = 0
        self.nvm_id_ns = None
        self.nvm_id_ns_sc_status = 0
        self.last_read_req_len = None

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                      cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        if opcode == _NVME_OPCODE_IDENTIFY and (cdw10 & 0xff) == _NVME_IDENTIFY_CNS_NS:
            if self.id_ns_sc_status:
                self.send_response(conn, 0, sc_status=self.id_ns_sc_status)
            else:
                self.send_response(conn, 0, payload=self.id_ns[:req_len])
        elif opcode == _NVME_OPCODE_IDENTIFY and (cdw10 & 0xff) == _NVME_IDENTIFY_CNS_CSI_NS:
            if self.nvm_id_ns_sc_status:
                self.send_response(conn, 0, sc_status=self.nvm_id_ns_sc_status)
            elif self.nvm_id_ns is not None:
                self.send_response(conn, 0, payload=self.nvm_id_ns[:req_len])
            else:
                self.send_response(conn, -1, errno_val=errno.ENOTTY)
        else:
            if opcode == _NVME_OPCODE_READ:
                self.last_read_req_len = req_len
            self.send_response(conn, 0)


class PITagsMockTestBase(unittest.TestCase):

    DEVICE = '/dev/nvme0n1'
    NSID = '1'

    def setUp(self):
        self.sysfs_dir = tempfile.mkdtemp(prefix='nvme-pi-tags-sysfs-', dir='/tmp')
        self.base_dir = tempfile.mkdtemp(prefix='nvme-pi-tags-base-', dir='/tmp')
        self.ipc_dir = tempfile.mkdtemp(prefix='nvme-pi-tags-ipc-', dir='/tmp')
        self.ipc_sock_path = os.path.join(self.ipc_dir, "ipc.sock")

        self.server = PITagsMockIPCServer(self.ipc_sock_path)
        self.server.start()

        self.env = make_mock_env(_MOCK_LIB, self.ipc_sock_path)

    def tearDown(self):
        self.server.shutdown()
        self.server.join()

        shutil.rmtree(self.sysfs_dir, ignore_errors=True)
        shutil.rmtree(self.base_dir, ignore_errors=True)
        shutil.rmtree(self.ipc_dir, ignore_errors=True)

    def _run(self, *args):
        return run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir, *args)


# ==================================================================== #
# 'nvme read'/'write'/'compare' (submit_io()).                         #
#                                                                        #
# No --block-size: get_pi_info() runs. Identify NVM CS NS itself        #
# failing (unsupported, ioctl error, any completion status) just means  #
# "no PI", not an error. But a format get_pi_info() *did* evaluate and   #
# found self-inconsistent -- ECLI_INVALID_TAGS (bad ref/storage tag) or  #
# ECLI_INVALID_PI_FORMAT (get_pif_sts() masking check) -- must abort,    #
# same as every init_pi_tags() caller below.                            #
# --block-size given: get_pi_info() is skipped; PI comes from            #
# init_pi_tags(), same as write-zeroes/copy below.                      #
# ==================================================================== #

class SubmitIOMockTestBase(PITagsMockTestBase):

    def _read(self, *args):
        return self._run('read', self.DEVICE, '-n', self.NSID, '--data-size', '4096', *args)


class SubmitIOAutoDiscoveredBlockSizeTest(SubmitIOMockTestBase):
    """No --block-size."""

    def test_nvm_cs_ns_ioctl_failure_falls_back_without_pi(self):
        """Must not SIGFPE dividing by a block size get_pi_info() left at
        0; the read must still succeed."""
        result = self._read()

        self.assertNotEqual(result.returncode, -signal.SIGFPE,
                            f'nvme read crashed with SIGFPE (divide by zero in submit_io()):\n'
                            f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}')
        self.assertEqual(result.returncode, 0,
                         f'nvme read failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}')

    def test_nvm_cs_ns_invalid_field_falls_back_and_succeeds(self):
        """Invalid Field -> not supported -> proceed without PI."""
        self.server.nvm_id_ns_sc_status = NVME_SC_INVALID_FIELD
        result = self._read()
        self.assertEqual(result.returncode, 0,
                         f'nvme read failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}')

    def test_nvm_cs_ns_other_status_error_falls_back_without_pi(self):
        """Any other failure (Internal Error here) is tolerated too: only
        ECLI_INVALID_TAGS aborts. More lenient than write-zeroes/copy and
        submit_io() with --block-size (see below)."""
        self.server.nvm_id_ns_sc_status = NVME_SC_INTERNAL
        result = self._read()
        self.assertEqual(result.returncode, 0,
                         f'nvme read failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}')

    def test_extended_lba_cs_ns_failure_still_uses_full_transfer_size(self):
        """A failing Identify NVM CS NS only means "no PI" -- it must not
        also shrink the transfer size. For an extended-LBA namespace the
        metadata rides along in each logical block, so the buffer/transfer
        size must stay 2**ds + ms, not fall back to the bare 2**ds get_pi_info()
        reads out of the base Identify Namespace before it even attempts
        Identify NVM CS NS."""
        ds, ms = 9, 8
        self.server.id_ns = _pack_id_ns(ds=ds, ms=ms, meta_ext=True)
        self.server.nvm_id_ns_sc_status = NVME_SC_INTERNAL

        result = self._read()

        self.assertEqual(result.returncode, 0,
                         f'nvme read failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}')

        full_lbs = (1 << ds) + ms
        expected_len = _expected_buffer_size(4096, full_lbs)
        bare_len = _expected_buffer_size(4096, 1 << ds)
        self.assertNotEqual(expected_len, bare_len,
                            'test bug: full and bare sizes must differ to be a useful check')
        self.assertEqual(self.server.last_read_req_len, expected_len,
                         f'expected the full extended-LBA transfer size {expected_len} bytes, '
                         f'got {self.server.last_read_req_len} (bare-block-size {bare_len} would '
                         f'undersize the buffer)')

    def test_base_identify_ns_failure_aborts_without_dividing_by_zero(self):
        """Unlike a failing Identify NVM CS NS, a failing *base* Identify
        Namespace leaves get_pi_info() unable to report a block size at
        all -- it returns -ECLI_IDENTIFY_NS_FAILED precisely so submit_io()
        can tell the two apart and abort here instead of dividing by the
        block size it never got (the same SIGFPE this whole change set is
        meant to prevent)."""
        self.server.id_ns_sc_status = NVME_SC_INTERNAL

        result = self._read()

        self.assertNotEqual(result.returncode, -signal.SIGFPE,
                            f'nvme read crashed with SIGFPE (divide by zero in submit_io()):\n'
                            f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}')
        self.assertNotEqual(result.returncode, 0,
                            f'nvme read with a failing base Identify Namespace should have failed:\n'
                            f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}')

    def test_invalid_ref_tag_aborts_the_command(self):
        """An invalid ref tag must still abort, unlike the failures above."""
        # 16B Guard, STS=8: ref tag is 32-8=24 bits; 0x1000000 is one past.
        self.server.nvm_id_ns = _pack_nvm_id_ns(sts=8, pif=PIF_16B_GUARD)

        result = self._read('--ref-tag', '0x1000000')

        self.assertNotEqual(result.returncode, 0,
                            f'nvme read with an out-of-range ref tag should have failed:\n'
                            f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}')

    def test_qpif_masking_inconsistent_aborts_the_command(self):
        """Identify NVM CS NS succeeds, but get_pif_sts()'s masking check
        on the data it returned fails: unlike an unsupported/failing
        Identify NVM CS NS above, this is a real error (the drive's own
        reported PI format is self-inconsistent) and must abort, not
        silently fall back to "no PI"."""
        # STS=16 (2 full bytes), byte-granularity masking, but LBSTM only
        # masks one of those two bytes -> get_pif_sts_via_qpif() fails.
        self.server.nvm_id_ns = _pack_nvm_id_ns(
            sts=16, pif=PIF_QTYPE, qpif=PIF_16B_GUARD, qpifs=True,
            pifa=PIFA_BYTE_GRANULARITY_MASKING, lbstm=0x01ff)

        result = self._read()

        self.assertNotEqual(result.returncode, 0,
                            f'nvme read with an inconsistent PI format should have failed:\n'
                            f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}')
        self.assertIn("Logical Block Storage Tag Mask is inconsistent",
                      result.stdout + result.stderr)


class SubmitIOExplicitBlockSizeTest(SubmitIOMockTestBase):
    """--block-size given: PI comes from init_pi_tags(), not get_pi_info()."""

    def _read_with_block_size(self, *args):
        return self._read('--block-size', '512', *args)

    def test_nvm_cs_ns_invalid_field_falls_back_and_succeeds(self):
        self.server.nvm_id_ns_sc_status = NVME_SC_INVALID_FIELD
        result = self._read_with_block_size()
        self.assertEqual(result.returncode, 0,
                         f'nvme read failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}')

    def test_nvm_cs_ns_other_status_error_aborts(self):
        """No "tolerate anything" fallback here: a real failure aborts the
        command, same as write-zeroes/copy."""
        self.server.nvm_id_ns_sc_status = NVME_SC_INTERNAL
        result = self._read_with_block_size()
        self.assertNotEqual(result.returncode, 0,
                            f'nvme read --block-size with Identify NVM CS NS failing on a real '
                            f'error should have failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}')

    def test_invalid_ref_tag_aborts_the_command(self):
        self.server.nvm_id_ns = _pack_nvm_id_ns(sts=8, pif=PIF_16B_GUARD)

        result = self._read_with_block_size('--ref-tag', '0x1000000')

        self.assertNotEqual(result.returncode, 0,
                            f'nvme read --block-size with an out-of-range ref tag should have '
                            f'failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}')


# ==================================================================== #
# 'nvme write-zeroes' (write_zeroes(), an init_pi_tags() caller).       #
# ==================================================================== #

class WriteZeroesInvalidTagsTest(PITagsMockTestBase):

    def setUp(self):
        super().setUp()
        # Fixed 16B Guard/STS=8 by default; individual tests override
        # nvm_id_ns_sc_status instead.
        self.server.nvm_id_ns = _pack_nvm_id_ns(sts=8, pif=PIF_16B_GUARD)

    def _write_zeroes(self, ref_tag):
        return self._run('write-zeroes', self.DEVICE, '-n', self.NSID,
                         '--ref-tag', hex(ref_tag), '--verbose')

    def test_valid_ref_tag_succeeds(self):
        """STS=8 -> ref tag is 24 bits; 0xffffff is the largest valid value."""
        result = self._write_zeroes(ref_tag=0xffffff)
        self.assertEqual(result.returncode, 0,
                         f'write-zeroes failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}')

    def test_invalid_ref_tag_aborts_the_command(self):
        result = self._write_zeroes(ref_tag=0x1000000)
        self.assertNotEqual(result.returncode, 0,
                            f'write-zeroes with an out-of-range ref tag should have failed:\n'
                            f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}')
        self.assertIn("Reference tag larger than allowed by PIF", result.stdout + result.stderr)

    def test_nvm_cs_ns_invalid_field_falls_back_and_succeeds(self):
        self.server.nvm_id_ns_sc_status = NVME_SC_INVALID_FIELD
        result = self._write_zeroes(ref_tag=0)
        self.assertEqual(result.returncode, 0,
                         f'write-zeroes failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}')


# ==================================================================== #
# 'nvme copy' (copy_cmd(), an init_pi_tags() caller).                   #
# ==================================================================== #

class CopyInvalidTagsTest(PITagsMockTestBase):

    def setUp(self):
        super().setUp()
        self.server.nvm_id_ns = _pack_nvm_id_ns(sts=8, pif=PIF_16B_GUARD)

    def _copy(self, ref_tag):
        # One source block ("0" is 1 block) is enough: init_pi_tags() only
        # cares about -n/--ref-tag/--storage-tag.
        return self._run('copy', self.DEVICE, '-n', self.NSID,
                         '--sdlba', '0', '--slbs', '0', '--blocks', '0',
                         '--ref-tag', hex(ref_tag), '--verbose')

    def test_valid_ref_tag_succeeds(self):
        result = self._copy(ref_tag=0xffffff)
        self.assertEqual(result.returncode, 0,
                         f'copy failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}')

    def test_invalid_ref_tag_aborts_the_command(self):
        result = self._copy(ref_tag=0x1000000)
        self.assertNotEqual(result.returncode, 0,
                            f'copy with an out-of-range ref tag should have failed:\n'
                            f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}')
        self.assertIn("Reference tag larger than allowed by PIF", result.stdout + result.stderr)

    def test_nvm_cs_ns_invalid_field_falls_back_and_succeeds(self):
        self.server.nvm_id_ns_sc_status = NVME_SC_INVALID_FIELD
        result = self._copy(ref_tag=0)
        self.assertEqual(result.returncode, 0,
                         f'copy failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}')


if __name__ == '__main__':
    # If called standalone, strip the arguments parsed above and run
    # standard unittest main.
    unittest_args = [sys.argv[0]]
    if len(sys.argv) > 3:
        unittest_args.extend(sys.argv[3:])
    unittest.main(argv=unittest_args)
