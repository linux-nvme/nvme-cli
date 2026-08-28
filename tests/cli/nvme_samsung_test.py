#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
"""Tests for "nvme samsung vs-internal-log".

Everything that does not touch the device is exercised here: option
handling, output-path composition and directory creation, dump file
naming, the data-area merge, -z archiving, progress and timing output,
and the exit status. The device itself is a mock that returns
well-formed synthetic dumps, so a failure below is a bug in the plugin
rather than in a drive.

Usage: python3 nvme_samsung_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from nvme_mock_ipc import MockIPCServer, make_mock_env, resolve_mock_lib_path, run_nvme

_NVME_BIN = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else 'nvme'
_MOCK_LIB = resolve_mock_lib_path("./libmock_nvme.so")

# Meson passes these as paths relative to the build directory, and the
# tests below chdir into a scratch directory to exercise the default
# output location. Pin them down first.
if os.path.exists(_NVME_BIN):
    _NVME_BIN = os.path.abspath(_NVME_BIN)
if os.path.exists(_MOCK_LIB):
    _MOCK_LIB = os.path.abspath(_MOCK_LIB)

SAMSUNG_VID = 0x144D
SERIAL = "MOCKSN0001"

_OPC_GET_LOG_PAGE = 0x02
_OPC_IDENTIFY = 0x06
_OPC_SET_FEATURES = 0x09
_OPC_GET_FEATURES = 0x0A

_FID_HOST_BEHAVIOR = 0x16
_HOST_BEHAVIOR_SIZE = 512
_ETDAS_OFFSET = 1  # struct nvme_feat_host_behavior: acre, etdas, ...

# Samsung vendor dump opcodes
_OPC_VENDOR_F7 = 0xF7
_OPC_VENDOR_F8 = 0xF8

_ID_CTRL_SIZE = 4096
_TELEMETRY_HEADER_SIZE = 512
_BYTES_PER_BLOCK = 512

# The vendor dump header reports its size at bytes 12..15, counted in 8K
# units; the plugin then reads 32K per step. 4 keeps the mock dump small.
_VENDOR_DUMP_UNITS = 4


def pack_id_ctrl(vid=SAMSUNG_VID, serial=SERIAL, da4s=False):
    """struct nvme_id_ctrl. Only VID (0), SN (4..23) and LPA (261) matter:
    LPA bit 6 is Data Area 4 Supported."""
    buf = bytearray(_ID_CTRL_SIZE)
    struct.pack_into('<H', buf, 0, vid)
    sn = serial.encode().ljust(20)[:20]
    buf[4:24] = sn
    if da4s:
        buf[261] |= 1 << 6
    return bytes(buf)


def pack_telemetry_header(last_blocks=(2, 4, 0, 0)):
    """struct telemetry_initiated_log. last_blocks is the last block of
    data areas 1..4; area N is empty when its last block does not advance
    past area N-1."""
    buf = bytearray(_TELEMETRY_HEADER_SIZE)
    buf[0] = 0x07
    struct.pack_into('<H', buf, 8, last_blocks[0])
    struct.pack_into('<H', buf, 10, last_blocks[1])
    struct.pack_into('<H', buf, 12, last_blocks[2])
    struct.pack_into('<I', buf, 16, last_blocks[3])
    return bytes(buf)


def pack_supported_log_pages(mcdas=True):
    """Log page 0. data[30] bit 0 is MCDAS for LID 7."""
    buf = bytearray(1024)
    if mcdas:
        buf[30] |= 1
    return bytes(buf)


def pack_vendor_dump_header(units=_VENDOR_DUMP_UNITS):
    buf = bytearray(8 * 1024)
    struct.pack_into('<I', buf, 12, units)
    return bytes(buf)


class SamsungMockServer(MockIPCServer):
    """Answers the commands vs-internal-log issues. Anything not listed
    succeeds with zeroes, which is enough for the feature negotiation the
    plugin does around Data Area 4."""

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.vid = SAMSUNG_VID
        self.serial = SERIAL
        self.da4s = False
        self.mcdas = True
        self.last_blocks = (2, 4, 0, 0)
        self.vendor_supported = True
        self.telemetry_sc_status = 0
        self.seen_opcodes = []
        # ETDAS lives in the device across commands, so the mock has to
        # keep it: set_etdas() only writes when it reads back as 0, and
        # clear_etdas() only restores when it reads back as 1.
        self.etdas = 0
        self.set_features_calls = 0
        self.log_lsps = []

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                     cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        self.seen_opcodes.append(opcode)

        if opcode == _OPC_GET_FEATURES and (cdw10 & 0xFF) == _FID_HOST_BEHAVIOR:
            buf = bytearray(_HOST_BEHAVIOR_SIZE)
            buf[_ETDAS_OFFSET] = self.etdas
            self.send_response(conn, 0, payload=bytes(buf)[:req_len])
            return

        if opcode == _OPC_SET_FEATURES and (cdw10 & 0xFF) == _FID_HOST_BEHAVIOR:
            # The outgoing buffer is not forwarded to the mock, but the
            # caller only ever writes the value it did not read, so
            # toggling tracks it exactly.
            self.etdas ^= 1
            self.set_features_calls += 1
            self.send_response(conn, 0)
            return

        if opcode == _OPC_IDENTIFY:
            payload = pack_id_ctrl(self.vid, self.serial, self.da4s)
            self.send_response(conn, 0, payload=payload[:req_len])
            return

        if opcode == _OPC_GET_LOG_PAGE:
            lid = cdw10 & 0xFF
            self.log_lsps.append((lid, (cdw10 >> 8) & 0x7F))
            if lid == 0:
                payload = pack_supported_log_pages(self.mcdas)
            elif lid in (0x07, 0x08):
                if self.telemetry_sc_status:
                    self.send_response(conn, 0, sc_status=self.telemetry_sc_status)
                    return
                if req_len == _TELEMETRY_HEADER_SIZE and lpo == 0:
                    payload = pack_telemetry_header(self.last_blocks)
                else:
                    payload = bytes([lid]) * req_len
            else:
                payload = bytes(req_len)
            self.send_response(conn, 0, payload=payload[:req_len])
            return

        if opcode in (_OPC_VENDOR_F7, _OPC_VENDOR_F8):
            if not self.vendor_supported:
                self.send_response(conn, 0, sc_status=0x02)  # INVALID_FIELD
                return
            if req_len == 8 * 1024:
                payload = pack_vendor_dump_header()
            else:
                payload = bytes([0xAB]) * req_len
            self.send_response(conn, 0, payload=payload[:req_len])
            return

        self.send_response(conn, 0, payload=bytes(req_len))


class SamsungCLITest(unittest.TestCase):

    DEVICE = '/dev/nvme0'

    def setUp(self):
        self.sysfs_dir = tempfile.mkdtemp(prefix='nvme-samsung-sysfs-', dir='/tmp')
        self.base_dir = tempfile.mkdtemp(prefix='nvme-samsung-base-', dir='/tmp')
        self.ipc_dir = tempfile.mkdtemp(prefix='nvme-samsung-ipc-', dir='/tmp')
        self.out_dir = tempfile.mkdtemp(prefix='nvme-samsung-out-', dir='/tmp')
        self.ipc_sock_path = os.path.join(self.ipc_dir, "ipc.sock")

        self.server = SamsungMockServer(self.ipc_sock_path)
        self.server.start()
        self.env = make_mock_env(_MOCK_LIB, self.ipc_sock_path)
        self.cwd = os.getcwd()
        os.chdir(self.out_dir)

    def tearDown(self):
        os.chdir(self.cwd)
        self.server.shutdown()
        self.server.join()
        for d in (self.sysfs_dir, self.base_dir, self.ipc_dir, self.out_dir):
            shutil.rmtree(d, ignore_errors=True)

    def run_cmd(self, *args):
        return run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                        'samsung', 'vs-internal-log', self.DEVICE, *args)

    def files(self, subdir=''):
        root = os.path.join(self.out_dir, subdir) if subdir else self.out_dir
        if not os.path.isdir(root):
            return []
        return sorted(os.listdir(root))

    def assertOk(self, result):
        self.assertEqual(result.returncode, 0,
                         f'command failed:\nstdout:\n{result.stdout}\n'
                         f'stderr:\n{result.stderr}')

    # ---------------------------------------------------------------- #
    # Output path handling: -O is a file name prefix, so directories    #
    # end at the last '/' whichever form is used.                       #
    # ---------------------------------------------------------------- #

    def test_output_dir_with_trailing_slash_is_created(self):
        result = self.run_cmd('-t', 'ctlr', '-O', './dumps/')
        self.assertOk(result)
        self.assertTrue(os.path.isdir(os.path.join(self.out_dir, 'dumps')),
                        './dumps/ was not created')
        self.assertTrue(any(f.startswith(SERIAL) for f in self.files('dumps')),
                        f'no dump written into ./dumps/: {self.files("dumps")}')

    def test_output_nested_dir_is_created(self):
        result = self.run_cmd('-t', 'ctlr', '-O', './a/b/c/')
        self.assertOk(result)
        self.assertTrue(os.path.isdir(os.path.join(self.out_dir, 'a/b/c')),
                        './a/b/c was not created')

    def test_output_relative_dir_without_dot_is_created(self):
        """The old mkdirs() rejected any path not starting with '.' or '/'."""
        result = self.run_cmd('-t', 'ctlr', '-O', 'dumps/')
        self.assertOk(result)
        self.assertTrue(os.path.isdir(os.path.join(self.out_dir, 'dumps')),
                        'dumps/ was not created')

    def test_output_last_component_is_a_file_name_prefix(self):
        result = self.run_cmd('-t', 'ctlr', '-O', './dumps/run1')
        self.assertOk(result)
        names = self.files('dumps')
        self.assertFalse(os.path.isdir(os.path.join(self.out_dir, 'dumps/run1')),
                         'run1 became a directory; it is a file name prefix')
        self.assertTrue(any(f.startswith('run1' + SERIAL) for f in names),
                        f'no run1-prefixed dump: {names}')

    # ---------------------------------------------------------------- #
    # Data area merge                                                   #
    # ---------------------------------------------------------------- #

    def test_merge_name_lists_only_the_areas_present(self):
        """Areas 3 and 4 are empty here, so the merged dump must not claim
        them. Area 4's last block is lower than area 3's, which is the
        unsigned-wrap case."""
        self.server.last_blocks = (2, 4, 0, 0)
        result = self.run_cmd('-t', 'ctlr', '-O', './dumps/')
        self.assertOk(result)
        names = self.files('dumps')
        self.assertTrue(any('Area_1+2.bin' in f for f in names),
                        f'no Area_1+2.bin: {names}')
        self.assertFalse(any('Area_1+2+3+4.bin' in f for f in names),
                         f'claimed areas that were never retrieved: {names}')

    def test_merge_includes_all_four_areas_when_present(self):
        self.server.last_blocks = (2, 4, 6, 8)
        result = self.run_cmd('-t', 'ctlr', '-O', './dumps/')
        self.assertOk(result)
        names = self.files('dumps')
        self.assertTrue(any('Area_1+2+3+4.bin' in f for f in names),
                        f'no Area_1+2+3+4.bin: {names}')

    def test_merged_file_is_header_plus_areas(self):
        self.server.last_blocks = (2, 4, 0, 0)
        self.assertOk(self.run_cmd('-t', 'ctlr', '-O', './dumps/'))
        d = os.path.join(self.out_dir, 'dumps')
        merged = [f for f in os.listdir(d) if f.endswith('Area_1+2.bin')][0]
        header = [f for f in os.listdir(d) if f.endswith('header_only.bin')][0]
        a1 = [f for f in os.listdir(d) if f.endswith('Area_1.bin')][0]
        a2 = [f for f in os.listdir(d) if f.endswith('Area_2.bin')][0]
        expect = (os.path.getsize(os.path.join(d, header))
                  + os.path.getsize(os.path.join(d, a1))
                  + os.path.getsize(os.path.join(d, a2)))
        self.assertEqual(os.path.getsize(os.path.join(d, merged)), expect,
                         'merged size is not header + area 1 + area 2')

    # ---------------------------------------------------------------- #
    # Progress, timing and -H / --verbose                               #
    # ---------------------------------------------------------------- #

    def test_hide_progress_keeps_the_completion_line(self):
        result = self.run_cmd('-t', 'ctlr', '-O', './dumps/', '-H')
        self.assertOk(result)
        self.assertIn('100%', result.stdout,
                      '--hide-progress swallowed the completion line')

    def test_hide_progress_drops_incremental_updates(self):
        with_progress = self.run_cmd('-t', 'ctlr', '-O', './a/')
        without = self.run_cmd('-t', 'ctlr', '-O', './b/', '-H')
        self.assertOk(with_progress)
        self.assertOk(without)
        self.assertLess(without.stdout.count('%'), with_progress.stdout.count('%'),
                        '--hide-progress did not reduce the progress output')

    def test_timing_table_is_verbose_only(self):
        quiet = self.run_cmd('-t', 'ctlr', '-O', './a/')
        loud = self.run_cmd('-t', 'ctlr', '-O', './b/', '--verbose')
        self.assertOk(quiet)
        self.assertNotIn('Avg time per loop', quiet.stdout,
                         'timing table printed without --verbose')
        self.assertIn('Avg time per loop', loud.stdout,
                      'timing table missing under --verbose')

    def test_timing_table_is_not_tied_to_hide_progress(self):
        result = self.run_cmd('-t', 'ctlr', '-O', './a/', '-H', '--verbose')
        self.assertOk(result)
        self.assertIn('Avg time per loop', result.stdout,
                      '--hide-progress suppressed the --verbose timing table')

    # ---------------------------------------------------------------- #
    # -z archiving                                                      #
    # ---------------------------------------------------------------- #

    def test_compress_produces_an_archive_and_removes_the_temp_dir(self):
        result = self.run_cmd('-t', 'ctlr', '-O', './dumps/', '-z')
        self.assertOk(result)
        names = self.files('dumps')
        self.assertTrue(any(f.endswith('.tar.gz') for f in names),
                        f'no archive produced: {names}')
        self.assertFalse(os.path.isdir(os.path.join(self.out_dir,
                                                    'dumps/temp_samsung_dumps')),
                         'the temporary directory was left behind')

    def test_compress_rejects_a_quote_in_the_output_path(self):
        os.makedirs(os.path.join(self.out_dir, "od'd"), exist_ok=True)
        result = self.run_cmd('-t', 'ctlr', '-O', "./od'd/", '-z')
        self.assertNotEqual(result.returncode, 0,
                            "a path containing ' must be refused, not shelled out")

    # ---------------------------------------------------------------- #
    # Dump type selection                                               #
    # ---------------------------------------------------------------- #

    def test_comma_separated_dump_types(self):
        result = self.run_cmd('-t', 'ctlr,vendor', '-O', './dumps/')
        self.assertOk(result)
        names = self.files('dumps')
        self.assertTrue(any('Telemetry_Controller' in f for f in names), names)
        self.assertTrue(any('VendorCrashDump' in f for f in names), names)

    def test_host0_is_excluded_unless_named(self):
        self.assertOk(self.run_cmd('-O', './all/'))
        self.assertFalse(any('Host(0)' in f for f in self.files('all')),
                         'host0 was collected without being named')
        self.assertOk(self.run_cmd('-t', 'host0', '-O', './h0/'))
        self.assertTrue(any('Host(0)' in f for f in self.files('h0')),
                        f'host0 was not collected when named: {self.files("h0")}')

    def test_unknown_dump_type_is_rejected(self):
        result = self.run_cmd('-t', 'nosuchtype', '-O', './dumps/')
        self.assertNotEqual(result.returncode, 0,
                            'an unknown -t token must fail')

    # ---------------------------------------------------------------- #
    # -a validation, which used to be skipped without -t                #
    # ---------------------------------------------------------------- #

    def test_data_area_out_of_range_is_rejected_with_dump_type(self):
        result = self.run_cmd('-t', 'ctlr', '-a', '7', '-O', './dumps/')
        self.assertNotEqual(result.returncode, 0, '-a 7 must be refused')

    def test_data_area_out_of_range_is_rejected_without_dump_type(self):
        result = self.run_cmd('-a', '7', '-O', './dumps/')
        self.assertNotEqual(result.returncode, 0,
                            '-a 7 must be refused even without -t')

    def test_single_data_area_extracts_only_that_area(self):
        self.server.last_blocks = (2, 4, 6, 8)
        result = self.run_cmd('-t', 'ctlr', '-a', '2', '-O', './dumps/')
        self.assertOk(result)
        names = self.files('dumps')
        self.assertTrue(any('Area_2.bin' in f for f in names), names)
        self.assertFalse(any('Area_3.bin' in f for f in names), names)

    # ---------------------------------------------------------------- #
    # Exit status                                                       #
    # ---------------------------------------------------------------- #

    def test_non_samsung_device_fails(self):
        self.server.vid = 0x1234
        result = self.run_cmd('-t', 'ctlr', '-O', './dumps/')
        self.assertNotEqual(result.returncode, 0,
                            'a non-Samsung VID must not exit successfully')
        self.assertIn('0x1234', result.stderr,
                      f'VID not reported endian-converted: {result.stderr}')

    def test_unsupported_vendor_dump_is_reported_but_not_fatal(self):
        self.server.vendor_supported = False
        result = self.run_cmd('-t', 'vendor', '-O', './dumps/')
        self.assertOk(result)
        self.assertIn('not supported', result.stdout + result.stderr)

    # ---------------------------------------------------------------- #
    # Option surface                                                    #
    # ---------------------------------------------------------------- #

    def test_help_declares_normal_output_format_only(self):
        result = subprocess.run(
            [_NVME_BIN, 'samsung', 'vs-internal-log', '--help'],
            capture_output=True, text=True)
        self.assertIn('Output format: normal', result.stdout + result.stderr)

    def test_help_keeps_capital_O_for_output_file(self):
        result = subprocess.run(
            [_NVME_BIN, 'samsung', 'vs-internal-log', '--help'],
            capture_output=True, text=True)
        out = result.stdout + result.stderr
        self.assertIn('--output-file=<FILE>, -O <FILE>', out)
        self.assertIn('--output-format=<FMT>, -o <FMT>', out)

    # ---------------------------------------------------------------- #
    # Data Area 4: DA4S / MCDAS negotiation and the ETDAS round trip    #
    # ---------------------------------------------------------------- #

    def _enable_da4(self):
        self.server.da4s = True
        self.server.mcdas = True
        self.server.last_blocks = (2, 4, 6, 8)

    def test_da4_setup_completes_when_supported(self):
        self._enable_da4()
        result = self.run_cmd('-t', 'host1', '-O', './dumps/')
        self.assertOk(result)
        self.assertIn('Setup for Data Area 4 extraction is done', result.stdout)
        self.assertTrue(any('Area_4.bin' in f for f in self.files('dumps')),
                        f'area 4 not extracted: {self.files("dumps")}')

    def test_da4_etdas_is_set_and_restored(self):
        self._enable_da4()
        self.assertOk(self.run_cmd('-t', 'host1', '-O', './dumps/'))
        self.assertGreaterEqual(self.server.set_features_calls, 2,
                                'ETDAS was not both set and restored')
        self.assertEqual(self.server.etdas, 0,
                         'ETDAS was left set on the device')

    def test_da4_sets_mcda_in_the_log_specific_parameter(self):
        """With MCDAS set, the host dump asks for MCDA 4: lsp |= 4 << 1,
        so LSP 1 becomes 9."""
        self._enable_da4()
        self.assertOk(self.run_cmd('-t', 'host1', '-O', './dumps/'))
        lsps = [lsp for lid, lsp in self.server.log_lsps if lid == 0x07]
        self.assertIn(9, lsps, f'MCDA 4 never requested; LSPs seen: {lsps}')

    def test_da4_unsupported_is_reported_and_not_fatal(self):
        self.server.da4s = False
        self.server.last_blocks = (2, 4, 6, 8)
        result = self.run_cmd('-t', 'host1', '-O', './dumps/')
        self.assertOk(result)
        self.assertIn('Data Area 4 Support(DA4S) bit is 0', result.stdout)
        self.assertIn('Data Area 4 will not be extracted', result.stdout)
        self.assertEqual(self.server.set_features_calls, 0,
                         'ETDAS touched although DA4S is 0')

    def test_mcdas_off_still_extracts_but_says_so(self):
        self.server.da4s = True
        self.server.mcdas = False
        self.server.last_blocks = (2, 4, 6, 8)
        result = self.run_cmd('-t', 'host1', '-O', './dumps/')
        self.assertOk(result)
        self.assertIn('Maximum Created Data Area Support(MCDAS) bit is 0',
                      result.stdout)
        self.assertIn('Setup for Data Area 4 extraction is done', result.stdout)

    def test_ctlr_dump_does_not_consult_mcdas(self):
        """MCDAS is only meaningful for the host-initiated log (lsp == 1)."""
        self._enable_da4()
        self.assertOk(self.run_cmd('-t', 'ctlr', '-O', './dumps/'))
        self.assertNotIn('Maximum Created Data Area Support', self.run_cmd(
            '-t', 'ctlr', '-O', './b/').stdout)

    # ---------------------------------------------------------------- #
    # Remaining option combinations                                     #
    # ---------------------------------------------------------------- #

    def test_host1_dump_type(self):
        result = self.run_cmd('-t', 'host1', '-O', './dumps/')
        self.assertOk(result)
        self.assertTrue(any('Host(1)' in f for f in self.files('dumps')),
                        f'no host1 dump: {self.files("dumps")}')

    def test_all_dump_types_named_explicitly(self):
        self._enable_da4()
        result = self.run_cmd('-t', 'host0,host1,ctlr,vendor', '-O', './dumps/')
        self.assertOk(result)
        names = self.files('dumps')
        for want in ('Host(0)', 'Host(1)', 'Controller', 'VendorCrashDump'):
            self.assertTrue(any(want in f for f in names),
                            f'{want} missing from {names}')

    def test_each_single_data_area(self):
        self._enable_da4()
        for area in (1, 2, 3, 4):
            with self.subTest(area=area):
                out = f'./a{area}/'
                result = self.run_cmd('-t', 'ctlr', '-a', str(area), '-O', out)
                self.assertOk(result)
                names = self.files(f'a{area}')
                self.assertTrue(any(f'Area_{area}.bin' in f for f in names),
                                f'-a {area} produced {names}')
                for other in {1, 2, 3, 4} - {area}:
                    self.assertFalse(any(f'Area_{other}.bin' in f for f in names),
                                     f'-a {area} also wrote area {other}: {names}')

    def test_default_output_is_the_current_directory(self):
        result = self.run_cmd('-t', 'ctlr')
        self.assertOk(result)
        self.assertTrue(any(f.startswith(SERIAL) for f in self.files()),
                        f'nothing written to the cwd: {self.files()}')

    def test_compress_with_single_data_area(self):
        result = self.run_cmd('-t', 'ctlr', '-a', '2', '-O', './dumps/', '-z')
        self.assertOk(result)
        self.assertTrue(any(f.endswith('.tar.gz') for f in self.files('dumps')),
                        f'no archive: {self.files("dumps")}')

    def test_compress_with_hide_progress(self):
        result = self.run_cmd('-t', 'ctlr', '-O', './dumps/', '-z', '-H')
        self.assertOk(result)
        self.assertTrue(any(f.endswith('.tar.gz') for f in self.files('dumps')),
                        f'no archive: {self.files("dumps")}')
        self.assertIn('100%', result.stdout,
                      'the completion line went missing under -z -H')

    def test_compress_without_output_option(self):
        result = self.run_cmd('-t', 'ctlr', '-z')
        self.assertOk(result)
        self.assertTrue(any(f.endswith('.tar.gz') for f in self.files()),
                        f'no archive in the cwd: {self.files()}')
        self.assertFalse(os.path.isdir(os.path.join(self.out_dir,
                                                    'temp_samsung_dumps')),
                         'the temporary directory was left behind')


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]], verbosity=2)
