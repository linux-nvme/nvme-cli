#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Samsung Electronics Co., Ltd.
#
# Authors: Hyuntae Kim <h1219.kim@samsung.com>
#          Jinmin Hwang <jinmin.hwang@samsung.com>
"""Tests for "nvme samsung vs-internal-log".

Everything that does not touch the device is exercised here: option
handling, output-path composition and directory creation, dump file
naming, the data-area merge, -z archiving, progress and timing output,
and the exit status. The device itself is a mock that returns
well-formed synthetic dumps, so a failure below is a bug in the plugin
rather than in a drive.

Run from the repository root with PYTHONPATH=.
Usage: python3 <test-script> <nvme> <mock-lib>
"""
import os
import stat
import struct
import subprocess
import tarfile
import unittest

from tests.cli.nvme_mock import (CNS_CTRL, FID_HOST_BEHAVIOR, NVME_BIN,
                                 OPC_GET_LOG_PAGE, OPC_SET_FEATURES,
                                 SC_INVALID_FIELD, MockController,
                                 MockTestCase, host_behavior, main)
from tests.cli.nvme_mock_ipc import built_with_library

_HAS_LIBARCHIVE = built_with_library(NVME_BIN, 'libarchive')
_NO_LIBARCHIVE_MSG = 'built without libarchive'

SAMSUNG_VID = 0x144D
SERIAL = "MOCKSN0001"


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


class SamsungController(MockController):
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
        self.identify[CNS_CTRL] = lambda cmd: pack_id_ctrl(
            self.vid, self.serial, self.da4s)
        # ETDAS lives in the device across commands: set_etdas() only
        # writes when it reads back as 0, and clear_etdas() only restores
        # when it reads back as 1.
        self.features[FID_HOST_BEHAVIOR] = host_behavior()
        self.logs[0x00] = lambda cmd: pack_supported_log_pages(self.mcdas)
        self.logs[0x07] = self.logs[0x08] = self.telemetry
        self.admin[_OPC_VENDOR_F7] = self.admin[_OPC_VENDOR_F8] = self.dump

    @property
    def etdas(self):
        return self.features[FID_HOST_BEHAVIOR][1]

    @property
    def set_features_calls(self):
        return len(self.admin_cmds(OPC_SET_FEATURES))

    @property
    def log_lsps(self):
        return [(c.lid, c.lsp) for c in self.log_reads()]

    @property
    def log_transfers(self):
        return [(c.lid, c.lpo, c.data_len) for c in self.log_reads()]

    def telemetry(self, cmd):
        if self.telemetry_sc_status:
            return self.telemetry_sc_status
        if cmd.data_len == _TELEMETRY_HEADER_SIZE and cmd.lpo == 0:
            return pack_telemetry_header(self.last_blocks)
        return bytes([cmd.lid]) * cmd.data_len

    def dump(self, cmd):
        if not self.vendor_supported:
            return SC_INVALID_FIELD
        if cmd.data_len == 8 * 1024:
            return pack_vendor_dump_header()
        return bytes([0xAB]) * cmd.data_len


class SamsungCLITest(MockTestCase):

    controller_class = SamsungController

    def setUp(self):
        super().setUp()
        self.chdir_out_dir()

    def run_cmd(self, *args):
        return self.nvme('samsung', 'vs-internal-log', self.ctrl, *args)

    def files(self, subdir=''):
        root = os.path.join(self.out_dir, subdir) if subdir else self.out_dir
        if not os.path.isdir(root):
            return []
        return sorted(os.listdir(root))

    def _archive_members(self, relative_path):
        archive = os.path.join(self.out_dir, relative_path)
        with tarfile.open(archive, 'r:gz') as tar:
            return tar.getmembers()

    def _archive_files(self, relative_path):
        return {os.path.basename(member.name)
                for member in self._archive_members(relative_path)
                if member.isfile()}

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
    # Progress, timing and --hide-progress / --verbose                  #
    # ---------------------------------------------------------------- #

    def test_hide_progress_keeps_the_completion_line(self):
        result = self.run_cmd('-t', 'ctlr', '-O', './dumps/', '--hide-progress')
        self.assertOk(result)
        self.assertIn('100%', result.stdout,
                      '--hide-progress swallowed the completion line')

    def test_hide_progress_drops_incremental_updates(self):
        with_progress = self.run_cmd('-t', 'ctlr', '-O', './a/')
        without = self.run_cmd('-t', 'ctlr', '-O', './b/', '--hide-progress')
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
        result = self.run_cmd('-t', 'ctlr', '-O', './a/', '--hide-progress', '--verbose')
        self.assertOk(result)
        self.assertIn('Avg time per loop', result.stdout,
                      '--hide-progress suppressed the --verbose timing table')

    # ---------------------------------------------------------------- #
    # Serial number handling: the drive supplies it and it lands in     #
    # the dump file names, so it must not steer the output path.        #
    # ---------------------------------------------------------------- #

    BAD_SERIAL = "../bad'\x01sn"
    SAFE_SERIAL = '___bad__sn'

    def test_serial_is_sanitized_before_it_is_used_in_file_names(self):
        self.server.serial = self.BAD_SERIAL
        result = self.run_cmd('-t', 'ctlr', '-O', './serial/')
        self.assertOk(result)
        names = self.files('serial')
        self.assertTrue(names, 'no dump was written')
        self.assertTrue(all(f.startswith(self.SAFE_SERIAL) for f in names),
                        names)
        self.assertEqual(self.files(), ['serial'],
                         'the serial escaped the designated output directory')

    @unittest.skipUnless(_HAS_LIBARCHIVE, _NO_LIBARCHIVE_MSG)
    def test_serial_is_sanitized_before_it_is_used_in_the_archive_name(self):
        self.server.serial = self.BAD_SERIAL
        result = self.run_cmd('-t', 'ctlr', '-O', './serial/', '-z')
        self.assertOk(result)
        archive = f'serial/Samsung_Dump_{self.SAFE_SERIAL}.tar.gz'
        self.assertTrue(os.path.isfile(os.path.join(self.out_dir, archive)),
                        f'no archive at {archive}: {self.files("serial")}')
        self.assertEqual(self.files(), ['serial'],
                         'the serial escaped the designated output directory')

    # ---------------------------------------------------------------- #
    # -z archiving                                                      #
    # ---------------------------------------------------------------- #

    @unittest.skipUnless(_HAS_LIBARCHIVE, _NO_LIBARCHIVE_MSG)
    def test_compress_produces_an_archive_and_removes_the_temp_dir(self):
        result = self.run_cmd('-t', 'ctlr', '-O', './dumps/', '-z')
        self.assertOk(result)
        archive = f'dumps/Samsung_Dump_{SERIAL}.tar.gz'
        self.assertTrue(os.path.isfile(os.path.join(self.out_dir, archive)),
                        f'no archive produced: {self.files("dumps")}')
        members = self._archive_files(archive)
        self.assertTrue(members, 'the archive holds no dump file')
        self.assertTrue(all(name.startswith(SERIAL) for name in members), members)
        self.assertFalse(os.path.isdir(os.path.join(self.out_dir,
                                                    'dumps/temp_samsung_dumps')),
                         'the temporary directory was left behind')

    @unittest.skipUnless(_HAS_LIBARCHIVE, _NO_LIBARCHIVE_MSG)
    def test_compress_archives_the_dump_files_and_nothing_else(self):
        """A directory member would carry the staging directory's mode, and
        tar applies that mode to the directory the archive is extracted
        into."""
        result = self.run_cmd('-t', 'ctlr', '-O', './dumps/', '-z')
        self.assertOk(result)
        members = self._archive_members(f'dumps/Samsung_Dump_{SERIAL}.tar.gz')
        self.assertTrue(members, 'the archive is empty')
        self.assertTrue(all(member.isfile() for member in members),
                        [member.name for member in members])

    @unittest.skipUnless(_HAS_LIBARCHIVE, _NO_LIBARCHIVE_MSG)
    def test_compress_treats_shell_metacharacters_as_literal_path_data(self):
        for component in ("odd'; touch PWNED; #", 'odd& echo PWNED &'):
            with self.subTest(component=component):
                result = self.run_cmd('-t', 'ctlr', '-O', f'./{component}/', '-z')
                self.assertOk(result)
                archive = os.path.join(component,
                                       f'Samsung_Dump_{SERIAL}.tar.gz')
                self.assertTrue(os.path.isfile(os.path.join(self.out_dir,
                                                            archive)))
                self.assertNotIn('PWNED', self.files(),
                                 'the output path was interpreted by a shell')
                self.assertFalse(os.path.exists(os.path.join(
                    self.out_dir, component, 'temp_samsung_dumps')))

    @unittest.skipUnless(_HAS_LIBARCHIVE, _NO_LIBARCHIVE_MSG)
    def test_compress_keeps_file_name_prefixes_local(self):
        cases = (
            ('./dumps/run1', f'dumps/run1Samsung_Dump_{SERIAL}.tar.gz',
             'run1', 'dumps/temp_samsung_dumps'),
            ('local:name', f'local:nameSamsung_Dump_{SERIAL}.tar.gz',
             'local:name', 'temp_samsung_dumps'),
        )
        for output, archive, member_prefix, staging in cases:
            with self.subTest(output=output):
                result = self.run_cmd('-t', 'ctlr', '-O', output, '-z')
                self.assertOk(result)
                self.assertTrue(os.path.isfile(os.path.join(self.out_dir,
                                                            archive)))
                members = self._archive_files(archive)
                self.assertTrue(members, 'the archive holds no dump file')
                self.assertTrue(all(name.startswith(member_prefix + SERIAL)
                                    for name in members), members)
                self.assertFalse(os.path.exists(os.path.join(self.out_dir,
                                                             staging)))

    def test_compress_refuses_preexisting_staging_objects(self):
        for kind in ('directory', 'file', 'symlink'):
            with self.subTest(kind=kind):
                relative_parent = f'existing-{kind}'
                parent = os.path.join(self.out_dir, relative_parent)
                staging = os.path.join(parent, 'temp_samsung_dumps')
                os.makedirs(parent)

                if kind == 'directory':
                    os.mkdir(staging)
                    sentinel = os.path.join(staging, 'sentinel')
                elif kind == 'file':
                    sentinel = staging
                else:
                    target = os.path.join(self.out_dir, 'symlink-target')
                    os.makedirs(target, exist_ok=True)
                    sentinel = os.path.join(target, 'sentinel')
                    os.symlink(target, staging)

                with open(sentinel, 'w', encoding='utf-8') as f:
                    f.write(kind)

                self.server.commands.clear()
                result = self.run_cmd('-t', 'ctlr',
                                      '-O', f'./{relative_parent}/', '-z')
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(OPC_GET_LOG_PAGE, self.server.opcodes(),
                                 'the dump started despite a taken staging path')
                self.assertIn(f'Remove ./{relative_parent}/temp_samsung_dumps '
                              'and run the command again', result.stderr,
                              'the failure does not say what to remove')
                with open(sentinel, encoding='utf-8') as f:
                    self.assertEqual(f.read(), kind, 'the sentinel was written over')
                if kind == 'symlink':
                    self.assertTrue(os.path.islink(staging))
                self.assertFalse(os.path.exists(os.path.join(
                    parent, f'Samsung_Dump_{SERIAL}.tar.gz')))

    def test_compress_failure_is_reported_and_keeps_staging(self):
        """A drive is collected but the archive cannot be written.

        Archiving goes through libarchive in-process now, not a spawned tar,
        so there is no external tool left to fail; a directory already
        sitting at the archive's target path makes
        archive_write_open_filename() fail the same way (EISDIR), regardless
        of privilege.
        """
        parent = 'archive-failure'
        archive = os.path.join(parent, f'Samsung_Dump_{SERIAL}.tar.gz')
        os.makedirs(os.path.join(self.out_dir, archive))

        result = self.run_cmd('-t', 'ctlr', '-O', f'./{parent}/', '-z')

        self.assertNotEqual(result.returncode, 0)
        staging = os.path.join(self.out_dir, parent, 'temp_samsung_dumps')
        self.assertTrue(os.path.isdir(staging),
                        'the staged dumps were discarded')
        self.assertEqual(stat.S_IMODE(os.stat(staging).st_mode), 0o700,
                         'the staging directory is not private')
        self.assertTrue(os.listdir(staging), 'the staged dumps were discarded')

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

    def test_repeated_dump_types(self):
        result = self.run_cmd('-t', 'CTLR', '-t', 'vendor', '-O', './dumps/')
        self.assertOk(result)
        names = self.files('dumps')
        self.assertTrue(any('Telemetry_Controller' in f for f in names), names)
        self.assertTrue(any('VendorCrashDump' in f for f in names), names)

    def test_unknown_dump_type_is_rejected(self):
        for types in ('nosuchtype', 'ctlr,nosuchtype', 'ctlr,', ''):
            with self.subTest(types=types):
                result = self.run_cmd('-t', types, '-O', './dumps/')
                self.assertNotEqual(result.returncode, 0,
                                    'an unknown -t token must fail')
                self.assertIn('host0, host1, ctlr, controller, vendor',
                              result.stderr)

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
            [NVME_BIN, 'samsung', 'vs-internal-log', '--help'],
            capture_output=True, text=True)
        self.assertIn('Output format: normal', result.stdout + result.stderr)

    def test_help_keeps_capital_O_for_output_file(self):
        result = subprocess.run(
            [NVME_BIN, 'samsung', 'vs-internal-log', '--help'],
            capture_output=True, text=True)
        out = result.stdout + result.stderr
        self.assertIn('--output-file=<FILE>, -O <FILE>', out)
        self.assertIn('--output-format=<FMT>, -o <FMT>', out)

    def test_direct_telemetry_keeps_127k_transfers(self):
        self.server.last_blocks = (260, 260, 260, 260)
        result = self.run_cmd('-t', 'ctlr', '-a', '1', '--hide-progress')
        self.assertOk(result)
        self.assertIn('(Xfer 127K)', result.stdout)
        self.assertEqual(self.server.log_transfers, [
            (0x08, 0, 512), (0x08, 0, 512),
            (0x08, 512, 127 * 1024), (0x08, 512 + 127 * 1024, 3 * 1024),
        ])
        path = os.path.join(self.out_dir,
                            f'{SERIAL}_Telemetry_Controller_Area_1.bin')
        with open(path, 'rb') as f:
            self.assertEqual(f.read(), bytes([0x08]) * 260 * _BYTES_PER_BLOCK)

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

    @unittest.skipUnless(_HAS_LIBARCHIVE, _NO_LIBARCHIVE_MSG)
    def test_compress_with_single_data_area(self):
        result = self.run_cmd('-t', 'ctlr', '-a', '2', '-O', './dumps/', '-z')
        self.assertOk(result)
        self.assertTrue(any(f.endswith('.tar.gz') for f in self.files('dumps')),
                        f'no archive: {self.files("dumps")}')

    @unittest.skipUnless(_HAS_LIBARCHIVE, _NO_LIBARCHIVE_MSG)
    def test_compress_with_hide_progress(self):
        result = self.run_cmd('-t', 'ctlr', '-O', './dumps/', '-z', '--hide-progress')
        self.assertOk(result)
        self.assertTrue(any(f.endswith('.tar.gz') for f in self.files('dumps')),
                        f'no archive: {self.files("dumps")}')
        self.assertIn('100%', result.stdout,
                      'the completion line went missing under -z -H')

    @unittest.skipUnless(_HAS_LIBARCHIVE, _NO_LIBARCHIVE_MSG)
    def test_compress_without_output_option(self):
        result = self.run_cmd('-t', 'ctlr', '-z')
        self.assertOk(result)
        archive = f'Samsung_Dump_{SERIAL}.tar.gz'
        self.assertTrue(os.path.isfile(os.path.join(self.out_dir, archive)),
                        f'no archive in the cwd: {self.files()}')
        members = self._archive_files(archive)
        self.assertTrue(members, 'the archive holds no dump file')
        self.assertTrue(all(name.startswith(SERIAL) for name in members), members)
        self.assertFalse(os.path.isdir(os.path.join(self.out_dir,
                                                    'temp_samsung_dumps')),
                         'the temporary directory was left behind')


if __name__ == '__main__':
    main()
