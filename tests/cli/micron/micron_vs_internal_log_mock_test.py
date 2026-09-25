#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron vs-internal-log command, hardware-free.

vs-internal-log has two modes.  By default it collects a debug package: a
staging directory named after the drive serial, filled with model-specific log
pages plus OS diagnostics and descriptor files, then archived and removed.
With --type it instead extracts a single telemetry log for one data area.

Which log pages the package collects depends on the drive model, and the
telemetry mode depends on the identify LPA field, so on hardware only one
drive's worth of either is reachable.  Here both are inputs: the collected
page set is asserted per model against the mock's record of what was read,
and the telemetry file's size is asserted against the header that sized it.

Tests in this module verify:
  * Argument validation: a missing or unsafe --package, an unrecognised
    --type, a missing or out-of-range --data_area, and --data_area without
    --type -- all of which precede the model gate.
  * Telemetry mode: the log page per type, the LPA support gate, the file
    size matching (data area last block + 1) * 512, and an empty data area.
  * Package mode: the archive for each supported extension, the staging
    directory being removed, and the archive tool's failure being reported.
  * The descriptor files the offline parser needs, with the PCI IDs and
    identify strings the drive reported.
  * The per-model log page sets, and the serial number being sanitised
    before it names a directory.
  * Error handling for a non-existent device.

Usage: python3 micron_vs_internal_log_mock_test.py <nvme-binary> <mock-lib>
"""

import csv
import io
import json
import os
import shutil
import struct
import tarfile
import zipfile

from micron_mock_test import (
    LID_TELEMETRY_CTRL,
    LID_TELEMETRY_HOST,
    LPA_TELEMETRY,
    MICRON_MODELS,
    MICRON_VENDOR_ID,
    TestMicronMock,
    main,
    pack_id_ctrl,
    pack_telemetry_log,
)

_COMMAND = "vs-internal-log"

_TELEMETRY_BLOCK = 512

_UNSUPPORTED_MODEL_MSG = ("Unsupported drive model for vs-internal-log "
                          "collection")
_TELEMETRY_UNSUPPORTED_MSG = ("telemetry option is not supported for "
                              "specified drive")

# Descriptor files the offline parser requires, relative to the package root.
_METADATA_FILE = "logpull_metadata_info.json"
_CMD_STATUS_FILE = "Controller/logpull_cmd_status_info.csv"
_DRIVE_INFO_FILE = "drive-info.txt"

_CMD_STATUS_COLUMNS = [
    "serial_number", "cmd_info", "op_code", "log_id", "cmd_class", "cmd_code",
    "binary_file", "execution_time_us", "mse_status",
]

_METADATA_REQUIRED_KEYS = [
    "tool_pull_name", "device_id", "vendor_id", "serial_number",
    "firmware_revision", "model_number_identify",
]

# Log pages every model's collection walks, from the base aVendorLogs table.
_BASE_LOGS = {0x03, 0xC5, 0xD0}

# Log pages added for the M51xx family, from aM51XXLogs.
_M51XX_LOGS = {0xFB, 0xD0, 0x03, 0xF8}

# Family-specific additions, keyed by the model that selects them. The M51CX
# table also lists 0xE2, but the cloud families skip that page, and 0xE9 is
# collected only for M51CX and M51BY.
_FAMILY_LOGS = {
    'M51AX': {0xCA, 0xFA, 0xF6, 0xFE, 0xFF, 0x04, 0x05, 0x06},
    'M51BX': {0xFA, 0xFE, 0xFF, 0xCA},
    'M51CX': {0xE3, 0xE4, 0xE8, 0xE9, 0xEA},
}

# Pages the collection loop never reads, whatever the model.
_NEVER_READ = {0xE1, 0xE5}

_SERIAL = "MOCKSN0001"


class InternalLogTestBase(TestMicronMock):
    """Shared setup for both modes."""

    def setUp(self):
        super().setUp()
        self.select_model('M51CX')
        self.server.identify = pack_id_ctrl(serial=_SERIAL,
                                            lpa=LPA_TELEMETRY)

    def package_path(self, name):
        return os.path.join(self.out_dir, name)

    def run_log(self, args):
        return self.run_plugin_cmd(_COMMAND, args=args)

    def require_tool(self, name):
        if not shutil.which(name):
            self.skipTest(f"{name} is not installed on this host")


class TestMicronInternalLogArguments(InternalLogTestBase):
    """Argument validation, all of which precedes the model gate."""

    def test_package_is_required(self):
        """Both modes name the file they need, with a mode-specific example."""
        cases = (
            ("package mode", "", "logfile.zip"),
            ("telemetry mode", "--type=host --data_area=1", "logfile.bin"),
        )
        for label, args, hint in cases:
            with self.subTest(mode=label):
                result = self.run_log(args)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Log data file must be specified", result.stderr)
                self.assertIn(hint, result.stderr)

    def test_unsafe_package_paths_are_rejected(self):
        """A path an archive tool could misread is refused before any I/O."""
        for path in ("-output.zip", "file*name.zip", "file?name.zip",
                     'file"name.zip', "file|name.zip", "file<name.zip",
                     "file>name.zip"):
            with self.subTest(package=path):
                result = self.run_log(f"--package={path}")

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Invalid package path", result.stderr)

    def test_trailing_backslash_is_rejected(self):
        """A trailing backslash would escape a closing quote on Windows."""
        result = self.run_log("--package=dir\\")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid package path", result.stderr)

    def test_unrecognised_telemetry_type_is_rejected(self):
        result = self.run_log("--type=invalid --data_area=1 "
                              f"--package={self.package_path('t.bin')}")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("host or controller", result.stderr)

    def test_data_area_is_required_in_telemetry_mode(self):
        result = self.run_log(
            f"--type=host --package={self.package_path('t.bin')}")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("data area", result.stderr.lower())

    def test_data_area_out_of_range_is_rejected(self):
        """The valid range is 1 to 4, so both bounds are refused."""
        for value in (0, 5, 99):
            with self.subTest(data_area=value):
                result = self.run_log(
                    f"--type=host --data_area={value} "
                    f"--package={self.package_path('t.bin')}")

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("data area", result.stderr.lower())

    def test_data_area_without_type_is_rejected(self):
        """--data_area only means something in telemetry mode."""
        result = self.run_log(
            f"--data_area=1 --package={self.package_path('p.zip')}")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("data area option is valid only for telemetry",
                      result.stderr)

    def test_validation_precedes_the_model_gate(self):
        """A bad argument is reported even on a drive the gate would refuse."""
        self.select_model(None)
        result = self.run_log("")

        self.assertIn("Log data file must be specified", result.stderr)
        self.assertNotIn(_UNSUPPORTED_MODEL_MSG, result.stderr)

    def test_validation_touches_no_log(self):
        """Nothing is read from the drive before the arguments are accepted."""
        self.server.commands.clear()
        self.run_log("--package=-bad.zip")

        self.assertEqual(self.server.log_reads(), [])

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_COMMAND,
                                   args="--package=/tmp/does-not-matter.zip")


class TestMicronInternalLogTelemetry(InternalLogTestBase):
    """Telemetry mode: one data area extracted to a binary file."""

    def extract(self, log_type, data_area,
                name=None, last_blocks=(2, 4, 6, 8)):
        """Extract a telemetry log and return the written file's path."""
        lid = (LID_TELEMETRY_CTRL if log_type == 'controller'
               else LID_TELEMETRY_HOST)
        self.server.logs[lid] = pack_telemetry_log(
            last_blocks=last_blocks, lid=lid)
        path = self.package_path(name or f"{log_type}_da{data_area}.bin")
        result = self.run_log(f"--type={log_type} --data_area={data_area} "
                              f"--package={path}")
        self.assertEqual(result.returncode, 0,
                         f"extraction failed: {result.stderr!r}")
        return path

    def test_log_page_per_telemetry_type(self):
        """host reads the host-initiated log, controller the other one."""
        for log_type, lid in (('host', LID_TELEMETRY_HOST),
                              ('controller', LID_TELEMETRY_CTRL)):
            with self.subTest(type=log_type):
                self.server.commands.clear()
                self.extract(log_type, 1)

                self.assertIn(lid, self.server.lids_read())

    def test_file_size_matches_the_header(self):
        """The file is (data area last block + 1) blocks, as claimed."""
        last_blocks = (2, 4, 6, 8)
        for data_area in (1, 2, 3, 4):
            with self.subTest(data_area=data_area):
                path = self.extract('controller', data_area,
                                    last_blocks=last_blocks)
                expected = (last_blocks[data_area - 1] + 1) * _TELEMETRY_BLOCK

                self.assertEqual(os.path.getsize(path), expected)

    def test_file_starts_with_the_log_header(self):
        """The header block is kept, so the file is a complete log."""
        path = self.extract('controller', 1)
        with open(path, 'rb') as f:
            header = f.read(_TELEMETRY_BLOCK)

        self.assertEqual(header[0], LID_TELEMETRY_CTRL,
                         "the controller log identifier block was not written")
        self.assertEqual(struct.unpack_from('<H', header, 8)[0], 2)

    def test_file_size_is_a_multiple_of_the_block_size(self):
        path = self.extract('controller', 2)

        self.assertEqual(os.path.getsize(path) % _TELEMETRY_BLOCK, 0)

    def test_empty_data_area_is_reported(self):
        """A data area the drive has nothing in is refused, not written."""
        self.server.logs[LID_TELEMETRY_CTRL] = pack_telemetry_log(
            last_blocks=(2, 0, 0, 0), lid=LID_TELEMETRY_CTRL)
        path = self.package_path("empty.bin")
        result = self.run_log(f"--type=controller --data_area=2 "
                              f"--package={path}")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("data area 2 is empty", result.stderr)
        self.assertFalse(os.path.exists(path),
                         "a file was written for an empty data area")

    def test_telemetry_support_gate(self):
        """A drive whose LPA lacks telemetry support is refused."""
        self.server.identify = pack_id_ctrl(serial=_SERIAL, lpa=0)
        result = self.run_log(
            f"--type=host --data_area=1 "
            f"--package={self.package_path('t.bin')}")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(_TELEMETRY_UNSUPPORTED_MSG, result.stderr)

    def test_other_lpa_bits_do_not_grant_telemetry_support(self):
        self.server.identify = pack_id_ctrl(serial=_SERIAL,
                                            lpa=0xFF & ~LPA_TELEMETRY)
        result = self.run_log(
            f"--type=host --data_area=1 "
            f"--package={self.package_path('t.bin')}")

        self.assertIn(_TELEMETRY_UNSUPPORTED_MSG, result.stderr)

    def test_telemetry_mode_builds_no_staging_directory(self):
        """Extracting one log must not create the package staging tree."""
        self.extract('controller', 1)

        self.assertNotIn(_SERIAL, os.listdir(self.out_dir))


class TestMicronInternalLogPackage(InternalLogTestBase):
    """Package mode: the archived debug collection."""

    def collect(self, name="package.zip", model=None):
        """Collect a debug package and return the archive path."""
        if model is not None:
            self.select_model(model)
        path = self.package_path(name)
        result = self.run_log(f"--package={path}")
        self.assertEqual(result.returncode, 0,
                         f"collection failed: {result.stderr!r}")
        return path

    def entries(self, path):
        """Return {package-relative name: archive member name}.

        The serial-number root folder is stripped so callers address entries
        by their path within the package.
        """
        if path.endswith(".zip"):
            with zipfile.ZipFile(path) as zf:
                names = [n for n in zf.namelist() if not n.endswith("/")]
        else:
            with tarfile.open(path) as tf:
                names = [m.name for m in tf.getmembers() if m.isfile()]
        entries = {}
        for name in names:
            parts = name.replace("\\", "/").split("/")
            entries["/".join(parts[1:])] = name
        return entries

    def read_entry(self, path, name):
        entries = self.entries(path)
        self.assertIn(name, entries,
                      f"{name} missing from the package: {sorted(entries)}")
        if path.endswith(".zip"):
            with zipfile.ZipFile(path) as zf:
                return zf.read(entries[name])
        with tarfile.open(path) as tf:
            return tf.extractfile(entries[name]).read()

    # ---------------------------------------------------------------- #
    # Archiving                                                        #
    # ---------------------------------------------------------------- #

    def test_zip_archive_is_created(self):
        self.require_tool('zip')
        path = self.collect("package.zip")

        self.assertTrue(zipfile.is_zipfile(path))
        self.assertGreater(os.path.getsize(path), 0)

    def test_tar_archives_are_created(self):
        """Both gzip extensions route to tar rather than zip."""
        self.require_tool('tar')
        for name in ("package.tgz", "package.tar.gz"):
            with self.subTest(package=name):
                path = self.collect(name)

                self.assertTrue(tarfile.is_tarfile(path))

    def test_staging_directory_is_removed(self):
        """The serial-named staging tree does not survive the collection."""
        self.require_tool('zip')
        self.collect()

        self.assertNotIn(_SERIAL, os.listdir(self.out_dir))

    def test_archive_holds_the_collected_files(self):
        self.require_tool('zip')
        entries = self.entries(self.collect())

        self.assertTrue(entries, "the archive holds no files")
        self.assertIn(_METADATA_FILE, entries)
        self.assertIn(_CMD_STATUS_FILE, entries)

    def test_archive_tool_failure_is_reported(self):
        """A drive is collected but the archive cannot be built."""
        self.fake_tool('zip')
        self.fake_tool('tar')
        path = self.package_path("failed.zip")
        result = self.run_log(f"--package={path}")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Failed to create log data package", result.stderr)

    def test_staging_directory_is_removed_after_a_tool_failure(self):
        """A failed archive must not leave the staging tree behind."""
        self.fake_tool('zip')
        self.fake_tool('tar')
        self.run_log(f"--package={self.package_path('failed.zip')}")

        self.assertNotIn(_SERIAL, os.listdir(self.out_dir))

    # ---------------------------------------------------------------- #
    # Descriptor files                                                 #
    # ---------------------------------------------------------------- #

    def test_metadata_holds_the_keys_the_parser_reads(self):
        self.require_tool('zip')
        path = self.collect()
        metadata = json.loads(self.read_entry(path, _METADATA_FILE))

        missing = [k for k in _METADATA_REQUIRED_KEYS if k not in metadata]
        self.assertFalse(missing, f"metadata is missing keys: {missing}")
        self.assertEqual(metadata["tool_pull_name"], "nvme-cli")

    def test_metadata_pci_ids_are_the_drive_ids(self):
        """The decoder family is selected from these, so they must be right."""
        self.require_tool('zip')
        path = self.collect(model='M51CX')
        metadata = json.loads(self.read_entry(path, _METADATA_FILE))

        self.assertEqual(int(metadata["vendor_id"], 16), MICRON_VENDOR_ID)
        self.assertEqual(int(metadata["device_id"], 16), self.device_id)

    def test_metadata_pci_ids_follow_the_drive(self):
        """A different drive reports different IDs, not a cached pair."""
        self.require_tool('zip')
        first = json.loads(self.read_entry(
            self.collect("one.zip", model='M51AX'), _METADATA_FILE))
        second = json.loads(self.read_entry(
            self.collect("two.zip", model='M6001'), _METADATA_FILE))

        self.assertEqual(int(first["device_id"], 16),
                         MICRON_MODELS['M51AX'][0])
        self.assertEqual(int(second["device_id"], 16),
                         MICRON_MODELS['M6001'][0])

    def test_metadata_identity_strings_are_trimmed(self):
        """Identify strings are padded; the metadata holds them trimmed."""
        self.require_tool('zip')
        self.server.identify = pack_id_ctrl(serial=_SERIAL, model="MockModel",
                                            fw="MFW1", lpa=LPA_TELEMETRY)
        metadata = json.loads(self.read_entry(self.collect(), _METADATA_FILE))

        self.assertEqual(metadata["serial_number"], _SERIAL)
        self.assertEqual(metadata["model_number_identify"], "MockModel")
        self.assertEqual(metadata["firmware_revision"], "MFW1")

    def test_drive_info_reports_the_pci_ids(self):
        """drive-info.txt is what the metadata IDs are checked against."""
        self.require_tool('zip')
        path = self.collect(model='M51CX')
        drive_info = self.read_entry(path, _DRIVE_INFO_FILE).decode()

        self.assertIn(f"{MICRON_VENDOR_ID:04X}", drive_info.upper())
        self.assertIn(f"{self.device_id:04X}", drive_info.upper())

    def test_cmd_status_csv_header(self):
        """The parser locates its columns by name, so the header must match."""
        self.require_tool('zip')
        text = self.read_entry(self.collect(), _CMD_STATUS_FILE).decode()
        rows = [r for r in csv.reader(io.StringIO(text)) if r]

        self.assertEqual(rows[0], _CMD_STATUS_COLUMNS)
        self.assertTrue(rows[1:], "the CSV has no data rows")

    def test_cmd_status_rows_name_collected_files(self):
        """A successful row must point at a file that is in the package."""
        self.require_tool('zip')
        path = self.collect()
        entries = self.entries(path)
        text = self.read_entry(path, _CMD_STATUS_FILE).decode()
        rows = [r for r in csv.reader(io.StringIO(text)) if r]
        header, data = rows[0], rows[1:]
        binary_idx = header.index("binary_file")
        status_idx = header.index("mse_status")

        successes = 0
        for row in data:
            if row[status_idx] != "Success":
                continue
            successes += 1
            name = row[binary_idx]
            if "%d" in name:
                prefix, suffix = name.split("%d", 1)
                self.assertTrue(
                    [n for n in entries
                     if n.startswith(f"Controller/{prefix}")
                     and n.endswith(suffix)],
                    f"no file matches the pattern {name}")
                continue
            self.assertIn(f"Controller/{name}", entries)

        self.assertGreater(successes, 0,
                           "no successful rows, so nothing would be decoded")

    def test_text_descriptors_use_lf_endings(self):
        """The descriptors must be byte-identical across platforms."""
        self.require_tool('zip')
        path = self.collect()
        for name in (_METADATA_FILE, _CMD_STATUS_FILE, _DRIVE_INFO_FILE):
            with self.subTest(file=name):
                self.assertEqual(self.read_entry(path, name).count(b"\r\n"), 0,
                                 f"{name} contains CRLF line endings")

    # ---------------------------------------------------------------- #
    # Per-model collection                                             #
    # ---------------------------------------------------------------- #

    def test_legacy_models_collect_only_the_base_logs(self):
        """M5410 and M5407 skip the M51xx additions entirely."""
        self.require_tool('zip')
        for model in ('M5410', 'M5407'):
            with self.subTest(model=model):
                self.server.commands.clear()
                self.collect(f"{model}.zip", model=model)
                read = self.server.lids_read()

                self.assertTrue(_BASE_LOGS <= read,
                                f"base logs missing: {_BASE_LOGS - read}")
                self.assertFalse(
                    _FAMILY_LOGS['M51CX'] & read,
                    "a legacy model was asked for the M51CX vendor logs")

    def test_family_specific_logs_are_collected(self):
        """Each M51xx family adds its own log pages."""
        self.require_tool('zip')
        for model, expected in _FAMILY_LOGS.items():
            with self.subTest(model=model):
                self.server.commands.clear()
                self.collect(f"{model}.zip", model=model)
                read = self.server.lids_read()

                self.assertTrue(expected <= read,
                                f"{model} did not collect {expected - read}")

    def test_families_do_not_collect_each_others_logs(self):
        """The family tables are alternatives, not a union."""
        self.require_tool('zip')
        self.server.commands.clear()
        self.collect("ax.zip", model='M51AX')
        ax_read = self.server.lids_read()

        self.assertFalse(
            _FAMILY_LOGS['M51CX'] & ax_read,
            f"M51AX collected M51CX logs: "
            f"{sorted(_FAMILY_LOGS['M51CX'] & ax_read)}")

    def test_some_pages_are_never_read(self):
        """Two entries in the M51CX table are skipped unconditionally."""
        self.require_tool('zip')
        for model in ('M51CX', 'M51BY', 'M51CY', 'M51AX'):
            with self.subTest(model=model):
                self.server.commands.clear()
                self.collect(f"never_{model}.zip", model=model)
                read = self.server.lids_read()

                self.assertFalse(
                    _NEVER_READ & read,
                    f"{model} read {sorted(_NEVER_READ & read)}")

    def test_the_e2_log_is_not_collected(self):
        """No model collects 0xE2.

        It appears only in the M51CX table, and the collection loop skips it
        for exactly the families that table is copied in for, so the entry is
        unreachable. Asserted here so a change to either side is noticed.
        """
        self.require_tool('zip')
        for model in ('M51CX', 'M51BY', 'M51CY', 'M51AX', 'M51BX'):
            with self.subTest(model=model):
                self.server.commands.clear()
                self.collect(f"e2_{model}.zip", model=model)

                self.assertNotIn(0xE2, self.server.lids_read())

    def test_workload_log_is_cloud_family_only(self):
        """0xE9 is collected for M51CX and M51BY, and no other model."""
        self.require_tool('zip')
        for model, expected in (('M51CX', True), ('M51BY', True),
                                ('M51CY', False), ('M51AX', False)):
            with self.subTest(model=model):
                self.server.commands.clear()
                self.collect(f"e9_{model}.zip", model=model)

                self.assertEqual(0xE9 in self.server.lids_read(), expected)

    def test_telemetry_is_collected_when_supported(self):
        """A drive advertising telemetry has both logs collected."""
        self.require_tool('zip')
        self.server.logs[LID_TELEMETRY_HOST] = pack_telemetry_log(
            lid=LID_TELEMETRY_HOST)
        self.server.logs[LID_TELEMETRY_CTRL] = pack_telemetry_log(
            lid=LID_TELEMETRY_CTRL)
        self.server.commands.clear()
        self.collect()
        read = self.server.lids_read()

        self.assertIn(LID_TELEMETRY_HOST, read)
        self.assertIn(LID_TELEMETRY_CTRL, read)

    def test_telemetry_is_skipped_when_unsupported(self):
        """A drive without telemetry support is not asked for those logs."""
        self.require_tool('zip')
        self.server.identify = pack_id_ctrl(serial=_SERIAL, lpa=0)
        self.server.commands.clear()
        self.collect()
        read = self.server.lids_read()

        self.assertNotIn(LID_TELEMETRY_HOST, read)
        self.assertNotIn(LID_TELEMETRY_CTRL, read)

    # ---------------------------------------------------------------- #
    # Serial handling                                                  #
    # ---------------------------------------------------------------- #

    def test_serial_is_sanitised_before_it_names_a_directory(self):
        """The drive supplies the serial, so it must not steer the path."""
        self.require_tool('zip')
        self.server.identify = pack_id_ctrl(serial="../bad'sn",
                                            lpa=LPA_TELEMETRY)
        before = set(os.listdir(self.out_dir))
        path = self.collect("sanitised.zip")
        entries = self.entries(path)

        self.assertTrue(entries)
        with zipfile.ZipFile(path) as zf:
            roots = {name.split("/")[0] for name in zf.namelist()}
        self.assertEqual(roots, {"___bad_sn"},
                         f"unexpected package root: {roots}")
        self.assertEqual(set(os.listdir(self.out_dir)) - before,
                         {"sanitised.zip"},
                         "the serial escaped the working directory")


if __name__ == '__main__':
    main()
