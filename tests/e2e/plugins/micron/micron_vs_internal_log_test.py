# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron vs-internal-log command.

The vs-internal-log command has two operating modes:

  Debug package mode (default):
    Collects model-specific NVMe log pages and OS diagnostics into a
    compressed archive (.zip, .tgz, or .tar.gz).  A temporary working
    directory named after the drive serial number is created in the
    current working directory and then removed once the archive is built.

  Telemetry mode (--type=host|controller):
    Extracts a single binary telemetry log file.  Requires both --type
    and --data_area (1-4).

Tests in this module verify:
  * Archive generation for each supported format (.zip, .tgz, .tar.gz).
  * Temporary directory cleanup after successful collection.
  * Error detection in stdout/stderr for every known failure path.
  * Argument validation: missing package, unsafe paths, telemetry
    mis-use, and out-of-range data_area.
  * The debug-data package metadata contract required by the offline parser:
  * logpull_metadata_info.json and Controller/logpull_cmd_status_info.csv.
"""

import csv
import io
import json
import os
import re
import struct
import unittest
import zipfile
from pathlib import Path

from .micron_test import TestMicron

# Telemetry log block size (bytes).  The plugin computes the size of a data
# area as (data_area_last_block + 1) * _TELEMETRY_BLOCK_SIZE.
_TELEMETRY_BLOCK_SIZE = 512

# Byte offset of each data area's "last block" field within the telemetry log
# header (struct nvme_telemetry_log), together with its struct-module format:
#   dalb1 @ 8  (__le16), dalb2 @ 10 (__le16), dalb3 @ 12 (__le16),
#   dalb4 @ 16 (__le32).
_DALB_HEADER = {
    1: (8, "<H"),
    2: (10, "<H"),
    3: (12, "<H"),
    4: (16, "<I"),
}

_UNSUPPORTED_MODEL_MSG = "Unsupported drive model for vs-internal-log collection"
_TELEMETRY_UNSUPPORTED_MSG = "telemetry option is not supported for specified drive"

# Descriptor files the offline parser requires, relative to the package root.
_METADATA_FILE = "logpull_metadata_info.json"
_CMD_STATUS_FILE = "Controller/logpull_cmd_status_info.csv"

# Column order of the cmd status CSV.  The parser reads cmd_info and
# mse_status by name, but the full header is written for compatibility.
_CMD_STATUS_COLUMNS = [
    "serial_number",
    "cmd_info",
    "op_code",
    "log_id",
    "cmd_class",
    "cmd_code",
    "binary_file",
    "execution_time_us",
    "mse_status",
]

# Metadata keys the parser reads.  device_id and vendor_id select the decoder
# family; a wrong value degrades to an UNKNOWN family rather than failing, so
# it produces a wrong decode instead of an error.
_METADATA_REQUIRED_KEYS = [
    "tool_pull_name",
    "device_id",
    "vendor_id",
    "serial_number",
    "firmware_revision",
    "model_number_identify",
]

# Status text the parser compares literally when selecting logs to decode.
_MSE_STATUS_SUCCESS = "Success"

# Size of struct micron_common_log_header, and the offset of its log_size
# field.  log_size counts the header itself.
_COMMON_LOG_HEADER_SIZE = 32
_COMMON_LOG_SIZE_OFFSET = 4

# Vendor log files that carry a common log header.  Other nvmelog_*.bin files
# use unrelated formats and are not covered by the framing check.
_COMMON_LOG_FILES = {
    "nvmelog_E2.bin",
    "nvmelog_E3.bin",
    "nvmelog_E4.bin",
    "nvmelog_E8.bin",
    "nvmelog_EA.bin",
}


class TestMicronVsInternalLog(TestMicron):
    """Test suite for the micron vs-internal-log plugin command."""

    # Collecting a debug-data package takes time on a populated drive, so
    # the metadata tests share a single one.  These are class attributes
    # because unittest builds a fresh instance per test method. They hold the
    # archive path, the parsed entry map, and any skip reason from the first
    # attempt.  Cleaned up in tearDownClass.
    _shared_zip_path = None
    _shared_zip_entries = None
    _shared_zip_skip = None

    # ------------------------------------------------------------------
    # Setup / teardown
    # ------------------------------------------------------------------

    def setUp(self):
        super().setUp()
        # Paths of archive files created by tests; removed in tearDown.
        self._archive_files = []

    def tearDown(self):
        for path in self._archive_files:
            path.unlink(missing_ok=True)
        super().tearDown()

    @classmethod
    def tearDownClass(cls):
        # The shared package is deliberately not registered with
        # _archive_path(), whose cleanup is per-test, so remove it here.
        if cls._shared_zip_path and os.path.exists(cls._shared_zip_path):
            os.remove(cls._shared_zip_path)
        cls._shared_zip_path = None
        cls._shared_zip_entries = None
        cls._shared_zip_skip = None
        super().tearDownClass()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _archive_path(self, filename):
        """Return a path inside the test log directory.

        The path is registered for automatic deletion in tearDown so that
        large archive files do not accumulate between test runs.
        """
        path = self.test_log_dir / filename
        self._archive_files.append(path)
        return path

    def _subdirs(self, path):
        """Return the set of subdirectory names in path."""
        return {p.name for p in path.iterdir() if p.is_dir()}

    def _run_log(self, args=""):
        """Run micron vs-internal-log against the default controller.

        Skips the calling test if the plugin itself reports the drive model
        (or, in telemetry mode, this specific drive) doesn't support
        vs-internal-log collection, rather than failing -- argument
        validation (missing/unsafe --package, telemetry argument misuse)
        always happens before this check, so those negative-path tests are
        unaffected.
        """
        result = self.run_plugin_cmd("vs-internal-log", args=args)
        if result.returncode != 0 and (
            _UNSUPPORTED_MODEL_MSG in result.stderr
            or _TELEMETRY_UNSUPPORTED_MSG in result.stderr
        ):
            self.skipTest(
                f"vs-internal-log not supported on this drive "
                f"(stderr: {result.stderr!r})"
            )
        return result

    def _collect_zip(self):
        """Return a shared .zip debug-data package as (ZipFile, entries).

        The collection command is run only on the first call; later calls
        reuse the resulting archive, since a full pull takes time and none
        of these tests mutate the package.  The ZipFile handle is opened fresh
        per test and closed by that test's cleanup, so only the expensive
        collection is shared, not an open file object.

        Entry names are normalised to use '/' and have the leading
        serial-number folder stripped, so callers can address entries by
        their package-relative path (e.g. "Controller/smart_data.bin").
        """
        cls = type(self)

        # A drive that doesn't support collection skips every test that needs
        # the package, without re-running the command to rediscover that.
        if cls._shared_zip_skip:
            self.skipTest(cls._shared_zip_skip)

        if not cls._shared_zip_path:
            output_path = os.path.join(
                self.test_log_dir, "internal_log_metadata.zip"
            )
            try:
                result = self._run_log(args=f"--package={output_path}")
            except unittest.SkipTest as exc:
                cls._shared_zip_skip = str(exc)
                raise

            self.assertEqual(
                result.returncode, 0,
                f"vs-internal-log failed: rc={result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}",
            )

            with zipfile.ZipFile(output_path) as zf:
                entries = {}
                for name in zf.namelist():
                    if name.endswith("/"):
                        continue
                    parts = name.replace("\\", "/").split("/")
                    # Drop the serial-number root folder.
                    entries["/".join(parts[1:])] = name

            self.assertTrue(entries, f"Package contains no files: {output_path}")
            cls._shared_zip_path = output_path
            cls._shared_zip_entries = entries

        zf = zipfile.ZipFile(cls._shared_zip_path)
        self.addCleanup(zf.close)
        return zf, cls._shared_zip_entries

    def _read_metadata(self, zf, entries):
        """Return the parsed logpull_metadata_info.json from a package."""
        self.assertIn(
            _METADATA_FILE, entries,
            f"{_METADATA_FILE} is missing from the package root; the parser "
            f"fails outright without it. Present: {sorted(entries)}",
        )
        raw = zf.read(entries[_METADATA_FILE]).decode("utf-8")
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            self.fail(f"{_METADATA_FILE} is not valid JSON: {exc}\n{raw}")

    def _read_cmd_status_rows(self, zf, entries):
        """Return (header, rows) from the cmd status CSV in a package."""
        self.assertIn(
            _CMD_STATUS_FILE, entries,
            f"{_CMD_STATUS_FILE} is missing; without it the parser decodes "
            f"nothing while still reporting success. Present: {sorted(entries)}",
        )
        text = zf.read(entries[_CMD_STATUS_FILE]).decode("utf-8")
        reader = csv.reader(io.StringIO(text))
        all_rows = [r for r in reader if r]
        self.assertTrue(all_rows, f"{_CMD_STATUS_FILE} is empty")
        return all_rows[0], all_rows[1:]

    def _test_archive_format(self, extension):
        """Shared body for the archive-format tests.

        Verifies:
          - Command exits with code 0.
          - The archive file is created and is non-empty.
          - No "Failed to create log data package" message appears in stderr.
          - No temporary working directories remain in the current directory
            after the command returns.
        """
        output_path = self._archive_path(f"internal_log{extension}")
        cwd = Path.cwd()
        dirs_before = self._subdirs(cwd)

        result = self._run_log(args=f"--package={output_path}")

        self.assertEqual(
            result.returncode, 0,
            f"vs-internal-log '{extension}' failed: "
            f"rc={result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}",
        )

        # Archive must exist and contain data.
        self.assertTrue(
            output_path.is_file(),
            f"Archive was not created: {output_path}",
        )
        self.assertGreater(
            output_path.stat().st_size, 0,
            f"Archive is empty: {output_path}",
        )

        # No packaging failure message should appear in stderr.
        self.assertNotIn(
            "Failed to create log data package", result.stderr,
            f"Archive creation error for '{extension}': {result.stderr}",
        )

        # All temporary working directories must have been removed.
        dirs_after = self._subdirs(cwd)
        leaked = dirs_after - dirs_before
        self.assertFalse(
            leaked,
            f"Temporary directories were not cleaned up after '{extension}' "
            f"collection: {leaked}",
        )

    # ------------------------------------------------------------------
    # Archive format tests
    # ------------------------------------------------------------------

    def test_zip_package(self):
        """vs-internal-log creates a .zip archive and removes temporary directories."""
        self._test_archive_format(".zip")

    def test_tgz_package(self):
        """vs-internal-log creates a .tgz archive and removes temporary directories."""
        self._test_archive_format(".tgz")

    def test_tar_gz_package(self):
        """vs-internal-log creates a .tar.gz archive and removes temporary directories."""
        self._test_archive_format(".tar.gz")

    # ------------------------------------------------------------------
    # Missing / invalid --package argument
    # ------------------------------------------------------------------

    def test_no_package_argument(self):
        """vs-internal-log fails with a descriptive message when --package is omitted.

        Covers both the debug-package and telemetry code paths: each branch
        emits a mode-specific example path in the error message.
        """
        cases = [
            ("debug-package mode", "",                        "logfile.zip"),
            ("telemetry mode",     "--type=host --data_area=1", "logfile.bin"),
        ]
        for label, args, hint in cases:
            with self.subTest(mode=label):
                result = self._run_log(args=args)

                self.assertNotEqual(
                    result.returncode, 0,
                    f"Expected non-zero exit when --package is omitted ({label})",
                )
                self.assertIn(
                    "Log data file must be specified", result.stderr,
                    f"Expected usage hint about missing package in stderr ({label}), "
                    f"got: {result.stderr!r}",
                )
                self.assertIn(
                    hint, result.stderr,
                    f"Expected mode-specific hint '{hint}' in stderr ({label}), "
                    f"got: {result.stderr!r}",
                )

    def test_unsafe_package_path_leading_dash(self):
        """vs-internal-log rejects a --package path that starts with '-'.

        A path starting with '-' could be mis-interpreted as a flag by the
        tar or zip tool that archives the output.  is_safe_path() rejects
        it before any I/O is attempted.
        """
        result = self._run_log(args="--package=-output.zip")

        self.assertNotEqual(
            result.returncode, 0,
            "Expected non-zero exit for --package path starting with '-'",
        )
        self.assertIn(
            "Invalid package path", result.stderr,
            f"Expected unsafe-path message in stderr, got: {result.stderr!r}",
        )

    def test_unsafe_package_path_special_chars(self):
        """vs-internal-log rejects a --package path containing unsafe characters.

        The glob character '*' is in the rejected-character table of
        is_safe_path().  It is safe to embed in a double-quoted shell argument
        in both POSIX shells (bash suppresses glob expansion inside double
        quotes) and cmd.exe (where '*' is not a shell metachar in argument
        strings).
        """
        result = self._run_log(args='--package="file*name.zip"')

        self.assertNotEqual(
            result.returncode, 0,
            "Expected non-zero exit for --package path containing '*'",
        )
        self.assertIn(
            "Invalid package path", result.stderr,
            f"Expected unsafe-path message in stderr, got: {result.stderr!r}",
        )

    # ------------------------------------------------------------------
    # Telemetry mode argument validation
    # ------------------------------------------------------------------

    def test_telemetry_invalid_type(self):
        """vs-internal-log rejects an unrecognised value for --type.

        Only "host" and "controller" are valid telemetry types.
        """
        output_path = self._archive_path("telemetry_invalid.bin")
        result = self._run_log(
            args=f"--type=invalid --data_area=1 --package={output_path}"
        )

        self.assertNotEqual(
            result.returncode, 0,
            "Expected non-zero exit for unrecognised --type value",
        )
        self.assertIn(
            "host or controller", result.stderr,
            f"Expected message naming valid telemetry types, "
            f"got stderr={result.stderr!r}",
        )

    def test_telemetry_missing_data_area(self):
        """vs-internal-log requires --data_area."""
        output_path = self._archive_path("telemetry_host.bin")
        result = self._run_log(args=f"--type=host --package={output_path}")

        self.assertNotEqual(
            result.returncode, 0,
            "Expected non-zero exit when --data_area is omitted",
        )
        self.assertIn(
            "data area", result.stderr.lower(),
            f"Expected message about missing data area, got stderr={result.stderr!r}",
        )

    def test_telemetry_data_area_out_of_range(self):
        """vs-internal-log rejects --data_area values outside the 1-4 range.

        The implementation checks cfg.data_area <= 0 || cfg.data_area > 4.
        Both bounds are exercised: 0 (lower) and 5 (upper).
        """
        output_path = self._archive_path("telemetry_oor.bin")
        for value in (0, 5):
            with self.subTest(data_area=value):
                result = self._run_log(
                    args=f"--type=host --data_area={value} --package={output_path}"
                )

                self.assertNotEqual(
                    result.returncode, 0,
                    f"Expected non-zero exit for --data_area={value} (valid range is 1-4)",
                )
                self.assertIn(
                    "data area", result.stderr.lower(),
                    f"Expected message about data area range, got stderr={result.stderr!r}",
                )

    # ------------------------------------------------------------------
    # Telemetry mode happy paths
    # ------------------------------------------------------------------

    def test_telemetry_success(self):
        """vs-internal-log extracts a telemetry log to a binary file."""
        output_path = self._archive_path("telemetry_ctrl_da1.bin")
        result = self._run_log(
            args=f"--type=controller --data_area=1 --package={output_path}"
        )

        self.assertEqual(
            result.returncode, 0,
            f"vs-internal-log --type=controller --data_area=1 failed: "
            f"rc={result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}",
        )
        self.assertTrue(
            output_path.is_file(),
            f"Telemetry log file was not created: {output_path}",
        )
        size = output_path.stat().st_size
        self.assertGreater(size, 0, "Telemetry log file is empty")
        self.assertEqual(
            size % 512, 0,
            f"Telemetry log file size {size} is not a multiple of 512 bytes",
        )

    def test_telemetry_size_matches_header(self):
        """Extracted telemetry file size matches the size claimed by its header.

        The plugin sizes each data area as (dalbN + 1) * 512, where dalbN is
        the "last block" field for the requested data area in the telemetry
        log header (struct nvme_telemetry_log).  This reads that field back
        out of the written .bin file and asserts the file is exactly that big,
        catching truncated or over-sized extractions that the coarser
        "non-empty, multiple of 512" check in test_telemetry_success misses.
        """
        # Test the largest supported data area.
        # Data area 4 is only populated when the controller reports extended
        # telemetry support (id-ctrl LPA bit 6, 0x40).
        lpa = int(self.get_id_ctrl_field_value("lpa"))
        data_area = 4 if (lpa & 0x40) else 3
        print(f"Testing telemetry data area {data_area} (LPA=0x{lpa:02x})")
        output_path = self._archive_path("telemetry_ctrl_size.bin")
        result = self._run_log(
            args=f"--type=controller --data_area={data_area} --package={output_path}"
        )

        self.assertEqual(
            result.returncode, 0,
            f"vs-internal-log --type=controller --data_area={data_area} failed: "
            f"rc={result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}",
        )
        self.assertTrue(
            output_path.is_file(),
            f"Telemetry log file was not created: {output_path}",
        )

        actual_size = output_path.stat().st_size
        self.assertGreaterEqual(
            actual_size, _TELEMETRY_BLOCK_SIZE,
            f"Telemetry log file is smaller than one block: {actual_size} bytes",
        )

        # Read the data-area block count straight out of the file's header.
        offset, fmt = _DALB_HEADER[data_area]
        with output_path.open("rb") as f:
            header = f.read(_TELEMETRY_BLOCK_SIZE)
        (dalb,) = struct.unpack_from(fmt, header, offset)

        expected_size = (dalb + 1) * _TELEMETRY_BLOCK_SIZE
        self.assertEqual(
            actual_size, expected_size,
            f"Telemetry file size {actual_size} does not match size claimed by "
            f"header: data area {data_area} last block = {dalb}, expected "
            f"(dalb + 1) * {_TELEMETRY_BLOCK_SIZE} = {expected_size} bytes",
        )

    def test_data_area_without_type(self):
        """vs-internal-log rejects --data_area when --type is not specified.

        --data_area is only meaningful in telemetry mode; the implementation
        prints an explicit error when it appears without --type.
        """
        output_path = self._archive_path("data_area_notype.zip")
        result = self._run_log(
            args=f"--data_area=1 --package={output_path}"
        )

        self.assertNotEqual(
            result.returncode, 0,
            "Expected non-zero exit for --data_area without --type",
        )
        self.assertIn(
            "data area option is valid only for telemetry", result.stderr,
            f"Expected telemetry-only message, got stderr={result.stderr!r}",
        )

    def test_text_metadata_files_are_lf_only(self):
        """The generated text files use LF endings on every platform.

        The metadata files must contain LF-only line endings, not CRLF.
        csv.reader normalizes line endings, so perform a byte-level check.
        """
        zf, entries = self._collect_zip()

        for name in (_CMD_STATUS_FILE, _METADATA_FILE, "drive-info.txt"):
            self.assertIn(name, entries, f"{name} is missing from the package")
            raw = zf.read(entries[name])
            self.assertEqual(
                raw.count(b"\r\n"), 0,
                f"{name} contains CRLF line endings; open it with a \"b\" mode "
                f"fopen so output is byte-identical across platforms",
            )

    def test_metadata_json_present_and_valid(self):
        """The package root holds a logpull_metadata_info.json with all read keys.

        The file must sit at the package root.
        """
        zf, entries = self._collect_zip()
        metadata = self._read_metadata(zf, entries)

        missing = [k for k in _METADATA_REQUIRED_KEYS if k not in metadata]
        self.assertFalse(
            missing,
            f"{_METADATA_FILE} is missing required keys: {missing}",
        )

        self.assertEqual(
            metadata["tool_pull_name"], "nvme-cli",
            "tool_pull_name identifies the collecting tool and selects the "
            "parser's CSV path",
        )

    def test_metadata_pci_ids_match_device(self):
        """Metadata device_id/vendor_id are 0x-prefixed hex matching the drive."""

        zf, entries = self._collect_zip()
        metadata = self._read_metadata(zf, entries)

        for key in ("device_id", "vendor_id"):
            value = metadata[key]
            self.assertRegex(
                value, r"^0x[0-9A-Fa-f]{4}$",
                f"{key}={value!r} must be a 0x-prefixed 4-digit hex string",
            )

        self.assertIn(
            "drive-info.txt", entries,
            "drive-info.txt is needed to cross-check the reported PCI IDs",
        )
        drive_info = zf.read(entries["drive-info.txt"]).decode("utf-8")

        for key, label in (("vendor_id", "VendorId"), ("device_id", "DeviceId")):
            match = re.search(rf"{label}\s*:\s*([0-9A-Fa-f]{{4}})", drive_info)
            self.assertIsNotNone(
                match, f"Could not find {label} in drive-info.txt:\n{drive_info}"
            )
            self.assertEqual(
                int(metadata[key], 16), int(match.group(1), 16),
                f"Metadata {key}={metadata[key]} disagrees with {label} "
                f"0x{match.group(1)} in drive-info.txt",
            )

    def test_metadata_identify_fields_are_trimmed(self):
        """Metadata identity fields match id-ctrl and carry no padding.

        Identify strings are space-padded in the NVMe data structure; the
        metadata must hold the trimmed value so it renders correctly in the
        parser's drive info output.
        """
        zf, entries = self._collect_zip()
        metadata = self._read_metadata(zf, entries)

        expected = {
            "serial_number": self.get_id_ctrl_field_value("sn"),
            "firmware_revision": self.get_id_ctrl_field_value("fr"),
            "model_number_identify": self.get_id_ctrl_field_value("mn"),
        }

        for key, want in expected.items():
            got = metadata[key]
            self.assertEqual(
                got, got.strip(),
                f"{key}={got!r} has leading/trailing whitespace",
            )
            self.assertEqual(
                got, want.strip(),
                f"{key}={got!r} does not match id-ctrl value {want.strip()!r}",
            )

    def test_cmd_status_csv_header(self):
        """The cmd status CSV leads with the 9-column header the parser expects.

        The parser locates cmd_info and mse_status by column name, so the
        header must be present and correctly spelled.
        """
        zf, entries = self._collect_zip()
        header, rows = self._read_cmd_status_rows(zf, entries)

        self.assertEqual(
            header, _CMD_STATUS_COLUMNS,
            "cmd status CSV header does not match the expected column list",
        )
        self.assertTrue(
            rows,
            "cmd status CSV has no data rows; the parser would decode nothing "
            "while still reporting success",
        )

    def test_cmd_status_rows_reference_collected_files(self):
        """Every successful CSV row names a binary that exists in the package.

        A row pointing at an absent file is the main failure mode this
        descriptor can introduce: the parser would try to decode a log that
        was never collected.
        """
        zf, entries = self._collect_zip()
        header, rows = self._read_cmd_status_rows(zf, entries)

        cmd_info_idx = header.index("cmd_info")
        binary_idx = header.index("binary_file")
        status_idx = header.index("mse_status")

        successes = 0
        for row in rows:
            self.assertEqual(
                len(row), len(_CMD_STATUS_COLUMNS),
                f"Malformed CSV row (expected {len(_CMD_STATUS_COLUMNS)} "
                f"columns): {row}",
            )
            if row[status_idx] != _MSE_STATUS_SUCCESS:
                continue
            successes += 1

            binary_file = row[binary_idx]
            if "%d" in binary_file:
                # A pattern entry covers a numbered family of files; at least
                # one instance must be present.
                prefix, suffix = binary_file.split("%d", 1)
                matches = [
                    name for name in entries
                    if name.startswith(f"Controller/{prefix}")
                    and name.endswith(suffix)
                ]
                self.assertTrue(
                    matches,
                    f"cmd_info {row[cmd_info_idx]} names pattern "
                    f"{binary_file}, but no matching file was collected",
                )
                continue

            self.assertIn(
                f"Controller/{binary_file}", entries,
                f"cmd_info {row[cmd_info_idx]} names {binary_file}, which is "
                f"not present under Controller/",
            )

        self.assertGreater(
            successes, 0,
            "No successful rows in the cmd status CSV; nothing would be parsed",
        )

    def test_cmd_status_rows_are_unique(self):
        """No binary is listed twice with a Success status.

        Several log pages are reachable from more than one collection table,
        so duplicate rows are a real possibility; each would cause the same
        binary to be decoded repeatedly.
        """
        zf, entries = self._collect_zip()
        header, rows = self._read_cmd_status_rows(zf, entries)

        binary_idx = header.index("binary_file")
        status_idx = header.index("mse_status")

        seen = set()
        duplicates = set()
        for row in rows:
            if len(row) <= max(binary_idx, status_idx):
                continue
            if row[status_idx] != _MSE_STATUS_SUCCESS:
                continue
            if row[binary_idx] in seen:
                duplicates.add(row[binary_idx])
            seen.add(row[binary_idx])

        self.assertFalse(
            duplicates,
            f"Binaries listed more than once with a Success status: "
            f"{sorted(duplicates)}",
        )

    def test_telemetry_rows_present_for_collected_logs(self):
        """Each collected telemetry binary has a matching CSV row.

        Host and controller telemetry route to different decoders, so the two
        must be distinguished rather than collapsed into one entry.
        """
        zf, entries = self._collect_zip()
        header, rows = self._read_cmd_status_rows(zf, entries)

        binary_idx = header.index("binary_file")
        status_idx = header.index("mse_status")
        successful = {
            row[binary_idx] for row in rows
            if len(row) > max(binary_idx, status_idx)
            and row[status_idx] == _MSE_STATUS_SUCCESS
        }

        telemetry_files = [
            "nvme_host_telemetry_log.bin",
            "nvme_controller_telemetry_log.bin",
        ]
        collected = [
            name for name in telemetry_files
            if f"Controller/{name}" in entries
        ]
        self.assertTrue(
            collected,
            "No telemetry logs were collected; expected at least one of "
            f"{telemetry_files} on a drive reporting telemetry support",
        )

        for name in collected:
            self.assertIn(
                name, successful,
                f"{name} was collected but has no Success row in the cmd "
                f"status CSV, so the parser would skip it",
            )

    def test_common_log_sizes_match_headers(self):
        """Each common-format vendor log is exactly as large as its header claims.

        log_size in struct micron_common_log_header counts the header itself,
        so the file size must equal it exactly.  This guards the framing that
        the offline parser relies on when walking these logs.
        """
        zf, entries = self._collect_zip()

        checked = 0
        for name, entry in sorted(entries.items()):
            base = os.path.basename(name)
            if base not in _COMMON_LOG_FILES:
                continue

            data = zf.read(entry)
            self.assertGreaterEqual(
                len(data), _COMMON_LOG_HEADER_SIZE,
                f"{base} is shorter than its {_COMMON_LOG_HEADER_SIZE}-byte header",
            )

            (log_size,) = struct.unpack_from(
                "<I", data, _COMMON_LOG_SIZE_OFFSET
            )
            self.assertEqual(
                len(data), log_size,
                f"{base} is {len(data)} bytes but its header claims "
                f"log_size={log_size} (log_size includes the 32-byte header)",
            )
            checked += 1

        if not checked:
            self.skipTest(
                "No common-format vendor logs were collected on this drive"
            )
