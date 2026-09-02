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
"""

import struct
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


class TestMicronVsInternalLog(TestMicron):
    """Test suite for the micron vs-internal-log plugin command."""

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
