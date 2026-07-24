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

import os

from tests.plugins.micron.micron_test import TestMicron


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
            if os.path.exists(path):
                os.remove(path)
        super().tearDown()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _archive_path(self, filename):
        """Return a path inside the test log directory.

        The path is registered for automatic deletion in tearDown so that
        large archive files do not accumulate between test runs.
        """
        path = os.path.join(self.test_log_dir, filename)
        self._archive_files.append(path)
        return path

    def _subdirs(self, path):
        """Return the set of subdirectory names in path."""
        return {n for n in os.listdir(path) if os.path.isdir(os.path.join(path, n))}

    def _run_log(self, args=""):
        """Run micron vs-internal-log against the default controller."""
        return self.run_plugin_cmd("vs-internal-log", args=args)

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
        cwd = os.getcwd()
        dirs_before = self._subdirs(cwd)

        result = self._run_log(args=f"--package={output_path}")

        self.assertEqual(
            result.returncode, 0,
            f"vs-internal-log '{extension}' failed: "
            f"rc={result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}",
        )

        # Archive must exist and contain data.
        self.assertTrue(
            os.path.isfile(output_path),
            f"Archive was not created: {output_path}",
        )
        self.assertGreater(
            os.path.getsize(output_path), 0,
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
            os.path.isfile(output_path),
            f"Telemetry log file was not created: {output_path}",
        )
        size = os.path.getsize(output_path)
        self.assertGreater(size, 0, "Telemetry log file is empty")
        self.assertEqual(
            size % 512, 0,
            f"Telemetry log file size {size} is not a multiple of 512 bytes",
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
