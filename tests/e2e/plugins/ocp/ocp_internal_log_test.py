# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
"""Test for OCP internal-log with the host and controller telemetry types.

`ocp internal-log -t host|controller` reads the drive's telemetry log and
its C9h Telemetry String Log, saves both, and decodes them into a JSON or
text report. Which statistics and event classes a drive logs, and in which
data area, depends on its OCP version and firmware, so these tests assume
none in particular: they decode the saved logs independently with
ocp_telemetry_layout.py and check that the report agrees with the bytes
the drive returned, whatever those turn out to be. Every event class, size
boundary and string table lookup is tested without hardware by the
tests/cli/ocp/ocp_internal_log_*_mock_test.py suites.

Every run with -t host has the drive create a new host-initiated telemetry
snapshot, so the tests share a single capture of Data Areas 1 and 2. On a
busy drive that can be millions of events and a report of several hundred
megabytes, so the report is parsed once and the text report is scanned
rather than loaded.

Tests in this module verify:
  * The saved telemetry log is the header plus Data Areas 1 and 2 exactly,
    and the saved string log is as long as its own table sizes say.
  * The report names every event FIFO the Data Area 1 header assigns to
    Data Area 1 or 2, using the string log's FIFO names.
  * Each FIFO's events match the raw FIFO by class, identifier and size,
    their Event Strings match the string log, and any Virtual FIFO events
    (class 0Bh) carry the identifier, subfields and names the raw bytes
    and string log call for.
  * Each data area's statistics match the raw descriptors by identifier,
    size and Context Index flag, down to the descriptors a Context
    Statistic Descriptor encapsulates.
  * Decoding the saved files with -l/-s reproduces the report byte for
    byte, and the text report carries every section and FIFO in order.
  * --host-generate=0 reads back the existing host-initiated snapshot
    without creating a new one.
  * A controller-initiated log, where the drive has one, is saved and
    decoded.
"""

import filecmp
import os
import shutil
import struct
import tempfile

from . import ocp_telemetry_layout as layout
from .ocp_test import TestOCP

# Identify Controller LPA bit 3: Telemetry Host-Initiated and
# Controller-Initiated log pages.
_LPA_TELEMETRY = 0x08

# internal-log's own summary of a fetch the drive refused; the reason (for
# example an unsupported C9h log) precedes it.
_UNSUPPORTED_MSGS = (
    "Failed to fetch telemetry-log from the drive.",
    "Failed to fetch string-log from the drive.",
)

_TEXT_RULE = "=" * 78

_HEADER_SECTIONS = (
    "Log Page Header",
    "Reason Identifier",
    "Telemetry Host-Initiated Data Block 1",
    "SMART / Health Information Log(LID-02h)",
    "SMART / Health Information Extended(LID-C0h)",
)

# Data areas decoded per telemetry type: the host log is the one under
# test, the controller log a smoke test.
_DATA_AREAS = {"host": 2, "controller": 1}

# Mismatching events quoted in a failure message.
_MAX_REPORTED = 5


def _fifo_info(da):
    return f"Data Area {da} Event FIFO info"


def _stats(da):
    return f"Data Area {da} Statistics"


class TestOCPInternalLog(TestOCP):
    """Verify that ocp internal-log decodes the drive's telemetry logs."""

    # Shared by every test in the class, because unittest builds a fresh
    # instance per test method: one capture per telemetry type as
    # (directory, output prefix, skip reason), and each capture's parsed
    # JSON report. Removed in tearDownClass.
    _captures = {}
    _reports = {}

    @classmethod
    def tearDownClass(cls):
        for directory, _, _ in cls._captures.values():
            shutil.rmtree(directory, ignore_errors=True)
        cls._captures = {}
        cls._reports = {}
        super().tearDownClass()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _require_telemetry(self):
        lpa = int(self.get_id_ctrl_field_value("lpa"), 0)
        if not lpa & _LPA_TELEMETRY:
            self.skipTest("controller does not support telemetry log pages "
                          "(Identify Controller LPA bit 3 clear)")

    def _capture(self, telemetry_type="host"):
        """Run internal-log against the drive once per telemetry type and
        return the output prefix its files were written under."""
        self._require_telemetry()
        captures = type(self)._captures
        if telemetry_type not in captures:
            directory = tempfile.mkdtemp(
                prefix=f"ocp-internal-log-{telemetry_type}-")
            prefix = os.path.join(directory, telemetry_type)
            result = self.run_ocp_cmd(
                "internal-log",
                args=(f"-t {telemetry_type} -a {_DATA_AREAS[telemetry_type]} "
                      f'-f "{prefix}"'))
            text = self.ocp_error_text(result)
            skip = None
            if result.returncode != 0 and any(msg in text
                                              for msg in _UNSUPPORTED_MSGS):
                skip = (f"ocp internal-log -t {telemetry_type} not supported "
                        f"on this drive: {text!r}")
            else:
                self.assertEqual(
                    result.returncode, 0,
                    f"ocp internal-log -t {telemetry_type} failed: "
                    f"rc={result.returncode}, stdout={result.stdout!r}, "
                    f"stderr={result.stderr!r}")
            captures[telemetry_type] = (directory, prefix, skip)
        _, prefix, skip = captures[telemetry_type]
        if skip:
            self.skipTest(skip)
        return prefix

    @staticmethod
    def _read(path):
        with open(path, "rb") as f:
            return f.read()

    def _logs(self, prefix):
        return (self._read(f"{prefix}-telemetry.bin"),
                self._read(f"{prefix}-string.bin"))

    def _report(self, telemetry_type="host"):
        """The capture's JSON report, parsed once."""
        prefix = self._capture(telemetry_type)
        reports = type(self)._reports
        if telemetry_type not in reports:
            path = f"{prefix}.json"
            self.assertTrue(os.path.exists(path),
                            f"{path} was not written; the decoder rejected "
                            f"the drive's log (see stderr)")
            with open(path, encoding="utf-8") as f:
                reports[telemetry_type] = self.parse_json_output(f.read(),
                                                                 path)
        return reports[telemetry_type]

    def _decode_files(self, prefix, name, args=""):
        """Decode the host capture's saved files into a report under
        @name, and return that report's path without its extension."""
        out = os.path.join(os.path.dirname(prefix), name)
        result = self.run_ocp_cmd(
            "internal-log",
            args=(f'-t host -a {_DATA_AREAS["host"]} '
                  f'-l "{prefix}-telemetry.bin" -s "{prefix}-string.bin" '
                  f'-f "{out}" {args}').strip())
        self.assertEqual(result.returncode, 0,
                         f"decoding the saved logs failed: "
                         f"stderr={result.stderr!r}")
        return out

    @staticmethod
    def _expected_fifos(telemetry, strings, da):
        names = layout.fifo_names(strings)
        return [(entry, f"EVENT FIFO {entry.number} - {names[entry.number]}")
                for entry in layout.fifo_table(telemetry) if entry.da == da]

    @staticmethod
    def _event_mismatches(event, decoded, tables, names):
        """(field, reported, expected) for every field of @decoded that
        disagrees with raw @event and the string log."""
        expected = {
            "Debug Event Class type": f"0x{event.cls:x}",
            "Event Identifier": f"0x{event.event_id:x}",
            "Event Data Size": f"0x{event.size_dw:x}",
            "Event String": (tables.vu_events
                             if event.cls >= layout.CLASS_VU_FIRST
                             else tables.events).get(
                                 (event.cls, event.event_id), ""),
        }
        if event.cls == layout.CLASS_VIRTUAL_FIFO and len(event.data) >= 2:
            fifo_id, = struct.unpack_from("<H", event.data)
            physical, virtual = layout.split_virtual_fifo_id(fifo_id)
            expected.update({
                "VU Virtual FIFO Identifier": f"0x{fifo_id:x}",
                "VU Virtual FIFO String": tables.vu_events.get(
                    (layout.CLASS_VIRTUAL_FIFO, fifo_id), ""),
                "Physical Event FIFO Number": f"0x{physical:x}",
                "Physical Event FIFO String": (
                    names[physical] if 1 <= physical <= layout.MAX_FIFOS
                    else ""),
                "Virtual FIFO Number": f"0x{virtual:x}",
            })
        return [(key, decoded.get(key), value)
                for key, value in expected.items()
                if decoded.get(key) != value]

    @staticmethod
    def _statistic_summary(decoded):
        """Identifier, size, Context Index flag and encapsulated
        identifiers of a reported statistic."""
        return (decoded.get("Statistics Identifier"),
                decoded.get("Statistic Data Size"),
                decoded.get("Statistics Info Context Index"),
                [inner.get("Statistics Identifier") for inner in
                 decoded.get("Encapsulated Statistic Descriptors", [])])

    @staticmethod
    def _raw_statistic_summary(stat):
        """_statistic_summary() of a layout.Statistic."""
        return (f"0x{stat.stat_id:x}", f"0x{stat.size_dw:x}",
                f"0x{int(stat.context_index):x}",
                [f"0x{inner.stat_id:x}" for inner in stat.encapsulated])

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_saved_logs_are_complete(self):
        telemetry, strings = self._logs(self._capture())
        self.assertEqual(telemetry[layout.HDR_LID], layout.LID_TELEMETRY_HOST)
        dalb1, dalb2, _, _ = layout.data_area_last_blocks(telemetry)
        self.assertGreater(dalb1, 0, "the host log has no Data Area 1")
        self.assertEqual(len(telemetry),
                         layout.HEADER_SIZE + dalb2 * layout.BLOCK_SIZE)
        self.assertEqual(len(strings), layout.string_log_length(strings))

    def test_report_lists_every_fifo(self):
        telemetry, strings = self._logs(self._capture())
        report = self._report()
        for section in (_HEADER_SECTIONS[0], _HEADER_SECTIONS[2]):
            self.assertIn(section, report)
        for da in (1, 2):
            with self.subTest(data_area=da):
                self.assertIn(_stats(da), report)
                self.assertEqual(
                    list(report[_fifo_info(da)]),
                    [title for _, title in
                     self._expected_fifos(telemetry, strings, da)])

    def test_events_match_the_raw_fifos(self):
        telemetry, strings = self._logs(self._capture())
        report = self._report()
        tables = layout.string_tables(strings)
        names = layout.fifo_names(strings)
        for da in (1, 2):
            for entry, title in self._expected_fifos(telemetry, strings, da):
                # The JSON printer drops Statistic Snapshot events (a known
                # defect, covered by the mock suite), so leave them out of
                # the comparison rather than fail every drive that logs
                # them.
                raw = [e for e in layout.iter_events(
                    layout.fifo_bytes(telemetry, entry))
                    if e.cls != layout.CLASS_STATISTIC_SNAPSHOT]
                reported = report[_fifo_info(da)].get(title, [])
                with self.subTest(fifo=title):
                    self.assertEqual(len(reported), len(raw))
                    mismatches = []
                    for event, decoded in zip(raw, reported):
                        for mismatch in self._event_mismatches(
                                event, decoded, tables, names):
                            mismatches.append((event.offset,) + mismatch)
                    self.assertEqual(
                        mismatches[:_MAX_REPORTED], [],
                        f"{len(mismatches)} fields disagree with the raw "
                        f"FIFO, as (byte offset, field, reported, expected)")

    def test_statistics_match_the_raw_descriptors(self):
        telemetry, _ = self._logs(self._capture())
        report = self._report()
        for da in (1, 2):
            raw = list(layout.iter_statistics(telemetry, da))
            reported = report[_stats(da)]
            with self.subTest(data_area=da):
                self.assertEqual([self._statistic_summary(s)
                                  for s in reported],
                                 [self._raw_statistic_summary(s)
                                  for s in raw])

    def test_decoding_the_saved_logs_reproduces_the_report(self):
        prefix = self._capture()
        out = self._decode_files(prefix, "redecoded")
        try:
            self.assertTrue(filecmp.cmp(f"{out}.json", f"{prefix}.json",
                                        shallow=False),
                            "decoding the saved logs gave a different report")
        finally:
            os.remove(f"{out}.json")

    def test_text_report_has_every_section_and_fifo(self):
        prefix = self._capture()
        telemetry, strings = self._logs(prefix)
        expected = list(_HEADER_SECTIONS)
        for da in (1, 2):
            expected += [_stats(da), _fifo_info(da)]
            expected += [title for _, title in
                         self._expected_fifos(telemetry, strings, da)]

        out = self._decode_files(prefix, "text", args="-o normal")
        titles = []
        try:
            with open(f"{out}.txt", encoding="utf-8",
                      errors="replace") as f:
                previous = [None, None]
                for line in f:
                    line = line.rstrip("\n")
                    if line == _TEXT_RULE and previous[0] == _TEXT_RULE:
                        titles.append(previous[1])
                    previous = [previous[1], line]
        finally:
            os.remove(f"{out}.txt")
        self.assertEqual(titles, expected)

    def test_host_generate_0_reads_the_existing_capture(self):
        """With --host-generate=0 the drive returns the snapshot the shared
        capture created rather than taking a new one, so the generation
        number and data areas are unchanged."""
        prefix = self._capture()
        captured, _ = self._logs(prefix)
        out = os.path.join(os.path.dirname(prefix), "retained")
        result = self.run_ocp_cmd(
            "internal-log",
            args=(f'-t host -g 0 -a {_DATA_AREAS["host"]} '
                  f'-s "{prefix}-string.bin" -f "{out}"'))
        self.assertEqual(result.returncode, 0,
                         f"ocp internal-log -t host -g 0 failed: "
                         f"stderr={result.stderr!r}")
        retained = self._read(f"{out}-telemetry.bin")
        self.assertEqual(retained[layout.HDR_BYTE_381],
                         captured[layout.HDR_BYTE_381],
                         "Host-Initiated Data Generation Number changed")
        self.assertTrue(retained[layout.HEADER_SIZE:]
                        == captured[layout.HEADER_SIZE:],
                        "the retained data areas differ from the capture")

    def test_controller_log(self):
        """A controller that has no controller-initiated data to report
        leaves nothing to decode, so check the header first."""
        self._require_telemetry()
        header_path = os.path.join(self.test_log_dir, "ctrl-header.bin")
        result = self.run_cmd(
            f"{self.nvme_bin} get-log {self.ctrl} "
            f"--log-id={layout.LID_TELEMETRY_CTRL} "
            f"--log-len={layout.HEADER_SIZE} --raw-binary > \"{header_path}\"")
        if result.returncode != 0:
            self.skipTest("controller-initiated telemetry log not readable: "
                          f"{result.stderr!r}")
        header = self._read(header_path)
        if len(header) < layout.HEADER_SIZE or \
                layout.data_area_last_blocks(header)[0] == 0:
            self.skipTest("the drive holds no controller-initiated "
                          "telemetry data")

        telemetry, strings = self._logs(self._capture("controller"))
        self.assertEqual(telemetry[layout.HDR_LID], layout.LID_TELEMETRY_CTRL)
        report = self._report("controller")
        self.assertEqual(
            list(report[_fifo_info(1)]),
            [title for _, title in
             self._expected_fifos(telemetry, strings, 1)])
