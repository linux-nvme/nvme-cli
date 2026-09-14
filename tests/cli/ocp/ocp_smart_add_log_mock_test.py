#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Tests for "nvme ocp smart-add-log" against a mocked controller.

The C0 SMART / Health Information Extended log page is 512 bytes of
tightly packed fields, rendered by three separate printers (text, JSON
format version 1, JSON format version 2) that each gate the same fields
on the version the page reports in its own log page version field.
Nothing about that needs a real drive: the mock returns a synthetic page
whose every field holds a known value, so these tests can assert the
exact number nvme-cli prints for every field at every log page version,
in every output mode -- which is the part a hardware test cannot pin
down, since a real drive reports whatever it reports.

Field offsets, widths and version gating come from
tests/e2e/plugins/ocp/ocp_c0_layout.py, transcribed from the OCP
specification rather than from nvme-cli's own struct, so a disagreement
between the two shows up as a failure here.

Tests in this module verify:
  * Every field decodes to the expected value, at every log page version
    0..7, in all three output modes -- and that fields above the
    reported version are absent rather than printed as garbage.
  * The three printers agree with each other field by field.
  * The log page GUID is rendered correctly, and a page carrying a
    different GUID is rejected.
  * The Get Log Page command carries the OCP UUID index in CDW14 and
    NVME_NSID_ALL as its namespace, and a controller whose UUID list
    holds no OCP entry is refused instead of being read with index 0.
  * Output-mode and error handling: -o binary, -o json format version
    selection, invalid format and format-version values, a failing Get
    Log Page, a truncated page, and a nonexistent device.

Runs nowhere but Linux: libmock_nvme.so is an LD_PRELOAD shim.

Usage: python3 ocp_smart_add_log_mock_test.py <nvme-binary> <mock-lib>
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

from tests.cli.nvme_mock_ipc import (MockIPCServer, make_mock_env,
                                     resolve_mock_lib_path, run_nvme)
from tests.e2e.plugins.ocp import ocp_c0_layout as layout

_NVME_BIN = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else 'nvme'
_MOCK_LIB = resolve_mock_lib_path("./libmock_nvme.so")

_OPC_GET_LOG_PAGE = 0x02
_OPC_IDENTIFY = 0x06

_CNS_UUID_LIST = 0x17
_OCP_LID_SMART = 0xC0

_NSID_ALL = 0xFFFFFFFF

# struct nvme_id_uuid_list: 32 reserved bytes, then 127 entries of
# {header, rsvd1[15], uuid[16]}.
_UUID_LIST_SIZE = 4096
_UUID_LIST_HEADER = 32
_UUID_ENTRY_SIZE = 32
_UUID_ENTRY_UUID_OFFSET = 16

# Only these two JSON layouts exist; --output-format-version selects
# between them and the default is 2 (nvme_args in src/args.c).
_JSON_FORMAT_VERSIONS = (1, 2)
_DEFAULT_JSON_FORMAT_VERSION = 2

_UNKNOWN_GUID_MSG = "Unknown GUID in C0 Log Page data"
_READ_FAILURE_MSG = "Failure reading the C0 Log Page"
_NO_UUID_MSG = "No OCP UUID index found"

_SC_INVALID_LOG_PAGE = 0x09

# Both printers group `default:` with their highest case, so going one
# past the highest known version also covers that branch.
MAX_TESTED_VERSION = layout.MAX_LOG_PAGE_VERSION + 1


def pack_uuid_list(slot=0, filler_count=0):
    """Build an Identify UUID List holding the OCP UUID at @slot.

    libnvme_find_uuid() stops at the first all-zero entry, so the slots
    ahead of @slot have to be occupied: @slot implies that many distinct
    filler UUIDs before it. Pass slot=None for a list with no OCP UUID
    at all (@filler_count entries, none of them OCP's)."""
    buf = bytearray(_UUID_LIST_SIZE)

    def put(index, uuid):
        base = (_UUID_LIST_HEADER + index * _UUID_ENTRY_SIZE
                + _UUID_ENTRY_UUID_OFFSET)
        buf[base:base + 16] = uuid

    occupied = slot if slot is not None else filler_count
    for i in range(occupied):
        # Distinct, non-zero, and not the OCP UUID.
        put(i, bytes([0xA0 + i] * 16))
    if slot is not None:
        put(slot, layout.OCP_UUID)
    return bytes(buf)


class OCPMockServer(MockIPCServer):
    """Serves the two commands smart-add-log issues, and records how it
    asked for the log page. Anything else succeeds with zeroes."""

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.page = layout.pack(version=layout.MAX_LOG_PAGE_VERSION)
        # None: no OCP UUID in the list, so the plugin must fall back to
        # UUID index 0.
        self.uuid_slot = 0
        self.uuid_filler_count = 0
        self.log_sc_status = 0
        # Serve fewer bytes than asked for, to model a short transfer.
        self.truncate_to = None
        self.log_requests = []

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                     cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        if opcode == _OPC_IDENTIFY and (cdw10 & 0xFF) == _CNS_UUID_LIST:
            payload = pack_uuid_list(self.uuid_slot, self.uuid_filler_count)
            self.send_response(conn, 0, payload=payload[:req_len])
            return

        if opcode == _OPC_GET_LOG_PAGE and (cdw10 & 0xFF) == _OCP_LID_SMART:
            self.log_requests.append({
                'nsid': nsid, 'cdw14': cdw14, 'len': req_len, 'lpo': lpo,
            })
            if self.log_sc_status:
                self.send_response(conn, 0, sc_status=self.log_sc_status)
                return
            payload = self.page[:req_len]
            if self.truncate_to is not None:
                payload = payload[:self.truncate_to]
            self.send_response(conn, 0, payload=payload)
            return

        self.send_response(conn, 0, payload=bytes(req_len))


class OCPSmartAddLogTestBase(unittest.TestCase):
    """Mock lifecycle and the run/parse helpers the tests share."""

    DEVICE = '/dev/nvme0'

    def setUp(self):
        """Everything here is torn down through addCleanup(), so a failure
        part way in still releases what was set up before it."""
        self.sysfs_dir = self._temp_dir('nvme-ocp-sysfs-')
        self.base_dir = self._temp_dir('nvme-ocp-base-')
        self.ipc_dir = self._temp_dir('nvme-ocp-ipc-')
        self.ipc_sock_path = os.path.join(self.ipc_dir, "ipc.sock")

        self.server = OCPMockServer(self.ipc_sock_path)
        self.server.start()
        # Cleanups run last-registered-first, so the server stops accepting
        # before join() waits on its thread, and before the socket's
        # directory goes away.
        self.addCleanup(self.server.join)
        self.addCleanup(self.server.shutdown)
        self.env = make_mock_env(_MOCK_LIB, self.ipc_sock_path)

    def _temp_dir(self, prefix):
        tmp = tempfile.TemporaryDirectory(prefix=prefix, dir='/tmp')
        self.addCleanup(tmp.cleanup)
        return tmp.name

    def run_smart(self, *args, device=None, encoding='utf-8'):
        return run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                        'ocp', 'smart-add-log',
                        device if device is not None else self.DEVICE,
                        *args, encoding=encoding)

    def assertOk(self, result):
        self.assertEqual(
            result.returncode, 0,
            f'command failed:\nstdout:\n{result.stdout}\n'
            f'stderr:\n{result.stderr}')
        return result

    def json_log(self, format_version=None, device=None):
        """Run with JSON output and return the parsed log page."""
        args = ['-o', 'json']
        if format_version is not None:
            args += ['--output-format-version', str(format_version)]
        result = self.assertOk(self.run_smart(*args, device=device))
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f'-o json output is not valid JSON ({exc}): '
                      f'{result.stdout!r}')

    def text_log(self, device=None):
        """Run with text output and return the scraped label/value map."""
        result = self.assertOk(self.run_smart(device=device))
        return layout.parse_stdout(result.stdout)

    def json_key(self, field, format_version):
        return field.v1_key if format_version == 1 else field.v2_key


class TestOCPSmartAddLogDecode(OCPSmartAddLogTestBase):
    """Every field, every version, every output mode."""

    def _assert_json_decodes(self, version, format_version):
        page = layout.pack(version=version)
        self.server.page = page
        log = self.json_log(format_version=format_version)

        expected = layout.fields_for_version(version)
        for field in expected:
            key = self.json_key(field, format_version)
            if key is None:
                continue
            with self.subTest(field=field.name):
                self.assertIn(
                    key, log,
                    f'JSON format version {format_version} omits {key!r} at '
                    f'log page version {version}')
                self.assertEqual(
                    layout.coerce_json(field, log[key]),
                    layout.decode(page, field),
                    f'{key!r} decoded wrongly (offset {field.offset}, '
                    f'{field.size} bytes, {field.kind})')

        # Fields the page is too old to carry must not appear at all.
        absent = set(layout.FIELDS) - set(expected)
        for field in absent:
            key = self.json_key(field, format_version)
            if key is None:
                continue
            with self.subTest(field=field.name, absent=True):
                self.assertNotIn(
                    key, log,
                    f'{key!r} is a version {field.min_version} field but was '
                    f'printed for a version {version} page')

    def test_json_v1_decodes_every_field_at_every_version(self):
        for version in range(0, MAX_TESTED_VERSION + 1):
            with self.subTest(log_page_version=version):
                self._assert_json_decodes(version, 1)

    def test_json_v2_decodes_every_field_at_every_version(self):
        for version in range(0, MAX_TESTED_VERSION + 1):
            with self.subTest(log_page_version=version):
                self._assert_json_decodes(version, 2)

    def test_text_decodes_every_field_at_every_version(self):
        for version in range(0, MAX_TESTED_VERSION + 1):
            with self.subTest(log_page_version=version):
                page = layout.pack(version=version)
                self.server.page = page
                found = self.text_log()

                expected = layout.fields_for_version(version)
                for field in expected:
                    if field.stdout_label is None:
                        continue
                    with self.subTest(field=field.name):
                        self.assertIn(
                            field.name, found,
                            f'text output omits {field.stdout_label!r} at '
                            f'log page version {version}')
                        self.assertEqual(
                            layout.parse_stdout_value(field,
                                                      found[field.name]),
                            layout.decode(page, field),
                            f'{field.stdout_label!r} decoded wrongly '
                            f'(offset {field.offset}, {field.size} bytes, '
                            f'{field.kind})')

                for field in set(layout.FIELDS) - set(expected):
                    if field.stdout_label is None:
                        continue
                    with self.subTest(field=field.name, absent=True):
                        self.assertNotIn(
                            field.name, found,
                            f'{field.stdout_label!r} is a version '
                            f'{field.min_version} field but was printed for '
                            f'a version {version} page')

    def test_printers_agree_field_by_field(self):
        """A field decoded from the wrong struct member in one printer
        passes a per-printer check but not this one."""
        self.server.page = layout.pack(version=layout.MAX_LOG_PAGE_VERSION)
        v1 = self.json_log(format_version=1)
        v2 = self.json_log(format_version=2)
        text = self.text_log()

        for field in layout.fields_for_version(layout.MAX_LOG_PAGE_VERSION):
            values = {}
            if field.v1_key is not None and field.v1_key in v1:
                values['json v1'] = layout.coerce_json(field,
                                                       v1[field.v1_key])
            if field.v2_key is not None and field.v2_key in v2:
                values['json v2'] = layout.coerce_json(field,
                                                       v2[field.v2_key])
            if field.stdout_label is not None and field.name in text:
                values['text'] = layout.parse_stdout_value(
                    field, text[field.name])
            with self.subTest(field=field.name):
                self.assertEqual(
                    len(set(values.values())), 1,
                    f'{field.name} differs between output modes: {values}')

    def test_all_printers_report_the_same_field_count(self):
        """The three printers describe one log page, so they cannot
        disagree about how many fields it has."""
        self.server.page = layout.pack(version=layout.MAX_LOG_PAGE_VERSION)
        v1 = self.json_log(format_version=1)
        v2 = self.json_log(format_version=2)
        text = self.text_log()
        self.assertEqual(
            (len(v1), len(v2), len(text)),
            (len(layout.FIELDS),) * 3,
            f'expected {len(layout.FIELDS)} fields from each printer; '
            f'v1={sorted(v1)}, v2={sorted(v2)}, text={sorted(text)}')

    def test_version_above_the_highest_known_renders_as_the_highest(self):
        """Both printers group `default:` with their highest case, so a
        newer page must still render every field they know."""
        self.server.page = layout.pack(version=layout.MAX_LOG_PAGE_VERSION + 1)
        for format_version in _JSON_FORMAT_VERSIONS:
            with self.subTest(format_version=format_version):
                log = self.json_log(format_version=format_version)
                self.assertEqual(len(log), len(layout.FIELDS))


class TestOCPSmartAddLogAsciiFields(OCPSmartAddLogTestBase):
    """The fixed-width ASCII and UUID buffers.

    These assert on the printers' output verbatim rather than through
    layout.coerce_json(): normalising a value the way coerce_json() does
    -- truncate at the first NUL, strip trailing blanks -- is exactly the
    handling under test here, so comparing through it could not fail.
    """

    def _revision(self):
        return layout.by_name('dssd_firmware_revision')

    def test_space_padded_ascii_is_reported_verbatim(self):
        """A blank-padded buffer reaches the output as the drive sent it.

        The printers render these fields with a bounded "%.*s", which
        drops NUL padding but says nothing about blanks, and no spec
        dictates which padding a drive uses.
        """
        field = self._revision()
        self.server.page = layout.pack(
            version=layout.MAX_LOG_PAGE_VERSION,
            values={field.name: b'FW1234  '})
        for format_version in _JSON_FORMAT_VERSIONS:
            with self.subTest(format_version=format_version):
                log = self.json_log(format_version=format_version)
                key = self.json_key(field, format_version)
                self.assertEqual(log[key], 'FW1234  ')

    def test_nul_padded_ascii_stops_at_the_nul(self):
        """A NUL-padded buffer must not leak the bytes past the
        terminator into the output."""
        field = self._revision()
        self.server.page = layout.pack(
            version=layout.MAX_LOG_PAGE_VERSION,
            values={field.name: b'FW1\x00XYZ'})
        for format_version in _JSON_FORMAT_VERSIONS:
            with self.subTest(format_version=format_version):
                log = self.json_log(format_version=format_version)
                key = self.json_key(field, format_version)
                self.assertEqual(log[key], 'FW1')

    def test_text_output_carries_no_nul_bytes(self):
        """Text output is meant to be read in a terminal, so a
        NUL-padded ASCII field must not be written out raw."""
        field = self._revision()
        self.server.page = layout.pack(
            version=layout.MAX_LOG_PAGE_VERSION,
            values={field.name: b'FW1\x00\x00\x00\x00\x00'})
        result = self.assertOk(self.run_smart())
        self.assertNotIn('\x00', result.stdout,
                         'text output contains NUL bytes')

    def test_build_uuid_is_rendered_as_a_uuid(self):
        field = layout.by_name('dssd_firmware_build_uuid')
        raw = bytes(range(16))
        self.server.page = layout.pack(
            version=layout.MAX_LOG_PAGE_VERSION, values={field.name: raw})
        for format_version in _JSON_FORMAT_VERSIONS:
            with self.subTest(format_version=format_version):
                log = self.json_log(format_version=format_version)
                key = self.json_key(field, format_version)
                self.assertEqual(log[key].lower(), layout.render_uuid(raw))


class TestOCPSmartAddLogGuid(OCPSmartAddLogTestBase):
    """The GUID check is what decides whether the page is OCP's at all."""

    def test_guid_is_reported(self):
        field = layout.by_name('log_page_guid')
        for format_version in _JSON_FORMAT_VERSIONS:
            with self.subTest(format_version=format_version):
                log = self.json_log(format_version=format_version)
                key = self.json_key(field, format_version)
                self.assertEqual(
                    log[key].lower(),
                    layout.render_guid(layout.SCAO_GUID_BYTES))

    def test_wrong_guid_is_rejected(self):
        self.server.page = layout.pack(
            version=layout.MAX_LOG_PAGE_VERSION, guid=bytes(range(16)))
        result = self.run_smart()
        self.assertNotEqual(result.returncode, 0,
                            'a non-OCP GUID must not exit successfully')
        self.assertIn(_UNKNOWN_GUID_MSG, result.stdout + result.stderr)

    def test_all_zero_guid_is_rejected(self):
        self.server.page = layout.pack(
            version=layout.MAX_LOG_PAGE_VERSION, guid=bytes(16))
        result = self.run_smart()
        self.assertNotEqual(result.returncode, 0,
                            'an all-zero GUID must not exit successfully')


class TestOCPSmartAddLogCommand(OCPSmartAddLogTestBase):
    """How the Get Log Page command itself is built."""

    def test_uuid_index_is_the_ocp_entry(self):
        """libnvme_find_uuid() returns the 1-based slot, which is what
        goes into CDW14[6:0]."""
        for slot, expected_index in ((0, 1), (1, 2), (2, 3)):
            with self.subTest(slot=slot):
                self.server.uuid_slot = slot
                self.server.log_requests.clear()
                self.assertOk(self.run_smart('-o', 'json'))
                self.assertEqual(
                    self.server.log_requests[-1]['cdw14'] & 0x7F,
                    expected_index)

    def test_a_uuid_list_without_the_ocp_entry_is_rejected(self):
        """A controller that does not advertise the OCP UUID has no OCP
        C0 layout to report, so the command is refused rather than issued
        with a default UUID index."""
        self.server.uuid_slot = None
        self.server.uuid_filler_count = 2
        result = self.run_smart()
        self.assertNotEqual(
            result.returncode, 0,
            'a UUID list without the OCP entry must not exit 0')
        self.assertIn(_NO_UUID_MSG, result.stdout + result.stderr)
        self.assertEqual(self.server.log_requests, [],
                         'the log page was requested without a UUID index')

    def test_an_empty_uuid_list_is_rejected(self):
        self.server.uuid_slot = None
        self.server.uuid_filler_count = 0
        result = self.run_smart()
        self.assertNotEqual(result.returncode, 0,
                            'an empty UUID list must not exit 0')
        self.assertIn(_NO_UUID_MSG, result.stdout + result.stderr)
        self.assertEqual(self.server.log_requests, [],
                         'the log page was requested without a UUID index')

    def test_log_is_requested_for_all_namespaces(self):
        self.assertOk(self.run_smart('-o', 'json'))
        self.assertEqual(self.server.log_requests[-1]['nsid'], _NSID_ALL)

    def test_whole_log_page_is_requested_from_offset_zero(self):
        self.assertOk(self.run_smart('-o', 'json'))
        request = self.server.log_requests[-1]
        self.assertEqual(request['len'], layout.LOG_PAGE_SIZE)
        self.assertEqual(request['lpo'], 0)


class TestOCPSmartAddLogOutputModes(OCPSmartAddLogTestBase):
    """Output-format selection and the option surface."""

    def test_json_default_format_version_is_2(self):
        default = self.json_log()
        explicit = self.json_log(format_version=_DEFAULT_JSON_FORMAT_VERSION)
        self.assertEqual(default, explicit)

    def test_json_format_versions_use_different_key_names(self):
        """Guards against --output-format-version being ignored."""
        v1 = self.json_log(format_version=1)
        v2 = self.json_log(format_version=2)
        self.assertNotEqual(sorted(v1), sorted(v2))

    def test_normal_matches_the_default_output(self):
        bare = self.assertOk(self.run_smart())
        normal = self.assertOk(self.run_smart('-o', 'normal'))
        self.assertEqual(bare.stdout, normal.stdout)

    def test_binary_emits_the_raw_log_page(self):
        result = self.run_smart('-o', 'binary', encoding=None)
        self.assertEqual(result.returncode, 0,
                         f'-o binary failed: {result.stderr!r}')
        self.assertEqual(result.stdout, self.server.page,
                         '-o binary did not emit the 512-byte log page')

    def test_namespace_device_gives_the_same_result(self):
        """The C0 log is controller-scoped, so the block device path must
        not change what is reported."""
        ctrl = self.json_log()
        ns = self.json_log(device='/dev/nvme0n1')
        self.assertEqual(ctrl, ns)

    def test_text_output_reports_no_status_line_on_success(self):
        """A successful command has no NVMe status to report."""
        result = self.assertOk(self.run_smart())
        self.assertNotIn('NVMe Status', result.stdout + result.stderr)


class TestOCPSmartAddLogErrors(OCPSmartAddLogTestBase):
    """Failure paths."""

    def test_failing_get_log_page_is_reported(self):
        self.server.log_sc_status = _SC_INVALID_LOG_PAGE
        result = self.run_smart()
        self.assertNotEqual(result.returncode, 0,
                            'a failed Get Log Page must not exit 0')
        self.assertIn(_READ_FAILURE_MSG, result.stdout + result.stderr)

    def test_failing_get_log_page_is_reported_in_json_mode(self):
        self.server.log_sc_status = _SC_INVALID_LOG_PAGE
        result = self.run_smart('-o', 'json')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(_READ_FAILURE_MSG, result.stdout + result.stderr)

    def test_truncated_log_page_is_rejected(self):
        """A short transfer leaves the GUID unset, so the page must be
        refused rather than decoded from a partly zeroed buffer."""
        self.server.truncate_to = 256
        result = self.run_smart()
        self.assertNotEqual(result.returncode, 0,
                            'a truncated log page must not exit 0')

    def test_nonexistent_device_fails(self):
        """handle_open_intercept() in libmock_nvme.c claims every well-formed
        /dev/nvme<N>[n<M>] path and hands back an fd onto /dev/null. Use an
        unsupported device name to simulate a nonexistent device."""
        result = self.run_smart(device='/dev/nvme99x99')
        self.assertNotEqual(result.returncode, 0,
                            'a nonexistent device must not exit 0')

    def test_help_is_available_without_a_device(self):
        result = subprocess.run(
            [_NVME_BIN, 'ocp', 'smart-add-log', '--help'],
            capture_output=True, text=True)
        out = result.stdout + result.stderr
        self.assertIn('--output-format', out)


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]], verbosity=2)
