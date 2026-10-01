#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Shared harness for the hardware-free ocp plugin tests.

libmock_nvme.c forwards every admin command nvme-cli issues to
OCPMockServer here. The server answers Identify Controller, the Identify
UUID List the OCP UUID index lookup reads, and Get Log Page for whichever
log IDs a test loads into it, serving each read by its log page offset
so chunked reads of a large log see the right bytes.

OCPInternalLogTestBase adds what the `ocp internal-log` suites share:
writing telemetry and string log fixtures to files, running the command,
and parsing the .json or .txt report it writes.

This module is imported by the ocp_*_mock_test.py suites; it registers no
tests of its own.
"""
import json
import os
import sys
import tempfile
import unittest

from tests.cli.nvme_mock_ipc import (MockIPCServer, make_mock_env,
                                     resolve_mock_lib_path, run_nvme)
from tests.e2e.plugins.ocp.ocp_c0_layout import OCP_UUID

NVME_BIN = (sys.argv[1]
            if len(sys.argv) > 1 and not sys.argv[1].startswith('-')
            else 'nvme')
MOCK_LIB = resolve_mock_lib_path("./libmock_nvme.so")

OPC_GET_LOG_PAGE = 0x02
OPC_IDENTIFY = 0x06

CNS_ID_CTRL = 0x01
CNS_UUID_LIST = 0x17

NSID_ALL = 0xFFFFFFFF

SC_INVALID_FIELD = 0x02

# struct nvme_id_ctrl: 4096 bytes, Log Page Attributes at byte 261.
ID_CTRL_SIZE = 4096
ID_CTRL_LPA = 261
# LPA bit 3: Telemetry Host-Initiated and Controller-Initiated log pages.
LPA_TELEMETRY = 0x08

# struct nvme_id_uuid_list: 32 reserved bytes, then 127 entries of
# {header, rsvd1[15], uuid[16]}.
UUID_LIST_SIZE = 4096
UUID_LIST_HEADER = 32
UUID_ENTRY_SIZE = 32
UUID_ENTRY_UUID_OFFSET = 16


def pack_id_ctrl(lpa=LPA_TELEMETRY):
    buf = bytearray(ID_CTRL_SIZE)
    buf[ID_CTRL_LPA] = lpa
    return bytes(buf)


def pack_uuid_list(slot=0, filler_count=0):
    """Build an Identify UUID List holding the OCP UUID at @slot.

    libnvme_find_uuid() stops at the first all-zero entry, so the slots
    ahead of @slot have to be occupied: @slot implies that many distinct
    filler UUIDs before it. Pass slot=None for a list with no OCP UUID
    at all (@filler_count entries, none of them OCP's)."""
    buf = bytearray(UUID_LIST_SIZE)

    def put(index, uuid):
        base = (UUID_LIST_HEADER + index * UUID_ENTRY_SIZE
                + UUID_ENTRY_UUID_OFFSET)
        buf[base:base + 16] = uuid

    occupied = slot if slot is not None else filler_count
    for i in range(occupied):
        # Distinct, non-zero, and not the OCP UUID.
        put(i, bytes([0xA0 + i] * 16))
    if slot is not None:
        put(slot, OCP_UUID)
    return bytes(buf)


class OCPMockServer(MockIPCServer):
    """Serves Identify Controller, the Identify UUID List and the log
    pages in @logs, and records every command in @commands.

    @logs maps a log ID to its bytes, or to an NVMe status code the read
    fails with. Subclasses steer individual commands by overriding
    respond(); anything nobody answers succeeds with zeroes."""

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.identify = pack_id_ctrl()
        self.uuid_slot = 0
        self.uuid_filler_count = 0
        self.logs = {}
        self.commands = []

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                     cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        cmd = {'opcode': opcode, 'nsid': nsid, 'cdw10': cdw10,
               'cdw14': cdw14, 'lpo': lpo, 'len': req_len}
        if opcode == OPC_IDENTIFY:
            cmd['cns'] = cdw10 & 0xFF
        elif opcode == OPC_GET_LOG_PAGE:
            cmd['lid'] = cdw10 & 0xFF
            cmd['lsp'] = (cdw10 >> 8) & 0x7F
            cmd['rae'] = bool(cdw10 & (1 << 15))
        self.commands.append(cmd)
        self.respond(conn, cmd)

    def respond(self, conn, cmd):
        if cmd['opcode'] == OPC_IDENTIFY:
            if cmd['cns'] == CNS_ID_CTRL:
                self.send_slice(conn, self.identify, 0, cmd['len'])
                return
            if cmd['cns'] == CNS_UUID_LIST:
                self.send_slice(conn, pack_uuid_list(self.uuid_slot,
                                                     self.uuid_filler_count),
                                0, cmd['len'])
                return
        elif cmd['opcode'] == OPC_GET_LOG_PAGE and cmd['lid'] in self.logs:
            entry = self.logs[cmd['lid']]
            if isinstance(entry, int):
                self.send_response(conn, 0, sc_status=entry)
            else:
                self.send_slice(conn, entry, cmd['lpo'], cmd['len'])
            return
        self.send_response(conn, 0, payload=bytes(cmd['len']))

    def send_slice(self, conn, payload, lpo, req_len):
        """Serve @payload[@lpo:@lpo + @req_len], zero-padded to @req_len."""
        chunk = payload[lpo:lpo + req_len]
        self.send_response(conn, 0,
                           payload=chunk + bytes(req_len - len(chunk)))

    def identify_requests(self, cns):
        return [c for c in self.commands
                if c['opcode'] == OPC_IDENTIFY and c['cns'] == cns]

    def log_reads(self, lid=None):
        return [c for c in self.commands
                if c['opcode'] == OPC_GET_LOG_PAGE
                and (lid is None or c['lid'] == lid)]


class OCPMockTestBase(unittest.TestCase):
    """Mock lifecycle and the run helpers every ocp suite shares."""

    DEVICE = '/dev/nvme0'
    server_class = OCPMockServer

    def setUp(self):
        """Everything here is torn down through addCleanup(), so a failure
        part way in still releases what was set up before it."""
        self.sysfs_dir = self._temp_dir('nvme-ocp-sysfs-')
        self.base_dir = self._temp_dir('nvme-ocp-base-')
        self.ipc_dir = self._temp_dir('nvme-ocp-ipc-')
        self.ipc_sock_path = os.path.join(self.ipc_dir, "ipc.sock")

        self.server = self.server_class(self.ipc_sock_path)
        self.server.start()
        # Cleanups run last-registered-first, so the server stops accepting
        # before join() waits on its thread, and before the socket's
        # directory goes away.
        self.addCleanup(self.server.join)
        self.addCleanup(self.server.shutdown)
        self.env = make_mock_env(MOCK_LIB, self.ipc_sock_path)

    def _temp_dir(self, prefix):
        tmp = tempfile.TemporaryDirectory(prefix=prefix, dir='/tmp')
        self.addCleanup(tmp.cleanup)
        return tmp.name

    def run_ocp(self, command, *args, device=None, encoding='utf-8'):
        return run_nvme(NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                        'ocp', command,
                        device if device is not None else self.DEVICE,
                        *args, encoding=encoding)

    def assertOk(self, result):
        self.assertEqual(
            result.returncode, 0,
            f'command failed:\nstdout:\n{result.stdout}\n'
            f'stderr:\n{result.stderr}')
        return result


# Section rules in the internal-log text report (STR_LINE and STR_LINE2 in
# plugins/ocp/ocp-telemetry-decode.h).
TEXT_RULE = '=' * 78
TEXT_RULE2 = '-' * 77
# Indent of the records in a nested list (STAT_NESTED_INDENT).
TEXT_INDENT = ' ' * 4

MODES = ('json', 'text')

STR_DA_EVENT_FIFO_INFO = 'Data Area {} Event FIFO info'
STR_DA_STATS = 'Data Area {} Statistics'


def parse_text_report(text):
    """Split an internal-log .txt report into [(title, [lines])].

    Every section, event FIFOs included, opens with a title framed by two
    TEXT_RULE lines; a lone closing TEXT_RULE ends the report."""
    lines = text.split('\n')
    sections = []
    i = 0
    while i < len(lines):
        if (lines[i] == TEXT_RULE and i + 2 < len(lines)
                and lines[i + 2] == TEXT_RULE):
            sections.append((lines[i + 1], []))
            i += 3
            continue
        if lines[i] != TEXT_RULE and sections:
            sections[-1][1].append(lines[i])
        i += 1
    return sections


def text_fields(lines):
    """Parse generic_structure_parser()'s "%-40s : %-4s" lines."""
    fields = {}
    for line in lines:
        key, sep, value = line.partition(' : ')
        if sep:
            fields[key.rstrip()] = value.rstrip()
    return fields


def text_records(lines):
    """Parse "key: value" lines into one dict per TEXT_RULE2-terminated
    record, keeping line order. A value may be empty ("key: ").

    A "key:" line opens a list: the TEXT_INDENT-indented lines after it
    are its records, parsed the same way, so the result has the shape of
    the JSON report."""
    records = []
    current = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if line == TEXT_RULE2:
            records.append(current)
            current = {}
            continue
        if line.endswith(':') and not line.startswith(TEXT_INDENT):
            nested = []
            while i < len(lines) and lines[i].startswith(TEXT_INDENT):
                nested.append(lines[i][len(TEXT_INDENT):])
                i += 1
            current[line[:-1]] = text_records(nested)
            continue
        key, sep, value = line.partition(': ')
        if sep:
            current[key] = value
    if current:
        records.append(current)
    return records


class OCPInternalLogTestBase(OCPMockTestBase):
    """Runs `ocp internal-log` on fixture files and reads back its report.

    The decoder writes its report to <-f>.json or <-f>.txt rather than to
    stdout, and reads -l/-s only when their paths contain "bin"."""

    def setUp(self):
        super().setUp()
        self.work_dir = self._temp_dir('nvme-ocp-internal-log-')
        self.out_prefix = os.path.join(self.work_dir, 'report')

    def write_file(self, name, data):
        path = os.path.join(self.work_dir, name)
        with open(path, 'wb') as f:
            f.write(data)
        return path

    def report_path(self, mode, prefix=None):
        return (prefix or self.out_prefix) + ('.json' if mode == 'json'
                                              else '.txt')

    def run_internal_log(self, *args, telemetry=None, strings=None,
                         prefix=None, device=None):
        """Run internal-log, reading @telemetry and @strings from files
        when given and from the mocked drive otherwise. Any report left by
        an earlier run is removed first."""
        prefix = prefix or self.out_prefix
        for mode in MODES:
            if os.path.exists(self.report_path(mode, prefix)):
                os.remove(self.report_path(mode, prefix))
        self.server.commands.clear()
        cmd = ['-f', prefix]
        if telemetry is not None:
            cmd += ['-l', self.write_file('telemetry.bin', telemetry)]
        if strings is not None:
            cmd += ['-s', self.write_file('string.bin', strings)]
        return self.run_ocp('internal-log', *cmd, *args, device=device)

    def decode(self, telemetry, strings, *args, mode='json', prefix=None):
        """Decode the fixtures and return the parsed report: a dict for
        JSON, [(title, [lines])] for text."""
        return self.decode_with_output(telemetry, strings, *args, mode=mode,
                                       prefix=prefix)[0]

    def decode_with_output(self, telemetry, strings, *args, mode='json',
                           prefix=None):
        """decode(), also returning the run's combined output, where the
        decoder reports what it could not decode."""
        if mode == 'text':
            args = ('-o', 'normal') + args
        result = self.assertOk(self.run_internal_log(
            *args, telemetry=telemetry, strings=strings, prefix=prefix))
        output = result.stdout + result.stderr
        path = self.report_path(mode, prefix)
        self.assertTrue(os.path.exists(path), f'{path} was not written')
        with open(path, encoding='utf-8') as f:
            content = f.read()
        if mode == 'text':
            return parse_text_report(content), output
        try:
            return json.loads(content), output
        except json.JSONDecodeError as exc:
            self.fail(f'{path} is not valid JSON ({exc}): {content!r}')

    def decode_fails(self, telemetry, strings, *args, mode='json'):
        """Decode fixtures the decoder has to reject. Returns the run's
        combined output, after checking that no JSON report was written;
        the text printer leaves the part written before the failure."""
        if mode == 'text':
            args = ('-o', 'normal') + args
        result = self.run_internal_log(*args, telemetry=telemetry,
                                       strings=strings)
        if mode == 'json':
            self.assertFalse(os.path.exists(self.report_path('json')),
                             'a report was written for a rejected log')
        return result.stdout + result.stderr

    def section(self, report, title):
        """Return a JSON object member, or a text section's lines."""
        if isinstance(report, dict):
            self.assertIn(title, report)
            return report[title]
        matches = [lines for name, lines in report if name == title]
        self.assertEqual(len(matches), 1,
                         f'expected one {title!r} section in '
                         f'{[name for name, _ in report]}')
        return matches[0]

    def fifo_titles(self, report, da=1):
        """The FIFO names a report lists under Data Area @da, in order."""
        if isinstance(report, dict):
            return list(report[STR_DA_EVENT_FIFO_INFO.format(da)])
        titles = [name for name, _ in report]
        start = titles.index(STR_DA_EVENT_FIFO_INFO.format(da)) + 1
        names = []
        for name in titles[start:]:
            if not name.startswith('EVENT FIFO '):
                break
            names.append(name)
        return names

    def fifo_events(self, telemetry, strings, number=1, *args, mode='json',
                    da=1):
        """Decode the fixtures and return FIFO @number's events as a list
        of dicts. Both printers emit the same keys and value strings, so
        one expectation covers either mode."""
        report = self.decode(telemetry, strings, *args, mode=mode)
        prefix = f'EVENT FIFO {number} - '
        names = [n for n in self.fifo_titles(report, da)
                 if n.startswith(prefix)]
        self.assertEqual(len(names), 1,
                         f'expected one {prefix!r} FIFO in Data Area {da}, '
                         f'got {self.fifo_titles(report, da)}')
        if mode == 'json':
            return report[STR_DA_EVENT_FIFO_INFO.format(da)][names[0]]
        return text_records(self.section(report, names[0]))


def main():
    unittest.main(argv=[sys.argv[0]], verbosity=2)
