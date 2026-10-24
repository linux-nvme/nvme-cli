#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>
"""Shared harness for the hardware-free ocp plugin tests.

libmock_nvme.c forwards every admin command nvme-cli issues to
OCPController here. The controller answers Identify Controller, the Identify
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

from tests.cli.nvme_mock import (CNS_CTRL, CNS_UUID_LIST, LPA_TELEMETRY,
                                 MockController, MockTestCase, id_ctrl,
                                 uuid_list)
from tests.e2e.plugins.ocp.ocp_c0_layout import OCP_UUID


def pack_id_ctrl(lpa=LPA_TELEMETRY):
    return id_ctrl(lpa=lpa)


def pack_uuid_list(slot=0, filler_count=0):
    """Build an Identify UUID List holding the OCP UUID at @slot.

    libnvme_find_uuid() stops at the first all-zero entry, so the slots
    ahead of @slot have to be occupied: @slot implies that many distinct
    filler UUIDs before it. Pass slot=None for a list with no OCP UUID
    at all (@filler_count entries, none of them OCP's)."""
    occupied = slot if slot is not None else filler_count
    # Distinct, non-zero, and not the OCP UUID.
    uuids = [bytes([0xA0 + i] * 16) for i in range(occupied)]
    if slot is not None:
        uuids.append(OCP_UUID)
    return uuid_list(*uuids)


class OCPController(MockController):
    """Serves Identify Controller, the Identify UUID List with the OCP
    UUID at @uuid_slot (see pack_uuid_list()) and the log pages in @logs.
    Anything nobody answers succeeds with zeroes."""

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.uuid_slot = 0
        self.uuid_filler_count = 0
        self.identify[CNS_CTRL] = pack_id_ctrl()
        self.identify[CNS_UUID_LIST] = lambda cmd: pack_uuid_list(
            self.uuid_slot, self.uuid_filler_count)


class OCPMockTestBase(MockTestCase):
    """The run helpers every ocp suite shares."""

    controller_class = OCPController

    def run_ocp(self, command, *args, device=None, encoding='utf-8',
                stack_limit_kb=None):
        return self.nvme('ocp', command,
                         device if device is not None else self.ctrl,
                         *args, encoding=encoding,
                         stack_limit_kb=stack_limit_kb)


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
    stdout."""

    def setUp(self):
        super().setUp()
        self.work_dir = os.path.join(self.tmp, 'internal-log')
        os.mkdir(self.work_dir)
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


