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

OCPFeatureController and OCPFeatureTestBase add what the suites of a
Get/Set Features pair share: an answer per SEL for Get Features, a status
for Set Features, the commands sent for the feature, and the values a Get
prints. OCPUUIDTests adds the tests of a command that looks up the OCP
UUID index.

OCPInternalLogTestBase adds what the `ocp internal-log` suites share:
writing telemetry and string log fixtures to files, running the command,
and parsing the .json or .txt report it writes.

This module is imported by the ocp_*_mock_test.py suites; it registers no
tests of its own.
"""
import json
import os
import re

from tests.cli.nvme_mock import (CNS_CTRL, CNS_UUID_LIST, LPA_TELEMETRY,
                                 OPC_GET_FEATURES, OPC_SET_FEATURES,
                                 MockController, MockTestCase, Reply,
                                 id_ctrl, uuid_list)
from tests.e2e.plugins.ocp.ocp_c0_layout import OCP_UUID

# uuid_slot 1 puts the OCP UUID in the second entry: UUID index 2, so a
# command sent with index 0 or 1 shows.
UUID_SLOT = 1
UUID_INDEX = UUID_SLOT + 1

NO_UUID_MSG = 'No OCP UUID index found'
SEL_NAMES = ('Current', 'Default', 'Saved')
# GETF-5 capabilities (SEL 3) of a saveable, changeable feature that is
# not per namespace.
SAVEABLE_CAPABILITIES = 0x5
# GETF-5 capabilities of a changeable feature that is not saveable.
CHANGEABLE_CAPABILITIES = 0x4


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

    def run_json(self, command, *args):
        """Run @command with -o json and return its parsed output."""
        result = self.assertOk(self.run_ocp(command, '-o', 'json', *args))
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f'-o json output is not valid JSON ({exc}): '
                      f'{result.stdout!r}')


class OCPFeatureController(OCPController):
    """Serves the feature @fid with the OCP UUID at UUID_SLOT: Get
    Features answers @dword0[SEL] in Dword 0, Set Features @set_status."""

    fid = None

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.uuid_slot = UUID_SLOT
        self.dword0 = {3: SAVEABLE_CAPABILITIES}
        self.set_status = 0
        self.features[self.fid] = self.answer_feature

    def answer_feature(self, cmd):
        if cmd.opcode == OPC_SET_FEATURES:
            return Reply(status=self.set_status)
        return Reply(result=self.dword0.get(cmd.sel, 0))


class OCPFeatureTestBase(OCPMockTestBase):
    """Runs the commands of the feature of an OCPFeatureController."""

    controller_class = OCPFeatureController

    def run_cmd(self, command, *args):
        """Run @command with only its own commands recorded."""
        self.server.commands.clear()
        return self.run_ocp(command, *args)

    def cmds(self, opcode):
        """The recorded commands with @opcode for the feature."""
        return [c for c in self.server.admin_cmds(opcode)
                if c.fid == self.controller_class.fid]

    def only(self, opcode):
        """The one recorded command with @opcode for the feature."""
        cmds = self.cmds(opcode)
        self.assertEqual(len(cmds), 1, cmds)
        return cmds[0]

    def printed_values(self, stdout):
        """The (SEL name, value) of each "get-feature:0x<FID> <SEL> value:
        <value>" line of @stdout."""
        pattern = (rf'get-feature:0x{self.controller_class.fid:02X} (\w+) '
                   r'value: ((?:0x)?[0-9a-f]+)')
        return [(m.group(1), int(m.group(2), 16))
                for m in re.finditer(pattern, stdout)]

    def get_value(self, command, *args):
        """Run @command; returns the one (SEL name, value) it prints and
        the Get Features sent."""
        result = self.assertOk(self.run_cmd(command, *args))
        printed = self.printed_values(result.stdout)
        self.assertEqual(len(printed), 1, result.stdout)
        return printed[0], self.only(OPC_GET_FEATURES)


class OCPUUIDTests:
    """Tests of a command that looks up the OCP UUID index, for a base
    with run_cmd() and cmds() as in OCPFeatureTestBase. @without_uuid is
    the opcode it sends for the feature, then the command and its
    arguments."""

    without_uuid = ()

    def test_without_the_ocp_uuid_nothing_is_sent(self):
        opcode, *command = self.without_uuid
        self.server.uuid_slot = None
        result = self.run_cmd(*command)
        self.assertIn(NO_UUID_MSG, result.stderr)
        self.assertEqual(self.cmds(opcode), [])

    def test_without_the_ocp_uuid_exits_nonzero(self):
        self.server.uuid_slot = None
        result = self.run_cmd(*self.without_uuid[1:])
        self.assertNotEqual(result.returncode, 0)


def report_fields(text):
    """Label to value for every "label : value" line of a log page
    report, labels and values stripped of their alignment; the label ends
    at the first colon."""
    fields = {}
    for line in text.splitlines():
        label, sep, value = line.partition(':')
        if sep:
            fields[label.strip()] = value.strip()
    return fields


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
