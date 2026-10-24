#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
"""Run the read-only commands in every output format.

Uses LD_PRELOAD mocking (see libmock_nvme.c), so no NVMe hardware and no
root are needed. The mock device answers every command with pseudo-random
data from a fixed seed, so each run sees the same data. Random data sets
most flags and fields, so the print code takes many of its branches.

The fields that give the size of a log or the number of its entries are
set to small values (see _FIXUPS). With random values there, a command
would read gigabytes, or print entries that are not in the buffer.

Each command must exit without a crash, and its JSON output must parse.

Usage: python3 nvme_print_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
import json
import os
import random
import struct
import subprocess
import unittest
from pathlib import Path

from tests.cli.nvme_mock import (CNS_CTRL, HAVE_JSON, NVME_IOCTL_ID,
                                 OPC_DIRECTIVE_RECV, OPC_GET_LOG_PAGE,
                                 OPC_IDENTIFY, MockController, MockTestCase,
                                 Reply, main)
from tests.cli.nvme_mock_ipc import run_nvme

_SEEDS = (1, 2)

# Run every command with and without the sandbox and compare the output.
_COMPARE_SANDBOX = os.environ.get('NVME_TEST_COMPARE_SANDBOX') == '1'

_OPC_IO_MGMT_RECV = 0x12
_OPC_RESV_REPORT = 0x0e
_DIR_STREAMS_PARAM = 0x0101      # directive type 1, operation 1
_DIR_STREAMS_STATUS = 0x0102     # directive type 1, operation 2
_LID_PERSISTENT_EVENT = 0x0d
_LID_MEDIA_UNIT_STATUS = 0x10
_LID_SUPPORTED_CAP_CONFIG = 0x11


def _put(buf, fmt, offset, value):
    if offset + struct.calcsize(fmt) <= len(buf):
        struct.pack_into(fmt, buf, offset, value)


# Log page ID -> (format, offset, value) fields to set in the log header.
# A value of None means the length of the first read, which is the header.
_FIXUPS = {
    0x0c: [('<H', 8, 1), ('<I', 20, 2)],        # ANA: ngrps, nnsids
    0x0d: [('<I', 4, 0), ('<Q', 8, None)],      # persistent event: tnev, tll
    0x0e: [('<I', 0, 16), ('<I', 4, 0)],        # LBA status: lslplen, nlslne
    0x10: [('<H', 0, 2)],                       # media unit status: nmu
    0x11: [('<B', 0, 1), ('<H', 20, 1),         # capacity config: sccn,
           ('<H', 128, 1), ('<H', 132, 1),      # egcn, egsets, egchans,
           ('<H', 136, 1), ('<H', 144, 0)],     # chmus, mudl
    0x17: [('<Q', 8, 2)],                       # dispersed ns: numpsub
    0x1a: [('<H', 8, 0)],                       # reachability groups: nrgd
    0x20: [('<H', 0, 0), ('<I', 4, 88),         # FDP configs: n, size,
           ('<H', 16, 72), ('<H', 24, 2)],      # config size, nruh
    0x21: [('<H', 0, 2)],                       # FDP RUH usage: nruh
    0x1b: [('<H', 8, 0)],                       # reachability assoc.: nrad
    0x25: [('<I', 4, None), ('<H', 12, 0)],     # power measurement: sze, nphd
    0x71: [('<Q', 8, 0), ('<I', 20, 1024)],     # host discovery: numrec, thdlpl
    0x72: [('<Q', 8, 0), ('<I', 20, 1024)],     # AVE discovery: numrec, tadlpl
    0x73: [('<I', 4, 8)],                       # pull model DDC: tpdrpl
}


# Identify Controller fields that give the size of the ANA log.
_ID_CTRL_FIXUPS = [
    ('<I', 348, 4),                             # nanagrpid
    ('<I', 540, 16),                            # mnan
]


class PrintController(MockController):
    """Answers each command with pseudo-random data and result, from a
    seed and the command, with the fixups above, or with the data of
    @logs and @dir_data. @id_ctrl patches Identify Controller: offset ->
    bytes."""

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.seed = 0
        self.header_len = {}
        self.id_ctrl = {}
        self.dir_data = {}
        self.ioctls[NVME_IOCTL_ID] = Reply(status=1)    # namespace 1

    def answer(self, cmd):
        rng = random.Random(f'{self.seed}:{cmd.opcode}:{cmd.cdw10}:'
                            f'{cmd.cdw11}:{cmd.lpo}')
        buf = bytearray(rng.randbytes(cmd.data_len))
        result = rng.getrandbits(32)
        opcode, dtype_doper = cmd.opcode, cmd.cdw11 & 0xffff

        if opcode == OPC_GET_LOG_PAGE and cmd.lid in self.logs:
            buf = super().answer(cmd)
        elif opcode == OPC_GET_LOG_PAGE and cmd.lpo == 0:
            self.header_len.setdefault(cmd.lid, cmd.data_len)
            for fmt, offset, value in _FIXUPS.get(cmd.lid, []):
                _put(buf, fmt, offset,
                     self.header_len[cmd.lid] if value is None else value)
        elif opcode == OPC_IDENTIFY and cmd.cns == CNS_CTRL:
            for fmt, offset, value in _ID_CTRL_FIXUPS:
                _put(buf, fmt, offset, value)
            for offset, value in self.id_ctrl.items():
                buf[offset:offset + len(value)] = value
        elif opcode == _OPC_IO_MGMT_RECV:
            _put(buf, '<H', 14, 2)      # reclaim unit handle status: nruhsd
        elif opcode == _OPC_RESV_REPORT:
            _put(buf, '<H', 5, 2)       # number of registered controllers
        elif opcode == OPC_DIRECTIVE_RECV and dtype_doper in self.dir_data:
            buf = self.dir_data[dtype_doper]
        elif (opcode == OPC_DIRECTIVE_RECV and
              dtype_doper == _DIR_STREAMS_STATUS):
            _put(buf, '<H', 0, 2)       # open stream count

        return Reply(data=buf, result=result)


_ID = ['ctrl', 'ns', 'ns-granularity', 'ns-lba-format', 'ns-list',
       'ctrl-list', 'nvm-ctrl', 'nvm-ns', 'nvm-ns-lba-format',
       'primary-ctrl-caps', 'secondary-ctrl-list', 'ns-ind', 'ns-descs',
       'nvmset', 'uuid', 'iocs', 'domain', 'endgrp-list']
_LOG = ['supported-pages', 'smart', 'ana', 'fw', 'endurance', 'effects',
        'error', 'changed-ns-list', 'changed-alloc-ns-list',
        'predictable-lat', 'pred-lat-event-agg', 'persistent-event',
        'endurance-event-agg', 'lba-status', 'resv-notif', 'phy-rx-eom',
        'self-test', 'fid-support-effects', 'mi-cmd-support-effects',
        'media-unit-stat', 'supported-cap-config', 'mgmt-addr-list',
        'rotational-media-info', 'dispersed-ns-participating-nss',
        'reachability-groups', 'reachability-associations',
        'host-discovery', 'ave-discovery', 'pull-model-ddc-req',
        'power-measurement', 'sanitize']
_FEAT = ['arbitration', 'power-mgmt', 'temp-thresh', 'volatile-wc',
         'num-queues', 'timestamp', 'hctm', 'host-behavior-support',
         'perf-characteristics', 'power-limit', 'power-thresh', 'power-meas',
         'err-recovery', 'lba-range-type', 'int-coalesce',
         'int-vector-config', 'write-atom-normal', 'async-event-conf',
         'keep-alive-timer']
_PLUGIN = [['fdp', 'configs', '-e', '1'], ['fdp', 'usage', '-e', '1'],
           ['fdp', 'stats', '-e', '1'], ['fdp', 'events', '-e', '1'],
           ['fdp', 'status', 'NS'], ['fdp', 'feature'],
           ['zns', 'id-ctrl'], ['zns', 'id-ns', 'NS'],
           ['zns', 'report-zones', 'NS', '-d', '4'],
           ['zns', 'changed-zone-list'], ['resv', 'report', 'NS'],
           ['dir', 'receive', 'NS', '-D', '0', '-O', '1'],
           ['dir', 'receive', 'NS', '-D', '1', '-O', '1'],
           ['dir', 'receive', 'NS', '-D', '1', '-O', '2', '-l', '64'],
           ['dir', 'receive', 'NS', '-D', '1', '-O', '3']]
_FORMATS = [[], ['-v'], ['-o', 'json'], ['-o', 'binary']]

# sysfs trees captured from real systems, from the libnvme tests.
_SYSFS_DATA = Path(__file__).resolve().parents[2] / 'libnvme/tests/sysfs/data'
_SYSFS_TREES = ['tree-pcie.tar.xz', 'tree-apple-nvme.tar.xz']
_LIST = [['list'], ['list-subsys'], ['show-topology'],
         ['show-topology', '-r', 'ctrl'], ['show-topology', '-r', 'multipath']]
_LIST_FORMATS = [[], ['-v'], ['-o', 'json'], ['-v', '-o', 'json']]


def _pretty_indent_error(text):
    """The first line of pretty JSON which is not indented by its depth."""
    depth = 0
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip(' ')
        closing = stripped[:1] in ('}', ']')
        if stripped and len(line) - len(stripped) != 2 * (depth - closing):
            return f'line {n}: {line!r}'
        in_str = esc = False
        for c in line:
            if esc:
                esc = False
            elif c == '\\':
                esc = in_str
            elif c == '"':
                in_str = not in_str
            elif not in_str and c in '{[':
                depth += 1
            elif not in_str and c in '}]':
                depth -= 1
    return None


class PrintCLITest(MockTestCase):

    controller_class = PrintController

    def _run_all(self, commands):
        for seed in _SEEDS:
            self.server.seed = seed
            for cmd in commands:
                for fmt in _FORMATS:
                    with self.subTest(seed=seed, cmd=' '.join(cmd + fmt)):
                        self._run(cmd + fmt)

    def _run(self, args, compare=True):
        binary = '-o' in args and 'binary' in args
        env = dict(self.env, NVME_SANDBOX='1') \
            if _COMPARE_SANDBOX else self.env
        result = run_nvme(self.nvme_bin, env, self.sysfs_dir,
                          self.base_dir, *args,
                          encoding=None if binary else 'utf-8')
        if _COMPARE_SANDBOX and compare:
            direct = run_nvme(self.nvme_bin,
                              dict(self.env, NVME_SANDBOX='0'),
                              self.sysfs_dir, self.base_dir, *args,
                              encoding=None if binary else 'utf-8')
            self.assertEqual(result.returncode, direct.returncode)
            self.assertEqual(result.stdout, direct.stdout)
            self.assertEqual(result.stderr, direct.stderr)
        errors, self.server.errors = self.server.errors, []
        if errors:
            self.fail('the mock server failed:\n' + ''.join(errors))
        # A signal or a sanitizer abort, not an NVMe error status.
        self.assertGreaterEqual(result.returncode, 0)
        self.assertLess(result.returncode, 128)
        # Empty JSON output is not printed at all.
        if (HAVE_JSON and result.returncode == 0 and '-o' in args and
                'json' in args and result.stdout.strip()):
            json.loads(result.stdout)
            # the members of the printer calls are put together as text
            self.assertIsNone(_pretty_indent_error(result.stdout))

    def test_id(self):
        self._run_all([['id', c, self.ns] for c in _ID])

    def test_log(self):
        self._run_all([['log', c, self.ctrl] for c in _LOG])

    def test_feat(self):
        self._run_all([['feat', c, self.ctrl] for c in _FEAT])

    def test_plugin(self):
        def dev(cmd):
            if 'NS' in cmd:
                return [self.ns if a == 'NS' else a for a in cmd]
            return cmd[:2] + [self.ctrl] + cmd[2:]

        self._run_all([dev(c) for c in _PLUGIN])

    def test_list(self):
        for tree in _SYSFS_TREES:
            self.sysfs_dir = os.path.join(self.tmp, tree.split('.')[0])
            os.mkdir(self.sysfs_dir)
            subprocess.run(['tar', 'xJf', _SYSFS_DATA / tree,
                            '-C', self.sysfs_dir], check=True)
            for cmd in _LIST:
                for fmt in _LIST_FORMATS:
                    with self.subTest(tree=tree, cmd=' '.join(cmd + fmt)):
                        # a missing hostnqn is generated anew each run
                        self._run(cmd + fmt, compare=False)

    def test_persistent_event(self):
        # One event of each type. Each one has enough data for the largest
        # event (SMART / Health, 512 bytes).
        rng = random.Random(0)
        etypes = list(range(0x01, 0x10)) + [0xde, 0xdf]
        events = b''
        for etype in etypes:
            data = rng.randbytes(512)
            # etype, etype_rev, ehl, ehai, cntlid, ets, pelpid, vsil, el
            events += struct.pack('<BBBBHQH4xHH', etype, 0, 21, 0, 1,
                                  rng.getrandbits(64), 0, 0, len(data))
            events += data
        header = bytearray(rng.randbytes(512))
        struct.pack_into('<B3xIQ', header, 0, _LID_PERSISTENT_EVENT,
                         len(etypes), len(header) + len(events))
        self.server.logs[_LID_PERSISTENT_EVENT] = bytes(header) + events

        for fmt in _FORMATS:
            self._run(['log', 'persistent-event', self.ctrl] + fmt)

    def test_id_ctrl_strings(self):
        # A '%' in a device string is not a format directive.
        mn = '%s%s%s%s%s%s%s%s'
        self.server.id_ctrl[24] = mn.encode().ljust(40)
        result = self.nvme('id-ctrl', self.ctrl)
        self.assertEqual(result.returncode, 0)
        self.assertIn(mn, result.stdout)

        if not HAVE_JSON:
            return
        result = self.nvme('id-ctrl', self.ctrl, '-o', 'json')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['mn'], mn)

    def test_persistent_event_entries(self):
        # Three Timestamp Change events. The first one has Vendor Specific
        # Information, which EL includes. The last one ends at TLL.
        vsi = b'\xaa' * 4
        events = b''
        for i, info in enumerate((vsi, b'', b'')):
            data = info + struct.pack('<QQ', 0x1000 + i, 0)
            # etype, etype_rev, ehl, ehai, cntlid, ets, pelpid, vsil, el
            events += struct.pack('<BBBBHQH4xHH', 0x03, 0, 21, 0, 1, 0, 0,
                                  len(info), len(data))
            events += data
        header = bytearray(512)
        struct.pack_into('<B3xIQ', header, 0, _LID_PERSISTENT_EVENT, 3,
                         len(header) + len(events))
        self.server.logs[_LID_PERSISTENT_EVENT] = bytes(header) + events

        result = self.nvme('log', 'persistent-event', self.ctrl)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.count('Event Number'), 3)

        if not HAVE_JSON:
            return
        result = self.nvme('log', 'persistent-event', self.ctrl, '-o', 'json')
        self.assertEqual(result.returncode, 0)
        entries = json.loads(result.stdout)['list_of_event_entries']
        self.assertEqual([e['prev_ts'] for e in entries],
                         [0x1000, 0x1001, 0x1002])

    @unittest.skipIf(os.geteuid() == 0, 'process limits do not apply to root')
    def test_sandbox_used(self):
        """With the sandbox, decoding needs a child process."""
        wrapper = os.path.join(self.tmp, 'nvme-no-fork')
        with open(wrapper, 'w', encoding='utf-8') as f:
            f.write('#!/bin/sh\nulimit -u 1 || exit 99\n'
                    'exec "$REAL_NVME" "$@"\n')
        os.chmod(wrapper, 0o755)
        env = dict(self.env, REAL_NVME=self.nvme_bin)
        # starting the privsep helper needs a child process too
        env.pop('NVME_PRIVSEP_TEST_HELPER', None)

        direct = run_nvme(wrapper, dict(env, NVME_SANDBOX='0'),
                          self.sysfs_dir, self.base_dir,
                          'log', 'smart', self.ctrl)
        if direct.returncode == 99:
            self.skipTest('ulimit -u not supported')
        self.assertEqual(direct.returncode, 0)
        sandboxed = run_nvme(wrapper, dict(env, NVME_SANDBOX='1'),
                             self.sysfs_dir, self.base_dir,
                             'log', 'smart', self.ctrl)
        self.assertEqual(sandboxed.returncode, 1)
        self.assertIn('cannot decode the device data in the sandbox',
                      sandboxed.stderr)

    def test_persistent_event_supported_events(self):
        # Only the Timestamp Change event (bit 3) is supported.
        header = bytearray(512)
        struct.pack_into('<B3xIQ', header, 0, _LID_PERSISTENT_EVENT, 0,
                         len(header))
        header[480] = 1 << 3
        self.server.logs[_LID_PERSISTENT_EVENT] = bytes(header)

        result = self.nvme('log', 'persistent-event', self.ctrl)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.count('Support '), 1)

        if not HAVE_JSON:
            return
        result = self.nvme('log', 'persistent-event', self.ctrl, '-o', 'json')
        self.assertEqual(result.returncode, 0)
        log = json.loads(result.stdout)
        self.assertEqual({k: v for k, v in log.items()
                          if k.startswith('bitmap_')},
                         {'bitmap_3': 'Support Timestamp Change Event(0x3)'})

    def test_persistent_event_vendor_specific(self):
        # An Event Name with an odd length leaves the next descriptor
        # and its signed integer unaligned.
        descs = (struct.pack('<HBBH', 0x10, 1, 0, 3) + b'abc' +
                 struct.pack('<HBBHq', 0x11, 4, 0, 8, -2))
        # etype, etype_rev, ehl, ehai, cntlid, ets, pelpid, vsil, el
        events = struct.pack('<BBBBHQH4xHH', 0xde, 0, 21, 0, 1, 0, 0, 0,
                             len(descs)) + descs
        header = bytearray(512)
        struct.pack_into('<B3xIQ', header, 0, _LID_PERSISTENT_EVENT, 1,
                         len(header) + len(events))
        self.server.logs[_LID_PERSISTENT_EVENT] = bytes(header) + events

        result = self.nvme('log', 'persistent-event', self.ctrl)
        self.assertEqual(result.returncode, 0)
        self.assertRegex(result.stdout, r'Signed Integer Data\s*:?\s*-2\b')

        if not HAVE_JSON:
            return
        result = self.nvme('log', 'persistent-event', self.ctrl, '-o', 'json')
        self.assertEqual(result.returncode, 0)
        self.assertIn('"signed_integer_data":-2', result.stdout.replace(' ', ''))

    def test_streams_directive(self):
        # msl, nssa, nsso, nssc, sws, sgs, nsa, nso
        self.server.dir_data[_DIR_STREAMS_PARAM] = struct.pack(
            '<HHHB9xIHHH6x', 1, 2, 3, 4, 0x10005, 6, 7, 8)
        # osc, sid[]
        self.server.dir_data[_DIR_STREAMS_STATUS] = struct.pack(
            '<4H', 3, 11, 12, 13)
        params = [1, 2, 3, 4, 0x10005, 6, 7, 8]
        status = [3, 11, 12, 13]

        def values(oper, *fmt):
            result = self.nvme('dir', 'receive', self.ns, '-D', '1', '-O',
                               oper, '-l', '64', '-v', *fmt)
            self.assertEqual(result.returncode, 0)
            if fmt:
                obj = json.loads(result.stdout)
                return [v for k, v in obj.items() if '(' in k or 'Stream' in k]
            return [int(line.split(':')[1]) for line in
                    result.stdout.splitlines()[1:] if ':' in line]

        self.assertEqual(values('1'), params)
        self.assertEqual(values('2'), status)

        if not HAVE_JSON:
            return
        self.assertEqual(values('1', '-o', 'json'), params)
        self.assertEqual(values('2', '-o', 'json'), status)

    def test_supported_cap_config(self):
        def media_units(*muids):
            return b''.join(struct.pack('<H4xH', m, 0) for m in muids)

        def channel(chanid, *muids):
            return struct.pack('<HH', chanid, len(muids)) + media_units(*muids)

        def egcd(endgid, sets, chans):
            return (struct.pack('<HH76xH', endgid, 7, len(sets)) +
                    b''.join(struct.pack('<H', s) for s in sets) +
                    struct.pack('<H', len(chans)) + b''.join(chans))

        def config(ccid, *egcds):
            return struct.pack('<HHH26x', ccid, 0, len(egcds)) + b''.join(egcds)

        log = (struct.pack('<B15x', 2) +
               config(1, egcd(1, [1, 2], [channel(0, 10), channel(1, 11, 12)])) +
               config(2, egcd(1, [], []), egcd(2, [3], [channel(5)])))
        self.server.logs[_LID_SUPPORTED_CAP_CONFIG] = log

        for fmt in _FORMATS:
            self._run(['log', 'supported-cap-config', self.ctrl] + fmt)

        # The checks below read the JSON output.
        if not HAVE_JSON:
            return

        result = self.nvme('log', 'supported-cap-config', self.ctrl,
                          '-o', 'json')
        self.assertEqual(result.returncode, 0)
        caps = json.loads(result.stdout)['Capacity Descriptor']
        self.assertEqual([c['cap_config_id'] for c in caps], [1, 2])
        egs = caps[0]['Endurance Descriptor']
        self.assertEqual([s['nvmsetid'] for s in egs[0]['NVM Set IDs']],
                         [1, 2])
        chans = egs[0]['Channel Descriptor']
        self.assertEqual([c['chanid'] for c in chans], [0, 1])
        self.assertEqual([m['muid'] for m in chans[1]['Media Descriptor']],
                         [11, 12])
        egs = caps[1]['Endurance Descriptor']
        self.assertEqual([e['endgid'] for e in egs], [1, 2])
        self.assertEqual(egs[1]['Channel Descriptor'][0]['chanid'], 5)

        # Longer than the first read of 4 KiB.
        chans = [channel(c, c) for c in range(1000)]
        self.server.logs[_LID_SUPPORTED_CAP_CONFIG] = (
            struct.pack('<B15x', 1) + config(1, egcd(1, [], chans)))
        result = self.nvme('log', 'supported-cap-config', self.ctrl,
                          '-o', 'json')
        self.assertEqual(result.returncode, 0)
        caps = json.loads(result.stdout)['Capacity Descriptor']
        chans = caps[0]['Endurance Descriptor'][0]['Channel Descriptor']
        self.assertEqual(len(chans), 1000)
        self.assertEqual(chans[999]['Media Descriptor'][0]['muid'], 999)

    def test_media_unit_stat(self):
        def desc(muid, cio, chans):
            return (struct.pack('<5H4B', muid, 0, 1, 1, 0, 90, 5,
                                len(chans), cio).ljust(cio, b'\0') +
                    b''.join(struct.pack('<H', c) for c in chans))

        def media_units(log):
            self.server.logs[_LID_MEDIA_UNIT_STATUS] = log
            result = self.nvme('log', 'media-unit-stat', self.ctrl, '-o',
                               'json')
            self.assertEqual(result.returncode, 0)
            return json.loads(result.stdout)['mus_list']

        log = (struct.pack('<3H10x', 3, 4, 1) + desc(0, 16, [0, 1]) +
               desc(1, 32, []) + desc(2, 16, [2, 3, 1]))
        self.server.logs[_LID_MEDIA_UNIT_STATUS] = log

        for fmt in _FORMATS:
            self._run(['log', 'media-unit-stat', self.ctrl] + fmt)

        # The checks below read the JSON output.
        if not HAVE_JSON:
            return

        mus = media_units(log)
        self.assertEqual([m['muid'] for m in mus], [0, 1, 2])
        self.assertEqual([[c['chanid'] for c in m['chanids']] for m in mus],
                         [[0, 1], [], [2, 3, 1]])

        # Longer than the first read of 4 KiB.
        mus = media_units(struct.pack('<H14x', 300) +
                          b''.join(desc(m, 16, range(8)) for m in range(300)))
        self.assertEqual(len(mus), 300)
        self.assertEqual(mus[299]['muid'], 299)

        # A CIO inside the descriptor header ends the list.
        mus = media_units(struct.pack('<H14x', 3) + desc(0, 16, [0]) +
                          desc(1, 8, []) + desc(2, 16, []))
        self.assertEqual([m['muid'] for m in mus], [0])

    def test_get_feature(self):
        self._run_all([['get-feature', self.ctrl, '-f', str(fid)]
                       for fid in range(0x01, 0x30)])


if __name__ == '__main__':
    main()
