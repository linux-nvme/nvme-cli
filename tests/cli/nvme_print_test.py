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
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from nvme_mock_ipc import (MockIPCServer, make_mock_env,
                           resolve_mock_lib_path, run_nvme)

_NVME_BIN = (sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-')
             else 'nvme')
_MOCK_LIB = resolve_mock_lib_path("./libmock_nvme.so")

_SEEDS = (1, 2)

# Without json-c, some commands ignore '-o json' and print text.
_HAVE_JSON = os.environ.get('NVME_TEST_JSON', '1') == '1'

_OPC_GET_LOG_PAGE = 0x02
_OPC_IDENTIFY = 0x06
_OPC_IO_MGMT_RECV = 0x12
_OPC_RESV_REPORT = 0x0e
_OPC_DIR_RECV = 0x1a
_DIR_STREAMS_STATUS = 0x0102     # directive type 1, operation 2
_OPC_GET_FEATURES = 0x0a
_FID_FDP_EVENTS = 0x1e
_LID_PERSISTENT_EVENT = 0x0d
_LID_SUPPORTED_CAP_CONFIG = 0x11
_CNS_CTRL = 0x01
_NVME_IOCTL_ID = 0x40


def _put(buf, fmt, offset, value):
    if offset + struct.calcsize(fmt) <= len(buf):
        struct.pack_into(fmt, buf, offset, value)


# Log page ID -> (format, offset, value) fields to set in the log header.
# A value of None means the length of the first read, which is the header.
_FIXUPS = {
    0x0c: [('<H', 8, 1), ('<I', 20, 2)],        # ANA: ngrps, nnsids
    0x0d: [('<I', 4, 0), ('<Q', 8, None)],      # persistent event: tnev, tll
    0x0e: [('<I', 0, 16), ('<I', 4, 0)],        # LBA status: lslplen, nlslne
    0x10: [('<H', 0, 0)],                       # media unit status: nmu
    0x11: [('<B', 0, 1), ('<H', 20, 1),         # capacity config: sccn,
           ('<H', 128, 1), ('<H', 132, 1),      # egcn, egsets, egchans,
           ('<H', 136, 1), ('<H', 144, 0)],     # chmus, mudl
    0x17: [('<Q', 8, 2)],                       # dispersed ns: numpsub
    0x1a: [('<H', 8, 0)],                       # reachability groups: nrgd
    0x20: [('<H', 0, 0), ('<I', 4, 88),         # FDP configs: n, size,
           ('<H', 16, 72), ('<H', 24, 2)],      # config size, nruh
    0x21: [('<H', 0, 2)],                       # FDP RUH usage: nruh
    0x23: [('<I', 0, 2)],                       # FDP events: n
    0x1b: [('<H', 8, 0)],                       # reachability assoc.: nrad
    0x25: [('<I', 4, None), ('<H', 12, 0)],     # power measurement: sze, nphd
    0x71: [('<Q', 8, 0), ('<I', 20, 1024)],     # host discovery: numrec, thdlpl
    0x72: [('<Q', 8, 0), ('<I', 20, 1024)],     # AVE discovery: numrec, tadlpl
    0x73: [('<I', 4, 8)],                       # pull model DDC: tpdrpl
    0xbf: [('<H', 0, 2)],                       # changed zones: nrzid
}


# Identify Controller fields that give the size of the ANA log.
_ID_CTRL_FIXUPS = [
    ('<I', 348, 4),                             # nanagrpid
    ('<I', 540, 16),                            # mnan
]


class PrintMockIPCServer(MockIPCServer):

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.seed = 0
        self.header_len = {}
        self.logs = {}

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                     cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        rng = random.Random(f'{self.seed}:{opcode}:{cdw10}:{cdw11}:{lpo}')
        buf = bytearray(rng.randbytes(req_len))
        result = rng.getrandbits(32)

        if opcode == _OPC_GET_LOG_PAGE and cdw10 & 0xff in self.logs:
            data = self.logs[cdw10 & 0xff][lpo:lpo + req_len]
            buf = bytearray(data.ljust(req_len, b'\0'))
        elif opcode == _OPC_GET_LOG_PAGE and lpo == 0:
            lid = cdw10 & 0xff
            self.header_len.setdefault(lid, req_len)
            for fmt, offset, value in _FIXUPS.get(lid, []):
                _put(buf, fmt, offset,
                     self.header_len[lid] if value is None else value)
        elif opcode == _OPC_IDENTIFY and cdw10 & 0xff == _CNS_CTRL:
            for fmt, offset, value in _ID_CTRL_FIXUPS:
                _put(buf, fmt, offset, value)
        elif opcode == _OPC_IO_MGMT_RECV:
            _put(buf, '<H', 14, 2)      # reclaim unit handle status: nruhsd
        elif opcode == _OPC_RESV_REPORT:
            _put(buf, '<H', 5, 2)       # number of registered controllers
        elif (opcode == _OPC_DIR_RECV and
              cdw11 & 0xffff == _DIR_STREAMS_STATUS):
            _put(buf, '<H', 0, 2)       # open stream count
        elif opcode == _OPC_GET_FEATURES and cdw10 & 0xff == _FID_FDP_EVENTS:
            result &= 0xff  # bits 31:8 are reserved

        self.send_response(conn, 0, result=result, payload=bytes(buf))

    def handle_raw_ioctl(self, conn, fd, ioc, payload):
        if ioc.type == ord('N') and ioc.nr == _NVME_IOCTL_ID:
            self.send_response(conn, 0, sc_status=1)    # namespace 1
        else:
            super().handle_raw_ioctl(conn, fd, ioc, payload)


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


class PrintCLITest(unittest.TestCase):

    CTRL = '/dev/nvme0'
    NS = '/dev/nvme0n1'

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix='nvme-print-', dir='/tmp')
        self.sysfs_dir = os.path.join(self.tmp_dir, 'sysfs')
        self.base_dir = os.path.join(self.tmp_dir, 'base')
        os.mkdir(self.sysfs_dir)
        os.mkdir(self.base_dir)
        sock_path = os.path.join(self.tmp_dir, 'ipc.sock')

        self.server = PrintMockIPCServer(sock_path)
        self.server.start()
        self.env = make_mock_env(_MOCK_LIB, sock_path)

    def tearDown(self):
        self.server.shutdown()
        self.server.join()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _run_all(self, commands):
        for seed in _SEEDS:
            self.server.seed = seed
            for cmd in commands:
                for fmt in _FORMATS:
                    with self.subTest(seed=seed, cmd=' '.join(cmd + fmt)):
                        self._run(cmd + fmt)

    def _run(self, args):
        binary = '-o' in args and 'binary' in args
        result = run_nvme(_NVME_BIN, self.env, self.sysfs_dir,
                          self.base_dir, *args,
                          encoding=None if binary else 'utf-8')
        # A signal or a sanitizer abort, not an NVMe error status.
        self.assertGreaterEqual(result.returncode, 0)
        self.assertLess(result.returncode, 128)
        # Empty JSON output is not printed at all.
        if (_HAVE_JSON and result.returncode == 0 and '-o' in args and
                'json' in args and result.stdout.strip()):
            json.loads(result.stdout)

    def test_id(self):
        self._run_all([['id', c, self.NS] for c in _ID])

    def test_log(self):
        self._run_all([['log', c, self.CTRL] for c in _LOG])

    def test_feat(self):
        self._run_all([['feat', c, self.CTRL] for c in _FEAT])

    def test_plugin(self):
        def dev(cmd):
            if 'NS' in cmd:
                return [self.NS if a == 'NS' else a for a in cmd]
            return cmd[:2] + [self.CTRL] + cmd[2:]

        self._run_all([dev(c) for c in _PLUGIN])

    def test_list(self):
        for tree in _SYSFS_TREES:
            self.sysfs_dir = os.path.join(self.tmp_dir, tree.split('.')[0])
            os.mkdir(self.sysfs_dir)
            subprocess.run(['tar', 'xJf', _SYSFS_DATA / tree,
                            '-C', self.sysfs_dir], check=True)
            for cmd in _LIST:
                for fmt in _LIST_FORMATS:
                    with self.subTest(tree=tree, cmd=' '.join(cmd + fmt)):
                        self._run(cmd + fmt)

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
            self._run(['log', 'persistent-event', self.CTRL] + fmt)

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
            self._run(['log', 'supported-cap-config', self.CTRL] + fmt)

        # The checks below read the JSON output.
        if not _HAVE_JSON:
            return

        result = run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                          'log', 'supported-cap-config', self.CTRL,
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
        result = run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                          'log', 'supported-cap-config', self.CTRL,
                          '-o', 'json')
        self.assertEqual(result.returncode, 0)
        caps = json.loads(result.stdout)['Capacity Descriptor']
        chans = caps[0]['Endurance Descriptor'][0]['Channel Descriptor']
        self.assertEqual(len(chans), 1000)
        self.assertEqual(chans[999]['Media Descriptor'][0]['muid'], 999)

    def test_get_feature(self):
        self._run_all([['get-feature', self.CTRL, '-f', str(fid)]
                       for fid in range(0x01, 0x30)])


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]] + sys.argv[3:], verbosity=2)
