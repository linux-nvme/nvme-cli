#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for the host-discovery, ave-discovery and pull-model-ddc-req log
commands against a mocked controller.

Each of these log pages has a header which says how long the whole page
is, and records or data behind it. The tests check that the commands read
the part behind the header and print it, that the header asks for the
page the options select, and that a page whose lengths don't add up is
printed only as far as it goes.

Usage: python3 nvme_discovery_logs_test.py <nvme-binary> <mock-lib>
"""
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest

from nvme_mock_ipc import MockIPCServer, make_mock_env, resolve_mock_lib_path, run_nvme

_NVME_BIN = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else 'nvme'
_MOCK_LIB = resolve_mock_lib_path("./libmock_nvme.so")

_OPC_GET_LOG_PAGE = 0x02
_LID_HOST_DISCOVERY = 0x71
_LID_AVE_DISCOVERY = 0x72
_LID_PULL_MODEL_DDC_REQ = 0x73
_LID_POWER_MEASUREMENT = 0x25
_LID_REACHABILITY_GROUPS = 0x1a
_LID_REACHABILITY_ASSOCIATIONS = 0x1b

_HEADER_LEN = 1024        # host and AVE discovery log headers
_HEDLPE_LEN = 1032        # struct nvme_host_ext_discovery_log
_ADLPE_LEN = 232          # struct nvme_ave_discovery_log_entry
_ATR_LEN = 20             # struct nvme_ave_tr_record
_PULL_HEADER_LEN = 8      # struct nvme_pull_model_ddc_req_log
_POWER_MEAS_HEADER_LEN = 64  # struct nvme_power_meas_log

_NVMF_TRTYPE_TCP = 3
_NVMF_ADDR_FAMILY_IP4 = 1


def _host_discovery_log(hostnqns, tel=_HEDLPE_LEN):
    """A host discovery log page with one record for each of @hostnqns,
    whose record lengths say @tel."""
    records = b''
    for nqn in hostnqns:
        rec = bytearray(_HEDLPE_LEN)
        rec[0] = _NVMF_TRTYPE_TCP
        rec[1] = _NVMF_ADDR_FAMILY_IP4
        rec[256:256 + len(nqn)] = nqn.encode()
        traddr = b'192.0.2.1'
        rec[512:512 + len(traddr)] = traddr
        struct.pack_into('<I', rec, 1024, tel)
        records += bytes(rec)
    hdr = bytearray(_HEADER_LEN)
    struct.pack_into('<QQHBxI', hdr, 0, 1, len(hostnqns), 0, 0,
                     _HEADER_LEN + len(records))
    return bytes(hdr) + records


def _ave_discovery_log(avenqns, tel=None, numatr=1):
    """An AVE discovery log page with one record of one IPv4 transport
    record for each of @avenqns. @tel and @numatr default to the record
    length and the number of transport records which match."""
    records = b''
    for nqn in avenqns:
        rec = bytearray(_ADLPE_LEN + _ATR_LEN)
        struct.pack_into('<I', rec, 0, len(rec) if tel is None else tel)
        rec[4:4 + len(nqn)] = nqn.encode()
        rec[228] = numatr
        rec[_ADLPE_LEN] = _NVMF_ADDR_FAMILY_IP4
        struct.pack_into('<H', rec, _ADLPE_LEN + 2, 4420)
        rec[_ADLPE_LEN + 4:_ADLPE_LEN + 8] = bytes([192, 0, 2, 7])
        records += bytes(rec)
    hdr = bytearray(_HEADER_LEN)
    struct.pack_into('<QQHxxI', hdr, 0, 1, len(avenqns), 0,
                     _HEADER_LEN + len(records))
    return bytes(hdr) + records


def _pull_model_ddc_req_log(osp, tpdrpl=None):
    if tpdrpl is None:
        tpdrpl = _PULL_HEADER_LEN + len(osp)
    return struct.pack('<B3xI', 1, tpdrpl) + osp


def _power_meas_log(nphd, ndescs):
    """A power measurement log page which says it has @nphd histogram
    descriptors and is as long as @ndescs of them."""
    sze = _POWER_MEAS_HEADER_LEN + 8 * ndescs
    hdr = bytearray(_POWER_MEAS_HEADER_LEN)
    struct.pack_into('<BBHIIH', hdr, 0, 1, 0, 0, sze, 0, nphd)
    descs = b''.join(struct.pack('<II', i + 1, 0) for i in range(ndescs))
    return bytes(hdr) + descs


def _reachability_log(descs, fixed_len=32):
    """A reachability groups (or associations) log page with a descriptor
    for each (id, [ids]) in @descs: the ID, the number of IDs, and the
    IDs after the @fixed_len byte fixed part."""
    out = struct.pack('<QH6x', 1, len(descs))
    for ident, ids in descs:
        d = bytearray(fixed_len)
        struct.pack_into('<IIQ', d, 0, ident, len(ids), 1)
        out += bytes(d) + b''.join(struct.pack('<I', i) for i in ids)
    return out


def _kv(text):
    """The "key : value" lines of a text output as (key, value) pairs."""
    pairs = []
    for line in text.splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            pairs.append((k.strip(), v.strip()))
    return pairs


class LogMockServer(MockIPCServer):
    """Serves the log page in @logs[lid] by the offset and length a Get
    Log Page asks for, and records (lid, lsp, offset, length) of each."""

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.logs = {}
        self.requests = []

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                     cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        if opcode != _OPC_GET_LOG_PAGE:
            self.send_response(conn, 0, payload=b'\x00' * req_len)
            return
        lid = cdw10 & 0xff
        lsp = (cdw10 >> 8) & 0x7f
        self.requests.append((lid, lsp, lpo, req_len))
        page = self.logs.get(lid, b'')
        data = page[lpo:lpo + req_len]
        self.send_response(conn, 0, payload=data + b'\x00' * (req_len - len(data)))


class DiscoveryLogsTest(unittest.TestCase):

    DEVICE = '/dev/nvme0'

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nvme-discovery-logs-', dir='/tmp')
        self.sysfs_dir = os.path.join(self.tmp, 'sysfs')
        self.base_dir = os.path.join(self.tmp, 'base')
        os.mkdir(self.sysfs_dir)
        os.mkdir(self.base_dir)
        self.server = LogMockServer(os.path.join(self.tmp, 'ipc.sock'))
        self.server.start()
        self.env = make_mock_env(_MOCK_LIB, self.server.sock_path)

    def tearDown(self):
        self.server.shutdown()
        self.server.join()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, *args):
        result = run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                          'log', *args, self.DEVICE)
        self.assertEqual(result.returncode, 0,
                         f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}')
        self.assertEqual(self.server.errors, [])
        return result.stdout

    def _run_json(self, *args):
        return json.loads(self._run(*args, '-o', 'json'))

    def _run_both(self, *args):
        """Runs the command with text and JSON output, for a page whose
        lengths don't add up. Returns the JSON output."""
        self._run(*args)
        return self._run_json(*args)

    def test_host_discovery_records_are_read(self):
        self.server.logs[_LID_HOST_DISCOVERY] = \
            _host_discovery_log(['nqn.2014-08.org.example:host1',
                                 'nqn.2014-08.org.example:host2'])
        out = self._run_json('host-discovery')
        self.assertEqual(out['hedlpe: 0']['hostnqn'],
                         'nqn.2014-08.org.example:host1')
        self.assertEqual(out['hedlpe: 1']['hostnqn'],
                         'nqn.2014-08.org.example:host2')
        self.assertEqual(out['hedlpe: 1']['traddr'], '192.0.2.1')

    def test_host_discovery_header_asks_for_all_host_entries(self):
        self.server.logs[_LID_HOST_DISCOVERY] = \
            _host_discovery_log(['nqn.2014-08.org.example:host1'])
        self._run_json('host-discovery', '--all-host-entries')
        reqs = [r for r in self.server.requests if r[0] == _LID_HOST_DISCOVERY]
        self.assertTrue(reqs)
        for lid, lsp, lpo, length in reqs:
            self.assertEqual(lsp, 1, f'request at offset {lpo}')

    def test_host_discovery_header_only(self):
        self.server.logs[_LID_HOST_DISCOVERY] = _host_discovery_log([])
        out = self._run_json('host-discovery')
        self.assertEqual(out['thdlpl'], _HEADER_LEN)
        self.assertFalse([k for k in out if k.startswith('hedlpe')])

    def test_host_discovery_zero_record_length(self):
        """A record length of 0 must not make the walk loop forever."""
        self.server.logs[_LID_HOST_DISCOVERY] = \
            _host_discovery_log(['nqn.2014-08.org.example:host1'], tel=0)
        self._run_both('host-discovery')

    def test_host_discovery_record_past_the_page(self):
        """A record which says it is longer than the page is not printed."""
        self.server.logs[_LID_HOST_DISCOVERY] = \
            _host_discovery_log(['nqn.2014-08.org.example:host1'],
                                tel=_HEDLPE_LEN * 4)
        out = self._run_both('host-discovery')
        self.assertFalse([k for k in out if k.startswith('hedlpe')])

    def test_ave_discovery_records_are_read(self):
        self.server.logs[_LID_AVE_DISCOVERY] = \
            _ave_discovery_log(['nqn.2014-08.org.example:ave1'])
        out = self._run_json('ave-discovery')
        self.assertEqual(out['adlpe: 0']['avenqn'],
                         'nqn.2014-08.org.example:ave1')
        self.assertEqual(out['adlpe: 0']['atr: 0']['avetraddr'], '192.0.2.7')
        self.assertEqual(out['adlpe: 0']['atr: 0']['avetrsvcid'], 4420)

    def test_ave_discovery_zero_record_length(self):
        self.server.logs[_LID_AVE_DISCOVERY] = \
            _ave_discovery_log(['nqn.2014-08.org.example:ave1'], tel=0)
        out = self._run_both('ave-discovery')
        self.assertFalse([k for k in out if k.startswith('adlpe')])

    def test_ave_discovery_transport_records_past_the_record(self):
        """More transport records than the record holds: only those in it
        are printed."""
        self.server.logs[_LID_AVE_DISCOVERY] = \
            _ave_discovery_log(['nqn.2014-08.org.example:ave1'], numatr=200)
        out = self._run_both('ave-discovery')
        self.assertEqual(out['adlpe: 0']['numatr'], 200)
        self.assertIn('atr: 0', out['adlpe: 0'])
        self.assertNotIn('atr: 1', out['adlpe: 0'])

    def test_ave_discovery_nqn_fills_its_field(self):
        """An NQN without a NUL ends at the end of its field."""
        nqn = 'nqn.2014-08.org.example:' + 'a' * 200
        self.server.logs[_LID_AVE_DISCOVERY] = _ave_discovery_log([nqn])
        out = self._run_both('ave-discovery')
        self.assertEqual(out['adlpe: 0']['avenqn'], nqn[:224])

    def test_pull_model_ddc_req_osp_is_read(self):
        self.server.logs[_LID_PULL_MODEL_DDC_REQ] = \
            _pull_model_ddc_req_log(b'OSPDATA!')
        out = self._run_json('pull-model-ddc-req')
        self.assertEqual(out['osp'], ['OSPDATA!'])

    def test_pull_model_ddc_req_short_length(self):
        """A length shorter than the header has no OSP to print."""
        self.server.logs[_LID_PULL_MODEL_DDC_REQ] = \
            _pull_model_ddc_req_log(b'', tpdrpl=4)
        out = self._run_both('pull-model-ddc-req')
        self.assertEqual(out['osp'], [])

    def test_pull_model_ddc_req_get_log_short_buffer(self):
        """get-log --verbose decodes the page in a buffer of the length
        asked for, not of the length the page says."""
        self.server.logs[_LID_PULL_MODEL_DDC_REQ] = \
            _pull_model_ddc_req_log(b'OSPDATA!' * 8, tpdrpl=0x10000)
        result = run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                          'get-log', self.DEVICE, '--log-id=0x73',
                          '--log-len=16', '--verbose')
        self.assertEqual(result.returncode, 0,
                         f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}')
        osp = result.stdout.split('osp:\n')[-1].splitlines()
        self.assertEqual(len(osp), 2, result.stdout)  # offset ruler, 8 bytes
        self.assertIn('OSPDATA!', osp[1])

    def test_power_measurement_more_descriptors_than_the_page(self):
        """More histogram descriptors than the page holds: only those in
        it are printed."""
        self.server.logs[_LID_POWER_MEASUREMENT] = _power_meas_log(100, 1)
        self._run('power-measurement', '--verbose')
        out = self._run_json('power-measurement')
        self.assertEqual(out['nphd'], 100)
        self.assertEqual(len(out['descs']), 1)

    def test_reachability_groups_descriptors_at_their_offsets(self):
        """The descriptors differ in length: the second follows the
        namespace IDs of the first."""
        self.server.logs[_LID_REACHABILITY_GROUPS] = \
            _reachability_log([(1, [10, 11]), (2, [20])])
        kv = _kv(self._run('reachability-groups'))
        self.assertEqual([v for k, v in kv if k == 'rgid'], ['1', '2'])
        self.assertEqual([v for k, v in kv if k.startswith('nsid')],
                         ['10', '11', '20'])

    def test_reachability_groups_no_zero_length_read(self):
        self.server.logs[_LID_REACHABILITY_GROUPS] = \
            _reachability_log([(1, []), (2, [])])
        self._run('reachability-groups', '--groups-only')
        lengths = [r[3] for r in self.server.requests
                   if r[0] == _LID_REACHABILITY_GROUPS]
        self.assertNotIn(0, lengths)

    def test_reachability_groups_too_many_namespace_ids(self):
        """A namespace ID count which no log can hold fails the command
        instead of being read or printed."""
        log = bytearray(_reachability_log([(1, [10])]))
        struct.pack_into('<I', log, 16 + 4, 0xffffffff)
        self.server.logs[_LID_REACHABILITY_GROUPS] = bytes(log)
        result = run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                          'log', 'reachability-groups', self.DEVICE)
        self.assertGreater(result.returncode, 0, 'not an error exit')
        self.assertNotIn('nsid', result.stdout)

    def test_reachability_associations_descriptors_at_their_offsets(self):
        self.server.logs[_LID_REACHABILITY_ASSOCIATIONS] = \
            _reachability_log([(1, [10, 11]), (2, [20])])
        kv = _kv(self._run('reachability-associations'))
        self.assertEqual([v for k, v in kv if k == 'rasid'], ['1', '2'])
        self.assertEqual([v for k, v in kv if k.startswith('rgid')],
                         ['10', '11', '20'])

    def test_reachability_json_lists_all_ids(self):
        self.server.logs[_LID_REACHABILITY_GROUPS] = \
            _reachability_log([(1, [10, 11]), (2, [20])])
        out = self._run_json('reachability-groups')
        self.assertEqual(out['rgid: 1']['nsid'], [10, 11])
        self.assertEqual(out['rgid: 2']['nsid'], [20])
        self.assertEqual(out['rgid: 2']['nnid'], 1)
        self.server.logs[_LID_REACHABILITY_ASSOCIATIONS] = \
            _reachability_log([(1, [10, 11])])
        out = self._run_json('reachability-associations')
        self.assertEqual(out['rasid: 1']['rgid'], [10, 11])


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]])
