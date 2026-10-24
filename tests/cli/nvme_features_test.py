#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests the Set Features commands set-feature and the feat plugin send:
the fields of Command Dword 10 to 14 and the data, as the NVM Express
Base Specification 2.4 (section 5.2.30.1) and the NVM Command Set
Specification 1.3 (LBA Range Type) define them.

The commands which change part of a feature first read it with Get
Features and keep the fields not given.

Usage: python3 nvme_features_test.py <path-to-nvme-binary> <mock-lib>
"""
import os
import struct

from tests.cli.nvme_mock import (FID_HOST_BEHAVIOR, NSID_ALL, NVME_IOCTL_ID,
                                 OPC_GET_FEATURES, OPC_SET_FEATURES,
                                 MockTestCase, Reply, host_behavior, main)

SV = 1 << 31

FID_ARBITRATION = 0x01
FID_POWER_MGMT = 0x02
FID_TEMP_THRESH = 0x04
FID_ERR_RECOVERY = 0x05
FID_VOLATILE_WC = 0x06
FID_NUM_QUEUES = 0x07
FID_IRQ_COALESCE = 0x08
FID_IRQ_CONFIG = 0x09
FID_WRITE_ATOMIC = 0x0a
FID_ASYNC_EVENT = 0x0b
FID_TIMESTAMP = 0x0e
FID_KATO = 0x0f
FID_HCTM = 0x10
FID_PERF_CHARACTERISTICS = 0x1c
FID_POWER_LIMIT = 0x23
FID_POWER_THRESH = 0x24
FID_POWER_MEASUREMENT = 0x25

PERF_ATTR_SIZE = 4096


class FeaturesTestBase(MockTestCase):

    def set_features(self):
        return self.server.admin_cmds(OPC_SET_FEATURES)

    def set_feature(self, *args):
        """Run @args, which sends one Set Features. Returns it."""
        self.assertOk(self.nvme(*args))
        cmd, = self.set_features()
        return cmd

    def assertFields(self, cmd, fid, cdw11=0, sv=False, nsid=0, cdw12=0,
                     cdw13=0, uidx=0):
        self.assertEqual(
            (cmd.cdw10, cmd.cdw11, cmd.nsid, cmd.cdw12, cmd.cdw13,
             cmd.cdw14),
            (fid | (SV if sv else 0), cdw11, nsid, cdw12, cdw13, uidx))


class SetFeatureTest(FeaturesTestBase):
    """set-feature"""

    def test_fields(self):
        cmd = self.set_feature('set-feature', self.ctrl, '--feature-id=0x80',
                               '--namespace-id=3', '--value=0x12345678',
                               '--cdw12=0x9abcdef0', '--uuid-index=5',
                               '--save')
        self.assertFields(cmd, 0x80, 0x12345678, sv=True, nsid=3,
                          cdw12=0x9abcdef0, uidx=5)
        self.assertIsNone(cmd.data)

    def test_nsid_of_the_device(self):
        """Without --namespace-id, the namespace of the device, all for a
        controller."""
        cmd = self.set_feature('set-feature', self.ctrl, '--feature-id=0x80')
        self.assertEqual(cmd.nsid, NSID_ALL)

        self.server.commands.clear()
        self.server.ioctls[NVME_IOCTL_ID] = Reply(status=1)
        cmd = self.set_feature('set-feature', self.ns, '--feature-id=0x80')
        self.assertEqual(cmd.nsid, 1)

    def test_data_file(self):
        data = bytes(range(256)) * 2
        path = os.path.join(self.tmp, 'data')
        with open(path, 'wb') as f:
            f.write(data)
        cmd = self.set_feature('set-feature', self.ctrl, '--feature-id=0x80',
                               '--data-len=512', f'--data={path}')
        self.assertEqual((cmd.data_len, cmd.data), (512, data))

    def test_data_stdin(self):
        data = b'\x5a' * 16
        self.assertOk(self.nvme('set-feature', self.ctrl, '--feature-id=0x80',
                                '--data-len=16', stdin_data=data,
                                encoding=None))
        cmd, = self.set_features()
        self.assertEqual(cmd.data, data)

    def test_data_length_of_the_feature(self):
        """Without --data-len, the length the feature has"""
        cmd = self.set_feature('set-feature', self.ctrl,
                               f'--feature-id={FID_HOST_BEHAVIOR}',
                               '--data=/dev/zero')
        self.assertEqual(cmd.data_len, 512)

    def test_feature_id_required(self):
        result = self.nvme('set-feature', self.ctrl, '--value=1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('feature-id required', result.stderr)
        self.assertEqual(self.set_features(), [])


class FeatPluginSetTest(FeaturesTestBase):
    """The feat plugin: each option of a feature goes into its field."""

    def test_fields(self):
        cases = [
            (['power-mgmt', '--ps=3', '--wh=2'],
             FID_POWER_MGMT, {'cdw11': 3 | 2 << 5}),
            (['hctm', '--tmt1=300', '--tmt2=310'],
             FID_HCTM, {'cdw11': 300 << 16 | 310}),
            (['volatile-wc', '--wce'],
             FID_VOLATILE_WC, {'cdw11': 1}),
            (['power-limit', '--plv=100', '--pls=1', '--uuid-index=2'],
             FID_POWER_LIMIT, {'cdw13': 100 | 1 << 16, 'uidx': 2}),
            (['power-thresh', '--ptv=10', '--pts=2', '--pmts=3', '--ept=1',
              '--uuid-index=1'],
             FID_POWER_THRESH,
             {'cdw11': 10 | 2 << 16 | 3 << 20 | 1 << 31, 'uidx': 1}),
            (['power-meas', '--act=1', '--pmts=2', '--smt=60'],
             FID_POWER_MEASUREMENT, {'cdw11': 1 | 2 << 4 | 60 << 16}),
            (['err-recovery', '--nsid=1', '--tler=10', '--dulbe'],
             FID_ERR_RECOVERY, {'cdw11': 10 | 1 << 16, 'nsid': 1}),
            (['int-coalesce', '--thr=5', '--time=10'],
             FID_IRQ_COALESCE, {'cdw11': 5 | 10 << 8}),
            (['int-vector-config', '--iv=3', '--cd'],
             FID_IRQ_CONFIG, {'cdw11': 3 | 1 << 16}),
            (['write-atom-normal', '--dn'],
             FID_WRITE_ATOMIC, {'cdw11': 1}),
            (['async-event-conf', '--result=0x1ff'],
             FID_ASYNC_EVENT, {'cdw11': 0x1ff}),
            (['keep-alive-timer', '--kato=5000'],
             FID_KATO, {'cdw11': 5000}),
        ]
        for args, fid, fields in cases:
            for save in ([], ['--save']):
                with self.subTest(args=args + save):
                    self.server.commands.clear()
                    cmd = self.set_feature('feat', args[0], self.ctrl,
                                           *args[1:], *save)
                    self.assertFields(cmd, fid, sv=bool(save), **fields)

    def test_timestamp(self):
        cmd = self.set_feature('feat', 'timestamp', self.ctrl,
                               '--tstmp=0x123456789abc')
        self.assertFields(cmd, FID_TIMESTAMP)
        # the timestamp in milliseconds, in the first 6 of 8 bytes
        self.assertEqual(cmd.data[:6],
                         struct.pack('<Q', 0x123456789abc)[:6])


    def test_perf_characteristics_standard(self):
        cmd = self.set_feature('feat', 'perf-characteristics', self.ctrl,
                               '--attri=0', '--r4karl=5')
        self.assertFields(cmd, FID_PERF_CHARACTERISTICS)
        expected = bytearray(PERF_ATTR_SIZE)
        expected[4] = 5
        self.assertEqual(cmd.data, expected)


    def test_perf_characteristics_vendor_specific(self):
        paid = '00112233-4455-6677-8899-aabbccddeeff'
        path = os.path.join(self.tmp, 'vs')
        with open(path, 'wb') as f:
            f.write(b'VSDATA')
        cmd = self.set_feature('feat', 'perf-characteristics', self.ctrl,
                               '--attri=0xc1', '--rvspa', f'--paid={paid}',
                               '--attrl=4', f'--vs-data={path}')
        self.assertFields(cmd, FID_PERF_CHARACTERISTICS,
                          cdw11=0xc1 | 1 << 8)
        # PAID, ATTRL, then the ATTRL bytes of vendor specific data
        expected = bytearray(PERF_ATTR_SIZE)
        expected[0:16] = bytes.fromhex(paid.replace('-', ''))
        struct.pack_into('<H', expected, 30, 4)
        expected[32:36] = b'VSDA'
        self.assertEqual(cmd.data, expected)

    def test_perf_characteristics_attribute_length(self):
        """The vendor specific data is at most 4064 bytes"""
        path = os.path.join(self.tmp, 'vs')
        with open(path, 'wb') as f:
            f.write(bytes(8192))
        result = self.nvme('feat', 'perf-characteristics', self.ctrl,
                           '--attri=0xc1', '--rvspa', '--attrl=4065',
                           f'--vs-data={path}')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('attribute length 4065 exceeds 4064 bytes',
                      result.stderr)
        self.assertEqual(self.set_features(), [])


class FeatPluginGetTest(FeaturesTestBase):
    """Without the options of the fields, the feat commands get the
    feature."""

    def test_arbitration(self):
        for args in ([], ['--output-format=normal'], ['--verbose'],
                     ['--sel=2']):
            with self.subTest(args=args):
                self.server.commands.clear()
                self.assertOk(self.nvme('feat', 'arbitration', self.ctrl,
                                        *args))
                self.assertEqual(self.set_features(), [])
                get, = self.server.admin_cmds(OPC_GET_FEATURES)
                self.assertEqual(get.fid, FID_ARBITRATION)


    def test_uuid_index(self):
        for command, fid in (('power-limit', FID_POWER_LIMIT),
                             ('power-thresh', FID_POWER_THRESH),
                             ('power-meas', FID_POWER_MEASUREMENT)):
            with self.subTest(command=command):
                self.server.commands.clear()
                self.assertOk(self.nvme('feat', command, self.ctrl,
                                        '--uuid-index=3'))
                get, = self.server.admin_cmds(OPC_GET_FEATURES)
                self.assertEqual((get.fid, get.uuid_index), (fid, 3))


class FeatPluginReadModifyWriteTest(FeaturesTestBase):
    """The feat commands which keep the fields not given, from the value
    Get Features reads: of the saved value with --save."""

    def assertGetSel(self, sel):
        get, = self.server.admin_cmds(OPC_GET_FEATURES)
        self.assertEqual(get.sel, sel)

    def test_temp_thresh(self):
        # TMPTH 345, TMPSEL 2, THSEL 1, TMPTHH 5
        self.server.features[FID_TEMP_THRESH] = Reply(
            result=345 | 2 << 16 | 1 << 20 | 5 << 22)
        cmd = self.set_feature('feat', 'temp-thresh', self.ctrl,
                               '--tmpth=350', '--tmpsel=2', '--thsel=1')
        get, = self.server.admin_cmds(OPC_GET_FEATURES)
        self.assertEqual(get.cdw11, 2 << 16 | 1 << 20)
        self.assertFields(cmd, FID_TEMP_THRESH,
                          cdw11=350 | 2 << 16 | 1 << 20 | 5 << 22)

    def test_arbitration(self):
        # AB 1, LPW 2, MPW 3, HPW 4
        self.server.features[FID_ARBITRATION] = Reply(
            result=1 | 2 << 8 | 3 << 16 | 4 << 24)
        cmd = self.set_feature('feat', 'arbitration', self.ctrl, '--ab=7',
                               '--hpw=0x40', '--save')
        self.assertGetSel(2)
        self.assertFields(cmd, FID_ARBITRATION, sv=True,
                          cdw11=7 | 2 << 8 | 3 << 16 | 0x40 << 24)

    def test_num_queues(self):
        # NSQA 15, NCQA 31
        self.server.features[FID_NUM_QUEUES] = Reply(result=15 | 31 << 16)
        cmd = self.set_feature('feat', 'num-queues', self.ctrl, '--nsqr=7')
        self.assertGetSel(0)
        self.assertFields(cmd, FID_NUM_QUEUES, cdw11=7 | 31 << 16)

    def test_host_behavior(self):
        self.server.features[FID_HOST_BEHAVIOR] = host_behavior(
            etdas=1, lbafee=1)
        cmd = self.set_feature('feat', 'host-behavior-support', self.ctrl,
                               '--acre=1', '--lbafee=0', '--cdfe=0x105')
        self.assertFields(cmd, FID_HOST_BEHAVIOR)
        self.assertEqual(cmd.data, host_behavior(acre=1, etdas=1, lbafee=0,
                                                 cdfe=0x105))

    def test_lba_range_type_count_mismatch(self):
        result = self.nvme('feat', 'lba-range-type', self.ctrl, '--nsid=1',
                           '--num=1', '--types=2', '--lbaros=1',
                           '--hlbars=0', '--slbas=0', '--nlbs=1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('No valid type definition', result.stderr)
        self.assertEqual(self.set_features(), [])


if __name__ == '__main__':
    main()
