#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
"""When nvme-discoverd retries a failed connect, and when it gives up.

Each test runs nvme-discoverd in the sandbox of handover.Host, with a
configured DC whose Discovery Log Page the fabric serves.

A DLP entry has NCC (EFLAGS bit 2) set while the CDC has no connection
to the subsystem. nvme-discoverd then stops after
connect-attempts-on-ncc failed attempts, and tries again when the DLP
no longer has NCC set.

Usage: NVME_DISCOVERD=<nvme-discoverd> python3 test_retry.py <nvme>
       <libmock_nvme.so>
"""
import time
import unittest

from handover import DISC_NQN, Host
from tests.cli.nvme_mock import main

DC_TRADDR = '192.0.2.10'
REF_TRADDR = '192.0.2.11'
IO_TRADDR = '192.0.2.20'
IO_NQN = 'nqn.2026-11.org.example:data'

NVME_NQN_CURR = 3
EFLAGS_EPCSD = 1 << 1
EFLAGS_NCC = 1 << 2


class RetryTest(unittest.TestCase):

    def setUp(self):
        self.host = Host()
        self.addCleanup(self.host.close)

    def configure_dc(self, dlp):
        dc = self.host.fabric.add_target('tcp', DC_TRADDR, '8009', DISC_NQN,
                                         dlp=dlp)
        self.host.fabrics_conf(
            '[Discovery Controller]\n'
            f'controller = transport=tcp;traddr={DC_TRADDR};trsvcid=8009\n')
        return dc

    def configure_ncc(self, eflags):
        """A persistent DC that lists an unreachable IOC with @eflags.
        Returns the DC and the IOC."""
        dc = self.configure_dc([])
        self.set_ioc_eflags(dc, eflags)
        ioc = self.host.fabric.add_target('tcp', IO_TRADDR, '4420', IO_NQN)
        ioc.reachable = False
        return dc, ioc

    @staticmethod
    def set_ioc_eflags(dc, eflags):
        dc.dlp = [{'transport': 'tcp', 'traddr': DC_TRADDR,
                   'trsvcid': '8009', 'subsysnqn': DISC_NQN,
                   'subtype': NVME_NQN_CURR, 'eflags': EFLAGS_EPCSD},
                  {'transport': 'tcp', 'traddr': IO_TRADDR,
                   'trsvcid': '4420', 'subsysnqn': IO_NQN,
                   'eflags': eflags}]

    def tracked(self, traddr):
        return [c for c in self.host.daemon.dump()
                if f'traddr={traddr}' in c['tid']]

    def wait(self, secs):
        """Let the retry timers run for @secs seconds."""
        end = time.monotonic() + secs
        while time.monotonic() < end:
            time.sleep(0.25)
            self.host.settle()

    def connects(self, traddr):
        """The connects to @traddr the fabric accepted."""
        refused = sum(1 for opts, _ in self.host.fabric.refused
                      if opts.get('traddr') == traddr)
        return sum(1 for opts in self.host.fabric.connects
                   if opts.get('traddr') == traddr) - refused

    def log(self):
        return (self.host.tmp / 'discoverd.log').read_text(
            encoding='utf-8', errors='replace')

    def test_referral_not_given_up(self):
        """dc-giveup-timeout does not apply to a referral: an admin
        configured it on the storage system. It retries for as long as
        its DC lists it."""
        host = self.host
        self.configure_dc([{'transport': 'tcp', 'traddr': REF_TRADDR,
                            'trsvcid': '8009', 'subsysnqn': DISC_NQN}])
        ref = host.fabric.add_target('tcp', REF_TRADDR, '8009', DISC_NQN)
        ref.reachable = False
        host.discoverd_config('[Discovery]\ndc-giveup-timeout = 0\n')
        host.start()
        self.wait(4)
        (ctrl,) = self.tracked(REF_TRADDR)
        self.assertGreaterEqual(ctrl['attempts'], 2)
        self.assertTrue(ctrl['retry_pending'])
        self.assertNotIn('giving up', self.log())

        ref.reachable = True
        self.wait(5)
        self.assertGreater(self.connects(REF_TRADDR), 0)

    def test_ncc_stops_and_resumes(self):
        """With NCC set, nvme-discoverd stops after
        connect-attempts-on-ncc attempts. It tries again when an AEN brings
        a DLP without NCC."""
        host = self.host
        dc, ioc = self.configure_ncc(EFLAGS_NCC)
        host.discoverd_config('[Discovery]\nconnect-attempts-on-ncc = 2\n')
        host.start()
        self.wait(4)
        (ctrl,) = self.tracked(IO_TRADDR)
        self.assertTrue(ctrl['ncc'])
        self.assertTrue(ctrl['ncc_stopped'])
        self.assertFalse(ctrl['retry_pending'])
        self.assertEqual(len(host.fabric.refused), 2)
        self.assertIn('NCC set, stopping after 2 attempts', self.log())

        ioc.reachable = True
        self.set_ioc_eflags(dc, 0)
        (dc_dev,) = host.find(DISC_NQN, DC_TRADDR)
        host.aen(dc_dev)
        self.wait(3)
        self.assertEqual(len(host.find(IO_NQN)), 1)
        (ctrl,) = self.tracked(IO_TRADDR)
        self.assertFalse(ctrl['ncc'])
        self.assertFalse(ctrl['ncc_stopped'])

    def test_no_ncc_keeps_retrying(self):
        """Without NCC, connect-attempts-on-ncc does not apply."""
        host = self.host
        self.configure_ncc(0)
        host.discoverd_config('[Discovery]\nconnect-attempts-on-ncc = 2\n')
        host.start()
        self.wait(4)
        (ctrl,) = self.tracked(IO_TRADDR)
        self.assertFalse(ctrl['ncc_stopped'])
        self.assertTrue(ctrl['retry_pending'])
        self.assertGreater(len(host.fabric.refused), 2)

    def test_ncc_no_limit_by_default(self):
        """connect-attempts-on-ncc defaults to 0: no limit."""
        host = self.host
        self.configure_ncc(EFLAGS_NCC)
        host.start()
        self.wait(4)
        (ctrl,) = self.tracked(IO_TRADDR)
        self.assertTrue(ctrl['ncc'])
        self.assertFalse(ctrl['ncc_stopped'])
        self.assertTrue(ctrl['retry_pending'])


if __name__ == '__main__':
    main()
