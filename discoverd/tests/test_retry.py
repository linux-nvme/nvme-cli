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

Usage: NVME_DISCOVERD=<nvme-discoverd> python3 test_retry.py <nvme>
       <libmock_nvme.so>
"""
import time
import unittest

from handover import DISC_NQN, Host
from tests.cli.nvme_mock import main

DC_TRADDR = '192.0.2.10'
REF_TRADDR = '192.0.2.11'


class RetryTest(unittest.TestCase):

    def setUp(self):
        self.host = Host()
        self.addCleanup(self.host.close)

    def configure_dc(self, dlp):
        self.host.fabric.add_target('tcp', DC_TRADDR, '8009', DISC_NQN,
                                    dlp=dlp)
        self.host.fabrics_conf(
            '[Discovery Controller]\n'
            f'controller = transport=tcp;traddr={DC_TRADDR};trsvcid=8009\n')

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


if __name__ == '__main__':
    main()
