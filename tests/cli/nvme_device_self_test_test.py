#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests device-self-test: the Device Self-test command it sends (NVM
Express Base Specification 2.4, section 5.2.5), and how it reports and
waits for the progress of a self-test from the Device Self-test log page.

Usage: python3 nvme_device_self_test_test.py <path-to-nvme-binary> <mock-lib>
"""
import os
import signal
import threading

from tests.cli.nvme_mock import NSID_ALL, MockTestCase, main

OPC_DEVICE_SELF_TEST = 0x14
LID_DEVICE_SELF_TEST = 0x06
SELF_TEST_LOG_SIZE = 564


def self_test_log(operation, completion):
    """The Device Self-test log page of a self-test @operation (0: none)
    at @completion percent"""
    return bytes([operation, completion]).ljust(SELF_TEST_LOG_SIZE, b'\0')


class DeviceSelfTestTest(MockTestCase):

    def self_tests(self):
        return self.server.admin_cmds(OPC_DEVICE_SELF_TEST)

    def test_self_test_codes(self):
        for code, message in ((1, 'Short Device self-test started'),
                              (2, 'Extended Device self-test started'),
                              (3, 'Host-Initiated Refresh started'),
                              (0xe, ''),
                              (0xf, 'Aborting device self-test operation')):
            with self.subTest(code=code):
                self.server.commands.clear()
                result = self.assertOk(self.nvme(
                    'device-self-test', self.ctrl,
                    f'--self-test-code={code}'))
                self.assertIn(message, result.stdout)
                cmd, = self.self_tests()
                self.assertEqual((cmd.nsid, cmd.cdw10), (NSID_ALL, code))

    def test_namespace(self):
        self.assertOk(self.nvme('device-self-test', self.ctrl,
                                '--self-test-code=1', '--namespace-id=1'))
        cmd, = self.self_tests()
        self.assertEqual((cmd.nsid, cmd.cdw10), (1, 1))

    def test_failed(self):
        self.server.admin[OPC_DEVICE_SELF_TEST] = 0x11d    # in progress
        result = self.nvme('device-self-test', self.ctrl,
                           '--self-test-code=1')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('started', result.stdout)

    def test_progress(self):
        """Without a self-test code, the progress of the self-test"""
        for log, message in ((self_test_log(0, 0), 'no self test running'),
                             (self_test_log(1, 42), 'progress 42%')):
            with self.subTest(message=message):
                self.server.logs[LID_DEVICE_SELF_TEST] = log
                result = self.assertOk(self.nvme('device-self-test',
                                                 self.ctrl))
                self.assertIn(message, result.stdout)
        self.assertEqual(self.self_tests(), [])

    def _wait(self, *progress):
        """Run a short self-test with --wait. The log page reads report
        @progress, (operation, completion) for each read."""
        logs = iter([self_test_log(*p) for p in progress])
        self.server.logs[LID_DEVICE_SELF_TEST] = lambda cmd: next(logs)
        return self.nvme('device-self-test', self.ctrl, '--self-test-code=1',
                         '--wait')

    def test_wait(self):
        self.assertOk(self._wait((1, 10), (1, 60), (0, 0)))
        self.assertEqual(len(self.server.log_reads(LID_DEVICE_SELF_TEST)), 3)

    def test_wait_interrupted(self):
        """Ctrl-C while waiting aborts the self-test"""
        if os.environ.get('NVME_PRIVSEP_TEST_HELPER'):
            self.skipTest('the privsep helper sends the commands')

        def progress(cmd):
            # during the sleep before the next read
            if not self.server.log_reads(LID_DEVICE_SELF_TEST)[:-1]:
                threading.Timer(0.3, os.kill,
                                (cmd.pid, signal.SIGINT)).start()
            return self_test_log(1, 10)

        self.server.logs[LID_DEVICE_SELF_TEST] = progress
        result = self.nvme('device-self-test', self.ctrl,
                           '--self-test-code=1', '--namespace-id=1', '--wait')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Interrupted', result.stderr)
        self.assertEqual([(c.nsid, c.cdw10) for c in self.self_tests()],
                         [(1, 1), (1, 0xf)])

    def test_wait_progress_backwards(self):
        result = self._wait((1, 60), (1, 10))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('progress broken', result.stderr)


if __name__ == '__main__':
    main()
