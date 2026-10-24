#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests sanitize and sanitize-ns: the Sanitize and Sanitize Namespace
commands they send (NVM Express Base Specification 2.4, sections 5.2.26
and 5.2.27), and the checks of the options against each other and
against the Sanitize Capabilities of the controller.

Usage: python3 nvme_sanitize_test.py <path-to-nvme-binary> <mock-lib>
"""
import struct

from tests.cli.nvme_mock import (CNS_CTRL, NVME_IOCTL_ID, MockTestCase, Reply,
                                 id_ctrl, main)

OPC_SANITIZE = 0x84
LID_SANITIZE_STATUS = 0x81
OPC_SANITIZE_NS = 0x8c

# SANICAP
CES = 1 << 0
BES = 1 << 1
OWS = 1 << 2
VERS = 1 << 3
SPRRS = 1 << 5

# Sanitize Command Dword 10
EXIT_FAILURE = 1
BLOCK_ERASE = 2
OVERWRITE = 3
CRYPTO_ERASE = 4
EXIT_MEDIA_VERIFICATION = 5
AUSE = 1 << 3
OIPBP = 1 << 8
NDAS = 1 << 9
EMVS = 1 << 10
PREQ = 1 << 11


def sanitize_log(sprog=0xffff, sstat=0, scdw10=0, etbe=0xffffffff,
                 etbend=0xffffffff):
    """A Sanitize Status log page: the progress SPROG, the status SSTAT,
    Command Dword 10 of the last Sanitize, the estimated times ETBE and
    ETBEND of a block erase. The other estimated times are not
    reported."""
    log = bytearray(512)
    struct.pack_into('<HHIIIIIII', log, 0, sprog, sstat, scdw10,
                     0xffffffff, etbe, 0xffffffff, 0xffffffff, etbend,
                     0xffffffff)
    return bytes(log)


class SanitizeTest(MockTestCase):

    def sanitize(self, sanicap, *args):
        self.server.identify[CNS_CTRL] = id_ctrl(sanicap=sanicap)
        return self.nvme('sanitize', self.ctrl, *args)

    def sanitizes(self):
        return self.server.admin_cmds(OPC_SANITIZE)

    def test_actions(self):
        all_caps = CES | BES | OWS | VERS | SPRRS
        cases = [
            (['--sanact=exit-failure'], EXIT_FAILURE, 0),
            (['--sanact=start-block-erase', '--ause', '--no-dealloc'],
             BLOCK_ERASE | AUSE | NDAS, 0),
            (['--sanact=start-overwrite', '--owpass=15', '--oipbp',
              '--ovrpat=0xdeadbeef'],
             OVERWRITE | 15 << 4 | OIPBP, 0xdeadbeef),
            (['--sanact=start-crypto-erase', '--emvs', '--preq'],
             CRYPTO_ERASE | EMVS | PREQ, 0),
            (['--sanact=exit-media-verification'],
             EXIT_MEDIA_VERIFICATION, 0),
            (['--sanact=2'], BLOCK_ERASE, 0),
        ]
        for args, cdw10, cdw11 in cases:
            with self.subTest(args=args):
                self.server.commands.clear()
                self.assertOk(self.sanitize(all_caps, *args))
                cmd, = self.sanitizes()
                self.assertEqual((cmd.cdw10, cmd.cdw11), (cdw10, cdw11))

    def test_unsupported(self):
        """An action or a bit the controller doesn't support is refused,
        before the command is sent."""
        cases = [
            (CES | OWS | VERS | SPRRS, ['--sanact=start-block-erase'],
             'block erase action unsupported'),
            (CES | BES | VERS | SPRRS, ['--sanact=start-overwrite'],
             'overwrite action unsupported'),
            (BES | OWS | VERS | SPRRS, ['--sanact=start-crypto-erase'],
             'crypto erase action unsupported'),
            (BES | SPRRS, ['--sanact=start-block-erase', '--emvs'],
             'media verification unsupported'),
            (BES | VERS, ['--sanact=start-block-erase', '--preq'],
             'purge required unsupported'),
        ]
        for sanicap, args, message in cases:
            with self.subTest(args=args):
                result = self.sanitize(sanicap, *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
        self.assertEqual(self.sanitizes(), [])

    def test_invalid_options(self):
        caps = CES | BES | OWS
        cases = [
            (['--sanact=0'], 'Invalid Sanitize Action'),
            (['--sanact=6'], 'Invalid Sanitize Action'),
            (['--sanact=exit-failure', '--ause'],
             'SANACT is Exit Failure Mode'),
            (['--sanact=exit-media-verification', '--no-dealloc'],
             'SANACT is Exit Media Verification State'),
            (['--sanact=start-overwrite', '--owpass=16'],
             'OWPASS out of range'),
            (['--sanact=start-block-erase', '--ovrpat=1'],
             'SANACT is not Overwrite'),
            (['--sanact=start-crypto-erase', '--oipbp'],
             'SANACT is not Overwrite'),
            (['--sanact=start-block-erase', '--repeat=0'],
             'invalid repeat count: 0'),
        ]
        for args, message in cases:
            with self.subTest(args=args):
                result = self.sanitize(caps, *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
        self.assertEqual(self.sanitizes(), [])

    def wait(self, sanicap, logs, *args):
        """Run sanitize with --wait. The Sanitize Status log page reads
        get @logs."""
        logs = iter(logs)
        self.server.logs[LID_SANITIZE_STATUS] = lambda cmd: next(logs)
        return self.sanitize(sanicap, '--wait', *args)

    def test_wait(self):
        """The estimated time of the action the log page has is the time
        without progress to wait for"""
        for ndas, estimate in (([], {'etbe': 10}),
                               (['--no-dealloc'], {'etbend': 10})):
            with self.subTest(ndas=ndas):
                scdw10 = BLOCK_ERASE | (NDAS if ndas else 0)
                logs = [sanitize_log(0, scdw10=scdw10, **estimate)]
                logs += [sanitize_log(p, scdw10=scdw10, **estimate)
                         for p in (0x4000, 0x8000, 0xffff)]
                self.server.commands.clear()
                self.assertOk(self.wait(BES, logs,
                                        '--sanact=start-block-erase', *ndas))
                self.assertEqual(
                    len(self.server.log_reads(LID_SANITIZE_STATUS)), 4)

    def test_wait_done(self):
        """An action without an estimated time can be done at the first
        read of the progress"""
        logs = [sanitize_log(0, scdw10=EXIT_FAILURE),
                sanitize_log(0xffff, scdw10=EXIT_FAILURE)]
        self.assertOk(self.wait(0, logs, '--sanact=exit-failure'))

    def test_failed(self):
        self.server.admin[OPC_SANITIZE] = 0x11d     # in progress
        result = self.sanitize(BES, '--sanact=start-block-erase')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.sanitizes()), 1)


class SanitizeNsTest(MockTestCase):

    def setUp(self):
        super().setUp()
        self.server.ioctls[NVME_IOCTL_ID] = Reply(status=1)

    def test_namespace(self):
        """The namespace of the device, or of --namespace-id; NSID 0h is
        invalid for Sanitize Namespace"""
        for device, args, nsid in ((self.ns, [], 1),
                                   (self.ctrl, ['--namespace-id=2'], 2)):
            with self.subTest(device=device, args=args):
                self.server.commands.clear()
                self.assertOk(self.nvme('sanitize-ns', device,
                                        '--sanact=start-crypto-erase', *args))
                cmd, = self.server.admin_cmds(OPC_SANITIZE_NS)
                self.assertEqual(cmd.nsid, nsid)

    def test_no_namespace(self):
        # a controller has no namespace
        del self.server.ioctls[NVME_IOCTL_ID]
        result = self.nvme('sanitize-ns', self.ctrl,
                           '--sanact=start-crypto-erase')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('get-namespace-id', result.stderr)
        self.assertEqual(self.server.admin_cmds(OPC_SANITIZE_NS), [])

    def test_actions(self):
        cases = [
            (['--sanact=exit-failure'], EXIT_FAILURE),
            (['--sanact=start-crypto-erase', '--ause', '--emvs', '--preq'],
             # PREQ is bit 4 in Sanitize Namespace
             CRYPTO_ERASE | AUSE | 1 << 4 | EMVS),
            (['--sanact=exit-media-verification'], EXIT_MEDIA_VERIFICATION),
        ]
        for args, cdw10 in cases:
            with self.subTest(args=args):
                self.server.commands.clear()
                self.assertOk(self.nvme('sanitize-ns', self.ns, *args))
                cmd, = self.server.admin_cmds(OPC_SANITIZE_NS)
                self.assertEqual(cmd.cdw10, cdw10)

    def test_invalid_options(self):
        cases = [
            (['--sanact=2'], 'Invalid Sanitize Action'),
            (['--sanact=3'], 'Invalid Sanitize Action'),
            (['--sanact=exit-failure', '--ause'],
             'SANACT is Exit Failure Mode'),
            (['--sanact=exit-media-verification', '--ause'],
             'SANACT is Exit Media Verification State'),
        ]
        for args, message in cases:
            with self.subTest(args=args):
                result = self.nvme('sanitize-ns', self.ns, *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
        self.assertEqual(self.server.admin_cmds(OPC_SANITIZE_NS), [])


if __name__ == '__main__':
    main()
