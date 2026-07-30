#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>

"""CLI integration tests for 'nvme config create'.

Tests invoke the nvme binary directly with an explicit --output under a
temporary directory, so no real hardware is needed and no system file is
touched.

Usage: python3 nvme_config_create_test.py <path-to-nvme-binary>
"""
import glob
import os
import shutil
import sys
import tempfile
import unittest

from nvme_test import TestNVMeBase

# Capture the nvme binary path from argv before unittest.main() strips it.
_NVME_BIN = sys.argv[1] \
    if len(sys.argv) > 1 and not sys.argv[1].startswith('-') \
    else 'nvme'


class ConfigCreateCLITest(TestNVMeBase):

    def setUp(self):
        super().setUp()
        self.nvme_bin = _NVME_BIN
        self.tmpdir = tempfile.mkdtemp(prefix='nvme-config-create-test-',
                                        dir='/tmp')
        self.output_ini = os.path.join(self.tmpdir, 'nvme-fabrics.conf')

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _run(self, *args, expect_fail=False):
        cmd = [self.nvme_bin] + list(args)
        result = self.run_cmd(cmd, shell=False)
        if expect_fail:
            self.assertNotEqual(result.returncode, 0,
                                f'Command {cmd} unexpectedly succeeded:\n'
                                f'{result.stdout}')
        else:
            self.assertEqual(result.returncode, 0,
                             f'Command {cmd} failed:\n{result.stderr}')
        return result

    def _create(self, *extra_args, expect_fail=False):
        return self._run('config', 'create', '--output', self.output_ini,
                         *extra_args, expect_fail=expect_fail)

    def _read_output(self):
        # A persona with an explicit hostnqn/hostid/host-symname lands in
        # its own <output>.d/NNN-persona.conf drop-in, not the main file;
        # only the default (no explicit identity) persona is written to
        # the main file itself. Concatenate both so assertions don't care
        # which.
        chunks = []
        if os.path.exists(self.output_ini):
            with open(self.output_ini) as f:
                chunks.append(f.read())
        for dropin in sorted(glob.glob(self.output_ini + '.d/*.conf')):
            with open(dropin) as f:
                chunks.append(f.read())
        return '\n'.join(chunks)

    # ------------------------------------------------------------------ #
    # happy path                                                          #
    # ------------------------------------------------------------------ #

    def test_create_discovery_controller_entry(self):
        self._create('--transport', 'fc',
                     '--traddr=nn-0x58ccf090c92006da:pn-0x58ccf091492806da',
                     '--host-traddr=nn-0x20000024ff7fa448:pn-0x21000024ff7fa448',
                     '--hostnqn=nqn.2014-08.org.nvmexpress:uuid:62a4ab74',
                     '--hostid=62a4ab74-1e18-11f1-8bb7-6c1ff71ba506',
                     '--discovery')
        content = self._read_output()
        self.assertIn('[Discovery Controller]', content)
        self.assertIn(
            'controller = transport=fc;'
            'traddr=nn-0x58ccf090c92006da:pn-0x58ccf091492806da;'
            'host-traddr=nn-0x20000024ff7fa448:pn-0x21000024ff7fa448',
            content)
        self.assertIn('hostnqn = nqn.2014-08.org.nvmexpress:uuid:62a4ab74',
                      content)
        self.assertIn('hostid = 62a4ab74-1e18-11f1-8bb7-6c1ff71ba506',
                      content)

    def test_create_io_controller_entry(self):
        self._create('--transport', 'tcp', '--traddr=192.168.1.20',
                     '--trsvcid=4420',
                     '--nqn=nqn.2024-01.com.example:data.vol1',
                     '--nr-io-queues=4')
        content = self._read_output()
        self.assertIn('[Subsystem]', content)
        self.assertIn('nqn = nqn.2024-01.com.example:data.vol1', content)
        self.assertIn('nr-io-queues = 4', content)
        self.assertIn(
            'controller = transport=tcp;traddr=192.168.1.20;trsvcid=4420',
            content)

    def test_host_symname_gets_own_dropin(self):
        self._create('--transport', 'tcp', '--traddr=192.168.1.21',
                     '--nqn=nqn.2024-01.com.example:data.vol2',
                     '--hostnqn=nqn.2014-08.org.nvmexpress:uuid:aaaa',
                     '--host-symname=lab-host-01')
        content = self._read_output()
        self.assertIn('hostsymname = lab-host-01', content)

    def test_discovery_persistent_flag_is_stored(self):
        self._create('--transport', 'fc',
                     '--traddr=nn-0x2:pn-0x2', '--discovery',
                     '--persistent')
        content = self._read_output()
        self.assertIn('[Discovery Controller]', content)
        self.assertIn('persistent = true', content)

    def test_persistent_flag_updates_existing_entry(self):
        self._create('--transport', 'fc',
                     '--traddr=nn-0x3:pn-0x3',
                     '--host-traddr=nn-0x4:pn-0x4', '--discovery')
        content = self._read_output()
        self.assertNotIn('persistent', content)

        self._create('--transport', 'fc',
                     '--traddr=nn-0x3:pn-0x3',
                     '--host-traddr=nn-0x4:pn-0x4', '--discovery',
                     '--persistent')
        content = self._read_output()
        self.assertEqual(content.count('[Discovery Controller]'), 1,
                         f'expected exactly one entry, got content:\n{content}')
        self.assertIn('persistent = true', content)

    def test_discovery_no_persistent_flag_is_stored(self):
        self._create('--transport', 'fc',
                     '--traddr=nn-0x8:pn-0x8', '--discovery',
                     '--no-persistent')
        content = self._read_output()
        self.assertIn('[Discovery Controller]', content)
        self.assertIn('persistent = false', content)

    def test_no_persistent_updates_existing_true_entry(self):
        self._create('--transport', 'fc',
                     '--traddr=nn-0xa:pn-0xa', '--discovery',
                     '--persistent')
        content = self._read_output()
        self.assertIn('persistent = true', content)

        self._create('--transport', 'fc',
                     '--traddr=nn-0xa:pn-0xa', '--discovery',
                     '--no-persistent')
        content = self._read_output()
        self.assertEqual(content.count('[Discovery Controller]'), 1,
                         f'expected exactly one entry, got content:\n{content}')
        self.assertIn('persistent = false', content)
        self.assertNotIn('persistent = true', content)

    def test_discovery_no_persistent_flag_is_stored(self):
        self._create('--transport', 'fc',
                     '--traddr=nn-0x8:pn-0x8', '--discovery',
                     '--no-persistent')
        content = self._read_output()
        self.assertIn('[Discovery Controller]', content)
        self.assertIn('persistent = false', content)

    def test_discovery_no_epcsd_flag_is_stored(self):
        self._create('--transport', 'fc',
                     '--traddr=nn-0x9:pn-0x9', '--discovery',
                     '--no-epcsd')
        content = self._read_output()
        self.assertIn('[Discovery Controller]', content)
        self.assertIn('epcsd = false', content)

    def test_no_persistent_updates_existing_true_entry(self):
        self._create('--transport', 'fc',
                     '--traddr=nn-0xa:pn-0xa', '--discovery',
                     '--persistent')
        content = self._read_output()
        self.assertIn('persistent = true', content)

        self._create('--transport', 'fc',
                     '--traddr=nn-0xa:pn-0xa', '--discovery',
                     '--no-persistent')
        content = self._read_output()
        self.assertEqual(content.count('[Discovery Controller]'), 1,
                         f'expected exactly one entry, got content:\n{content}')
        self.assertIn('persistent = false', content)
        self.assertNotIn('persistent = true', content)

    def test_second_create_preserves_first_entry(self):
        self._create('--transport', 'fc',
                     '--traddr=nn-0x1:pn-0x1', '--discovery')
        self._create('--transport', 'tcp', '--traddr=192.168.1.30',
                     '--nqn=nqn.2024-01.com.example:data.vol3')
        content = self._read_output()
        self.assertIn('[Discovery Controller]', content)
        self.assertIn('controller = transport=fc;traddr=nn-0x1:pn-0x1',
                      content)
        self.assertIn('[Subsystem]', content)
        self.assertIn('nqn = nqn.2024-01.com.example:data.vol3', content)

    def test_repeated_identical_create_is_idempotent(self):
        args = ('--transport', 'fc', '--traddr=nn-0x1:pn-0x1', '--discovery',
               '--hostnqn=nqn.2014-08.org.nvmexpress:uuid:aaaa',
               '--hostid=46ba5037-7ce5-41fa-9452-48477bf00080')
        self._create(*args)
        self._create(*args)
        self._create(*args)
        content = self._read_output()
        self.assertEqual(
            content.count(
                'controller = transport=fc;traddr=nn-0x1:pn-0x1'),
            1,
            f'expected exactly one entry, got content:\n{content}')

    # ------------------------------------------------------------------ #
    # errors                                                              #
    # ------------------------------------------------------------------ #

    def test_io_controller_without_nqn_errors(self):
        self._create('--transport', 'tcp', '--traddr=192.168.1.40',
                     expect_fail=True)
        self.assertFalse(os.path.exists(self.output_ini))

    def test_missing_traddr_errors(self):
        result = self._create('--transport', 'tcp', '--discovery',
                              expect_fail=True)
        self.assertFalse(os.path.exists(self.output_ini))

    def test_persistent_without_discovery_errors(self):
        self._create('--transport', 'tcp', '--traddr=192.168.1.41',
                     '--nqn=nqn.2024-01.com.example:data.vol4',
                     '--persistent', expect_fail=True)
        self.assertFalse(os.path.exists(self.output_ini))

    def test_epcsd_without_discovery_errors(self):
        self._create('--transport', 'tcp', '--traddr=192.168.1.42',
                     '--nqn=nqn.2024-01.com.example:data.vol5',
                     '--epcsd', expect_fail=True)
        self.assertFalse(os.path.exists(self.output_ini))

    def test_no_persistent_without_discovery_errors(self):
        self._create('--transport', 'tcp', '--traddr=192.168.1.43',
                     '--nqn=nqn.2024-01.com.example:data.vol6',
                     '--no-persistent', expect_fail=True)
        self.assertFalse(os.path.exists(self.output_ini))

    def test_no_epcsd_without_discovery_errors(self):
        self._create('--transport', 'tcp', '--traddr=192.168.1.44',
                     '--nqn=nqn.2024-01.com.example:data.vol7',
                     '--no-epcsd', expect_fail=True)
        self.assertFalse(os.path.exists(self.output_ini))

    def test_persistent_and_no_persistent_mutually_exclusive(self):
        self._create('--transport', 'fc', '--traddr=nn-0xb:pn-0xb',
                     '--discovery', '--persistent', '--no-persistent',
                     expect_fail=True)
        self.assertFalse(os.path.exists(self.output_ini))

    def test_epcsd_and_no_epcsd_mutually_exclusive(self):
        self._create('--transport', 'fc', '--traddr=nn-0xc:pn-0xc',
                     '--discovery', '--epcsd', '--no-epcsd',
                     expect_fail=True)
        self.assertFalse(os.path.exists(self.output_ini))


if __name__ == '__main__':
    # Remove the binary path from argv so unittest.main() doesn't see it.
    if len(sys.argv) >= 2 and not sys.argv[1].startswith('-'):
        del sys.argv[1]
    unittest.main()
