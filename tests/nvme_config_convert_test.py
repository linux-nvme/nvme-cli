#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
"""CLI integration tests for 'nvme config-convert'.

Tests invoke the nvme binary directly with an explicit --config file and
--output under a temporary directory, so no real hardware is needed and no
system file is touched by the --config/--output path itself.

discovery.conf conversion is deliberately NOT exercised here: its path is
hardcoded to SYSCONFDIR/nvme/discovery.conf with no override (--config only
ever affects config.json), so it cannot be sandboxed the way --config/
--output can. Its parsing logic (nvme_config_convert_discovery()) should be
covered separately, e.g. as a C unit test that calls it directly against a
temp file. Because the real discovery.conf is always converted (and renamed)
when it exists, this whole suite skips itself if one is present on the
machine running the tests -- a config-convert invocation must never rename a
developer's real discovery.conf as a side effect of running the test suite.

Usage: python3 nvme_config_convert_test.py <path-to-nvme-binary>
"""
import glob
import json
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

_REAL_DISCOVERY_CONF = '/etc/nvme/discovery.conf'


@unittest.skipIf(os.path.exists(_REAL_DISCOVERY_CONF),
                  f'{_REAL_DISCOVERY_CONF} exists on this machine; '
                  'config-convert always converts and renames it, so '
                  'skipping to avoid touching real system configuration')
class ConfigConvertCLITest(TestNVMeBase):

    def setUp(self):
        super().setUp()
        self.nvme_bin = _NVME_BIN
        self.tmpdir = tempfile.mkdtemp(prefix='nvme-config-convert-test-',
                                        dir='/tmp')
        self.config_json = os.path.join(self.tmpdir, 'config.json')
        self.output_ini = os.path.join(self.tmpdir, 'nvme-fabrics.conf')

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_json(self, obj):
        with open(self.config_json, 'w') as f:
            json.dump(obj, f)

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

    def _convert(self, *extra_args, expect_fail=False):
        return self._run('config-convert', '--config', self.config_json,
                         '--output', self.output_ini, *extra_args,
                         expect_fail=expect_fail)

    def _read_output(self):
        # A persona with an explicit hostnqn/hostid lands in its own
        # <output>.d/NNN-persona.conf drop-in, not the main file; only the
        # default (no explicit identity) persona is written to the main
        # file itself. Concatenate both so assertions don't care which.
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

    def test_convert_dc_and_subsystem(self):
        self._write_json({
            'hosts': [{
                'hostnqn': 'nqn.2014-08.org.nvmexpress:uuid:1111',
                'hostid': '46ba5037-7ce5-41fa-9452-48477bf00080',
                'hostsymname': 'lab-host-01',
                'subsystems': [
                    {
                        'nqn': 'nqn.2014-08.org.nvmexpress.discovery',
                        'ports': [{
                            'transport': 'tcp',
                            'traddr': '192.168.1.10',
                            'trsvcid': '8009',
                            'discovery': True,
                        }],
                    },
                    {
                        'nqn': 'nqn.2024-01.com.example:data.vol1',
                        'ports': [{
                            'transport': 'tcp',
                            'traddr': '192.168.1.20',
                            'trsvcid': '4420',
                            'nr_io_queues': 4,
                        }],
                    },
                ],
            }],
        })
        self._convert()
        content = self._read_output()
        self.assertIn('[Host]', content)
        self.assertIn('hostnqn = nqn.2014-08.org.nvmexpress:uuid:1111',
                      content)
        self.assertIn('hostid = 46ba5037-7ce5-41fa-9452-48477bf00080',
                      content)
        self.assertIn('hostsymname = lab-host-01', content)
        self.assertIn('[Discovery Controller]', content)
        self.assertIn(
            'controller = transport=tcp;traddr=192.168.1.10;trsvcid=8009',
            content)
        self.assertIn('[Subsystem]', content)
        self.assertIn('nqn = nqn.2024-01.com.example:data.vol1', content)
        self.assertIn('nr-io-queues = 4', content)
        self.assertIn(
            'controller = transport=tcp;traddr=192.168.1.20;trsvcid=4420',
            content)
        # The well-known discovery NQN is omitted, not written literally.
        self.assertNotIn('nqn = nqn.2014-08.org.nvmexpress.discovery',
                         content)

    def test_convert_legacy_bare_array_format(self):
        self._write_json([{
            'hostnqn': 'nqn.2014-08.org.nvmexpress:uuid:2222',
            'subsystems': [{
                'nqn': 'nqn.2024-01.com.example:data.vol2',
                'ports': [{
                    'transport': 'tcp',
                    'traddr': '10.0.0.5',
                }],
            }],
        }])
        self._convert()
        content = self._read_output()
        self.assertIn('hostnqn = nqn.2014-08.org.nvmexpress:uuid:2222',
                      content)
        self.assertIn('nqn = nqn.2024-01.com.example:data.vol2', content)

    def test_dhchap_default_inherited_by_port(self):
        self._write_json({
            'hosts': [{
                'hostnqn': 'nqn.2014-08.org.nvmexpress:uuid:3333',
                'dhchap_key': 'DHHC-1:00:host-default-key:',
                'subsystems': [{
                    'nqn': 'nqn.2024-01.com.example:data.vol3',
                    'ports': [{
                        'transport': 'tcp',
                        'traddr': '10.0.0.6',
                    }],
                }],
            }],
        })
        self._convert()
        content = self._read_output()
        self.assertIn('dhchap-secret = DHHC-1:00:host-default-key:', content)

    def test_dhchap_port_value_overrides_default(self):
        self._write_json({
            'hosts': [{
                'hostnqn': 'nqn.2014-08.org.nvmexpress:uuid:4444',
                'dhchap_key': 'DHHC-1:00:host-default-key:',
                'subsystems': [{
                    'nqn': 'nqn.2024-01.com.example:data.vol4',
                    'ports': [{
                        'transport': 'tcp',
                        'traddr': '10.0.0.7',
                        'dhchap_key': 'DHHC-1:00:port-specific-key:',
                    }],
                }],
            }],
        })
        self._convert()
        content = self._read_output()
        self.assertIn('dhchap-secret = DHHC-1:00:port-specific-key:', content)
        self.assertNotIn('DHHC-1:00:host-default-key:', content)

    # ------------------------------------------------------------------ #
    # errors                                                              #
    # ------------------------------------------------------------------ #

    def test_missing_explicit_config_file_errors(self):
        missing = os.path.join(self.tmpdir, 'does-not-exist.json')
        self._run('config-convert', '--config', missing,
                  '--output', self.output_ini, expect_fail=True)
        self.assertFalse(os.path.exists(self.output_ini))

    def test_malformed_json_errors(self):
        with open(self.config_json, 'w') as f:
            f.write('{not valid json')
        self._convert(expect_fail=True)
        self.assertFalse(os.path.exists(self.output_ini))

    def test_missing_hosts_array_errors(self):
        self._write_json({'not-hosts': []})
        self._convert(expect_fail=True)
        self.assertFalse(os.path.exists(self.output_ini))

    # ------------------------------------------------------------------ #
    # output / force / rename                                             #
    # ------------------------------------------------------------------ #

    def test_refuses_to_overwrite_existing_output_without_force(self):
        self._write_json({'hosts': []})
        with open(self.output_ini, 'w') as f:
            f.write('preexisting content\n')
        self._convert(expect_fail=True)
        with open(self.output_ini) as f:
            self.assertEqual(f.read(), 'preexisting content\n')

    def test_force_overwrites_existing_output(self):
        self._write_json({
            'hosts': [{
                'subsystems': [{
                    'nqn': 'nqn.2024-01.com.example:data.vol5',
                    'ports': [{'transport': 'tcp', 'traddr': '10.0.0.8'}],
                }],
            }],
        })
        with open(self.output_ini, 'w') as f:
            f.write('preexisting content\n')
        self._convert('--force')
        content = self._read_output()
        self.assertIn('nqn = nqn.2024-01.com.example:data.vol5', content)

    def test_source_file_renamed_to_converted_on_success(self):
        self._write_json({'hosts': []})
        self._convert()
        self.assertFalse(os.path.exists(self.config_json))
        self.assertTrue(os.path.exists(self.config_json + '.converted'))

    def test_rerun_after_conversion_is_idempotent(self):
        # A second run with the same --config, after config.json was
        # already renamed to config.json.converted, must not choke on
        # the source file being gone -- it was already converted, not
        # missing. --force sidesteps the (unrelated) "output already
        # exists" refusal so this test isolates just that behavior.
        self._write_json({'hosts': []})
        self._convert()
        result = self._convert('--force')
        self.assertNotIn('failed to parse', result.stderr)


if __name__ == '__main__':
    # Remove the binary path from argv so unittest.main() doesn't see it.
    if len(sys.argv) >= 2 and not sys.argv[1].startswith('-'):
        del sys.argv[1]
    unittest.main()
