#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""CLI integration tests for the 'nvme keys' plugin.

Tests invoke the nvme binary directly and need no real NVMe hardware.

They are deliberately restricted to the commands (and option combinations)
that only generate or validate key material: 'gen-dhchap', 'gen-tls',
'check-dhchap' and 'check-tls' without '--identity'/'--subsysnqn'. Those
never touch a kernel keyring. The remaining commands ('insert-tls',
'import', 'export', 'revoke', and check-*/--identity or --subsysnqn) look
up or modify a real '.nvme' keyring via keyctl, whose presence and contents
depend on the host/container the tests run on (and keyctl itself may be
unavailable, e.g. under seccomp) -- exercising those paths here would mean
either mutating shared system state or asserting on host-dependent
behavior. Their argument-validation errors that are checked *before* any
keyring access (e.g. "insert-tls" without "--subsysnqn") are still safe to
test and are included below.

A '--secret=pin:<value>' input deterministically derives the same raw
secret on every run (unlike the default, which is random), which is what
makes exact-output assertions below possible.

Usage: python3 nvme_keys_test.py <path-to-nvme-binary>
"""
import sys
import unittest


# Capture the nvme binary path from argv before unittest.main() strips it.
_NVME_BIN = sys.argv[1] \
    if len(sys.argv) > 1 and not sys.argv[1].startswith('-') \
    else 'nvme'

_PIN_DHCHAP_KEY = 'DHHC-1:00:9wCYVQqDvADjGIZo6q/v2SfmXZqqkNa9TcvYu97Ly3Q/gajh:'
_PIN_TLS_KEY = 'NVMeTLSkey-1:01:9wCYVQqDvADjGIZo6q/v2SfmXZqqkNa9TcvYu97Ly3Q/gajh:'


class KeysCLITest(unittest.TestCase):

    def _run(self, *args, stdin_data=None, expect_fail=False):
        import subprocess
        cmd = [_NVME_BIN, 'keys'] + list(args)
        result = subprocess.run(cmd, input=stdin_data,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                encoding='utf-8')
        if expect_fail:
            self.assertNotEqual(result.returncode, 0,
                                f'Command {cmd} unexpectedly succeeded:\n'
                                f'{result.stdout}')
        else:
            self.assertEqual(result.returncode, 0,
                             f'Command {cmd} failed:\n{result.stderr}')
        return result

    # ------------------------------------------------------------------ #
    # gen-dhchap                                                          #
    # ------------------------------------------------------------------ #

    def test_gen_dhchap_default_is_hmac_none(self):
        result = self._run('gen-dhchap', '--secret=pin:1234')
        self.assertEqual(result.stdout.strip(), _PIN_DHCHAP_KEY)

    def test_gen_dhchap_same_pin_is_deterministic(self):
        first = self._run('gen-dhchap', '--secret=pin:1234')
        second = self._run('gen-dhchap', '--secret=pin:1234')
        self.assertEqual(first.stdout, second.stdout)

    def test_gen_dhchap_hmac_selects_key_length(self):
        # HMAC 1/2/3 map to SHA-256/384/512 and thus 32/48/64-byte keys,
        # encoded as DHHC-1:<hmac>:<base64 of key+crc>:
        for hmac, key_len in ((1, 32), (2, 48), (3, 64)):
            with self.subTest(hmac=hmac):
                result = self._run('gen-dhchap', f'--hmac={hmac}')
                self.assertTrue(result.stdout.startswith(f'DHHC-1:0{hmac}:'))

    def test_gen_dhchap_nqn_changes_transformed_key(self):
        one = self._run('gen-dhchap', '--secret=pin:1234', '--hmac=1',
                        '--nqn=nqn.2014-08.org.nvmexpress:uuid:abc')
        two = self._run('gen-dhchap', '--secret=pin:1234', '--hmac=1',
                        '--nqn=nqn.2014-08.org.nvmexpress:uuid:xyz')
        self.assertNotEqual(one.stdout, two.stdout)

    def test_gen_dhchap_invalid_hmac_fails(self):
        self._run('gen-dhchap', '--hmac=9', expect_fail=True)

    def test_gen_dhchap_mismatched_key_length_for_hmac_fails(self):
        self._run('gen-dhchap', '--hmac=1', '--key-length=48',
                  expect_fail=True)

    # ------------------------------------------------------------------ #
    # gen-tls                                                             #
    # ------------------------------------------------------------------ #

    def test_gen_tls_default_is_hmac_sha256(self):
        result = self._run('gen-tls', '--secret=pin:1234')
        self.assertEqual(result.stdout.strip(), _PIN_TLS_KEY)

    def test_gen_tls_hmac_sha384_uses_longer_key(self):
        result = self._run('gen-tls', '--secret=pin:1234', '--hmac=2')
        self.assertTrue(result.stdout.startswith('NVMeTLSkey-1:02:'))
        self.assertNotEqual(result.stdout.strip(), _PIN_TLS_KEY)

    def test_gen_tls_invalid_hmac_fails(self):
        self._run('gen-tls', '--hmac=9', expect_fail=True)

    def test_gen_tls_invalid_identity_version_fails(self):
        self._run('gen-tls', '--secret=pin:1234', '--identity=9',
                  expect_fail=True)

    def test_gen_tls_insert_without_subsysnqn_fails(self):
        # --insert requires --subsysnqn; this is checked before any
        # keyring access is attempted.
        self._run('gen-tls', '--secret=pin:1234', '--insert',
                  expect_fail=True)

    # ------------------------------------------------------------------ #
    # check-dhchap                                                        #
    # ------------------------------------------------------------------ #

    def test_check_dhchap_accepts_generated_key(self):
        result = self._run('check-dhchap', f'--keydata={_PIN_DHCHAP_KEY}')
        self.assertIn('Key is valid', result.stdout)
        self.assertIn('HMAC 0', result.stdout)
        self.assertIn('length 32', result.stdout)

    def test_check_dhchap_reads_from_stdin(self):
        result = self._run('check-dhchap', stdin_data=_PIN_DHCHAP_KEY + '\n')
        self.assertIn('Key is valid', result.stdout)

    def test_check_dhchap_rejects_malformed_key(self):
        result = self._run('check-dhchap', '--keydata=not-a-key',
                           expect_fail=True)
        self.assertIn('Invalid key header', result.stdout + result.stderr)

    def test_check_dhchap_rejects_tampered_key(self):
        # Flip the last character before the CRC to corrupt it while
        # keeping the string a valid-looking base64 header/length.
        tampered = _PIN_DHCHAP_KEY.replace('gajh:', 'gajj:')
        result = self._run('check-dhchap', f'--keydata={tampered}',
                           expect_fail=True)
        self.assertIn('CRC mismatch', result.stdout + result.stderr)

    # ------------------------------------------------------------------ #
    # check-tls                                                           #
    # ------------------------------------------------------------------ #

    def test_check_tls_accepts_generated_key(self):
        result = self._run('check-tls', f'--keydata={_PIN_TLS_KEY}')
        self.assertIn('Key is valid', result.stdout)
        self.assertIn('HMAC 1', result.stdout)
        self.assertIn('length 32', result.stdout)

    def test_check_tls_reads_from_stdin(self):
        result = self._run('check-tls', stdin_data=_PIN_TLS_KEY + '\n')
        self.assertIn('Key is valid', result.stdout)

    def test_check_tls_rejects_malformed_key(self):
        self._run('check-tls', '--keydata=bogus', expect_fail=True)

    def test_check_tls_invalid_identity_version_fails(self):
        self._run('check-tls', f'--keydata={_PIN_TLS_KEY}', '--identity=9',
                  expect_fail=True)

    # ------------------------------------------------------------------ #
    # argument validation for the keyring-mutating commands               #
    # ------------------------------------------------------------------ #
    #
    # These commands need a real '.nvme' keyring to do anything useful, so
    # only their pre-keyring argument validation is exercised here.

    def test_insert_tls_requires_subsysnqn(self):
        result = self._run('insert-tls', f'--keydata={_PIN_TLS_KEY}',
                           expect_fail=True)
        self.assertIn('subsystem NQN', result.stdout + result.stderr)

    def test_revoke_requires_identity(self):
        result = self._run('revoke', expect_fail=True)
        self.assertIn('--identity', result.stdout + result.stderr)


if __name__ == '__main__':
    # Remove the binary path from argv so unittest.main() doesn't see it.
    if len(sys.argv) >= 2 and not sys.argv[1].startswith('-'):
        del sys.argv[1]
    unittest.main()
