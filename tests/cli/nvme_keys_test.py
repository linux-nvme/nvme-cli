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
that only generate or validate key material: 'gen-kxchap', 'gen-tls',
'check-kxchap' and 'check-tls' without '--identity'/'--subsysnqn'. Those
never touch a kernel keyring. The remaining commands ('insert-tls',
'import', 'export', 'revoke', and check-*/--identity or --subsysnqn) look
up or modify a real '.nvme' keyring via keyctl, whose presence and contents
depend on the host/container the tests run on (and keyctl itself may be
unavailable, e.g. under seccomp) -- exercising those paths here would mean
either mutating shared system state or asserting on host-dependent
behavior. Their argument-validation errors that are checked *before* any
keyring access (e.g. "insert-tls" without "--subsysnqn") are still safe to
test and are included below.

The deprecated top-level aliases ('nvme gen-dhchap-key' and friends) are
out of scope with one exception: where an alias does something of its own
rather than forwarding argv unchanged, that behavior is covered here. They
are compiled in only with '-Ddeprecated-cmds=enabled', so those tests skip
themselves when the binary under test has no such command.

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


def _has_deprecated_cmds():
    """The deprecated aliases need -Ddeprecated-cmds=enabled to exist."""
    import subprocess
    result = subprocess.run([_NVME_BIN, 'help'],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            encoding='utf-8')
    return 'gen-dhchap-key' in result.stdout + result.stderr


_DEPRECATED_CMDS = _has_deprecated_cmds()

_PIN_KXCHAP_KEY = 'DHHC-1:00:9wCYVQqDvADjGIZo6q/v2SfmXZqqkNa9TcvYu97Ly3Q/gajh:'
_PIN_TLS_KEY = 'NVMeTLSkey-1:01:9wCYVQqDvADjGIZo6q/v2SfmXZqqkNa9TcvYu97Ly3Q/gajh:'
_HOST_NQN = 'nqn.2014-08.org.nvmexpress:uuid:abc'
# The alias prints this when it drops '--nqn'. Matching the option
# name alone would also hit the getopt error listing it as a
# candidate, and the help text naming it.
_NQN_IGNORED = "'--nqn' is ignored"


class KeysCLITest(unittest.TestCase):

    def _exec(self, cmd, stdin_data=None, expect_fail=False):
        import subprocess
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

    def _run(self, *args, stdin_data=None, expect_fail=False):
        return self._exec([_NVME_BIN, 'keys'] + list(args),
                          stdin_data, expect_fail)

    def _run_alias(self, *args, stdin_data=None, expect_fail=False):
        """Run a deprecated top-level command, not the 'keys' plugin."""
        return self._exec([_NVME_BIN] + list(args), stdin_data, expect_fail)

    # ------------------------------------------------------------------ #
    # gen-kxchap                                                          #
    # ------------------------------------------------------------------ #

    def test_gen_kxchap_default_is_hmac_none(self):
        result = self._run('gen-kxchap', '--secret=pin:1234')
        self.assertEqual(result.stdout.strip(), _PIN_KXCHAP_KEY)

    def test_gen_kxchap_same_pin_is_deterministic(self):
        first = self._run('gen-kxchap', '--secret=pin:1234')
        second = self._run('gen-kxchap', '--secret=pin:1234')
        self.assertEqual(first.stdout, second.stdout)

    def test_gen_kxchap_hmac_selects_key_length(self):
        # HMAC 1/2/3 map to SHA-256/384/512 and thus 32/48/64-byte keys,
        # encoded as DHHC-1:<hmac>:<base64 of key+crc>:
        for hmac, key_len in ((1, 32), (2, 48), (3, 64)):
            with self.subTest(hmac=hmac):
                result = self._run('gen-kxchap', f'--hmac={hmac}')
                self.assertTrue(result.stdout.startswith(f'DHHC-1:0{hmac}:'))

    def test_gen_kxchap_nqn_is_rejected(self):
        # The payload is the secret, which no NQN takes part in deriving,
        # so '--nqn' is gone rather than accepted and ignored.
        self._run('gen-kxchap', '--secret=pin:1234', '--hmac=1',
                  '--nqn=nqn.2014-08.org.nvmexpress:uuid:abc',
                  expect_fail=True)

    @unittest.skipUnless(_DEPRECATED_CMDS, 'built without deprecated commands')
    def test_gen_dhchap_key_alias_drops_nqn(self):
        # Every spelling nvme-cli 2.x accepted for the host NQN: one or two
        # dashes before a prefix of 'nqn' that stayed unambiguous against
        # the global --no-retries, with the value as the next argument,
        # attached by '=', or attached bare to the short option. The
        # trailing '--hmac=1' must survive, so a consumed value cannot
        # have swallowed the option after it.
        forms = [(s, _HOST_NQN)
                 for s in ('-n', '-nq', '-nqn', '--nq', '--nqn')]
        forms += [(f'{s}={_HOST_NQN}',)
                  for s in ('-nq', '-nqn', '--nq', '--nqn')]
        forms += [(f'-n{_HOST_NQN}',)]      # short option, value attached

        expected = self._run_alias('gen-dhchap-key', '--secret=pin:1234',
                                   '--hmac=1')
        for form in forms:
            with self.subTest(form=form):
                result = self._run_alias('gen-dhchap-key',
                                         '--secret=pin:1234', *form,
                                         '--hmac=1')
                self.assertEqual(result.stdout, expected.stdout)
                self.assertIn(_NQN_IGNORED, result.stderr)

    @unittest.skipUnless(_DEPRECATED_CMDS, 'built without deprecated commands')
    def test_gen_dhchap_key_alias_keeps_2x_rejections(self):
        # '--n' was ambiguous with --no-retries even in 2.x, and so were
        # '-n=<nqn>' and '--n=<nqn>'. Keep rejecting them rather than
        # accepting more than the command ever did.
        for form in (('--n', _HOST_NQN), (f'-n={_HOST_NQN}',),
                     (f'--n={_HOST_NQN}',)):
            with self.subTest(form=form):
                result = self._run_alias('gen-dhchap-key',
                                         '--secret=pin:1234', *form,
                                         expect_fail=True)
                self.assertNotIn(_NQN_IGNORED, result.stderr)

    @unittest.skipUnless(_DEPRECATED_CMDS, 'built without deprecated commands')
    def test_gen_dhchap_key_alias_keeps_other_options(self):
        # Dropping '--nqn' must not swallow the global options that also
        # start with an 'n', which getopt_long_only() accepts with a
        # single dash.
        for opt in ('-no-retries', '--no-retries', '--no-ioctl-probing'):
            with self.subTest(opt=opt):
                result = self._run_alias('gen-dhchap-key',
                                         '--secret=pin:1234', opt)
                self.assertEqual(result.stdout.strip(), _PIN_KXCHAP_KEY)
                self.assertNotIn(_NQN_IGNORED, result.stderr)

    def test_gen_kxchap_hmac_does_not_change_payload(self):
        # The payload is the secret; the hash identifier only records which
        # transformation the consumer is to apply, so the same secret must
        # encode to the same base64 string whichever one is selected.
        payload = _PIN_KXCHAP_KEY.split(':')[2]
        result = self._run('gen-kxchap', '--secret=pin:1234', '--hmac=1')
        self.assertEqual(result.stdout.strip(), f'DHHC-1:01:{payload}:')

    def test_gen_kxchap_invalid_hmac_fails(self):
        self._run('gen-kxchap', '--hmac=9', expect_fail=True)

    def test_gen_kxchap_mismatched_key_length_for_hmac_fails(self):
        self._run('gen-kxchap', '--hmac=1', '--key-length=48',
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
    # check-kxchap                                                        #
    # ------------------------------------------------------------------ #

    def test_check_kxchap_accepts_generated_key(self):
        result = self._run('check-kxchap', f'--keydata={_PIN_KXCHAP_KEY}')
        self.assertIn('Key is valid', result.stdout)
        self.assertIn('HMAC 0', result.stdout)
        self.assertIn('length 32', result.stdout)

    def test_check_kxchap_reads_from_stdin(self):
        result = self._run('check-kxchap', stdin_data=_PIN_KXCHAP_KEY + '\n')
        self.assertIn('Key is valid', result.stdout)

    def test_check_kxchap_rejects_malformed_key(self):
        result = self._run('check-kxchap', '--keydata=not-a-key',
                           expect_fail=True)
        self.assertIn('Invalid key header', result.stdout + result.stderr)

    def test_check_kxchap_rejects_tampered_key(self):
        # Flip the last character before the CRC to corrupt it while
        # keeping the string a valid-looking base64 header/length.
        tampered = _PIN_KXCHAP_KEY.replace('gajh:', 'gajj:')
        result = self._run('check-kxchap', f'--keydata={tampered}',
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
