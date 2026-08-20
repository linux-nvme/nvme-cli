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
that only generate or validate key material: 'gen-kxchap-secret', 'gen-tls',
'check-kxchap-secret' and 'check-tls' without '--identity'/'--subsysnqn'. Those
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
    # gen-kxchap-secret                                                   #
    # ------------------------------------------------------------------ #

    def test_gen_kxchap_default_is_hmac_none(self):
        result = self._run('gen-kxchap-secret', '--secret=pin:1234')
        self.assertEqual(result.stdout.strip(), _PIN_KXCHAP_KEY)

    def test_gen_kxchap_same_pin_is_deterministic(self):
        first = self._run('gen-kxchap-secret', '--secret=pin:1234')
        second = self._run('gen-kxchap-secret', '--secret=pin:1234')
        self.assertEqual(first.stdout, second.stdout)

    def test_gen_kxchap_hmac_selects_default_secret_length(self):
        # HMAC 1/2/3 map to SHA-256/384/512, so an unspecified secret
        # length defaults to the matching 32/48/64 bytes. A secret of len
        # bytes plus a 4 byte CRC encodes to 4 * ceil((len + 4) / 3)
        # base64 characters.
        for hmac, secret_len in ((1, 32), (2, 48), (3, 64)):
            with self.subTest(hmac=hmac):
                result = self._run('gen-kxchap-secret', f'--hmac={hmac}')
                key = result.stdout.strip()
                self.assertTrue(key.startswith(f'DHHC-1:0{hmac}:'))
                self.assertEqual(len(key.split(':')[2]),
                                 4 * -(-(secret_len + 4) // 3))

    def test_gen_kxchap_secret_length_is_independent_of_hmac(self):
        # The hash identifier does not constrain the length of the secret,
        # so every length is valid with every hash identifier.
        for hmac in (0, 1, 2, 3):
            for secret_len in (32, 48, 64):
                with self.subTest(hmac=hmac, secret_len=secret_len):
                    result = self._run('gen-kxchap-secret', f'--hmac={hmac}',
                                       f'--secret-length={secret_len}')
                    self.assertEqual(len(result.stdout.strip().split(':')[2]),
                                     4 * -(-(secret_len + 4) // 3))

    def test_gen_kxchap_secret_sets_the_length(self):
        # A secret given as hex is the payload, so it fixes the length:
        # without '--secret-length' it must encode whole, not be truncated
        # to the digest-size default the generated case falls back to.
        for secret_len in (32, 48, 64):
            with self.subTest(secret_len=secret_len):
                secret = 'ab' * secret_len
                implied = self._run('gen-kxchap-secret', f'--secret={secret}')
                explicit = self._run('gen-kxchap-secret', f'--secret={secret}',
                                     f'--secret-length={secret_len}')
                self.assertEqual(implied.stdout, explicit.stdout)
                self.assertEqual(
                    len(implied.stdout.strip().split(':')[2]),
                    4 * -(-(secret_len + 4) // 3))

    def test_gen_kxchap_invalid_implied_secret_length_fails(self):
        # A hex secret of a length the format does not allow is rejected on
        # the implied path too, not passed on to be truncated or padded.
        self._run('gen-kxchap-secret', f'--secret={"ab" * 33}',
                  expect_fail=True)

    def test_gen_kxchap_odd_hex_secret_fails(self):
        # An odd number of hexadecimal characters is not a whole number of
        # bytes. nvme-cli 2.x padded the trailing nibble with a zero and
        # emitted a secret the caller never gave.
        self._run('gen-kxchap-secret', f'--secret={"ab" * 31 + "a"}',
                  expect_fail=True)

    def test_gen_kxchap_secret_length_must_match_the_secret(self):
        # The secret is the payload, so a length that contradicts it is an
        # error rather than a licence to truncate.
        self._run('gen-kxchap-secret', f'--secret={"ab" * 64}',
                  '--secret-length=32', expect_fail=True)

    def test_gen_kxchap_nqn_is_rejected(self):
        # The payload is the secret, which no NQN takes part in deriving,
        # so '--nqn' is gone rather than accepted and ignored.
        self._run('gen-kxchap-secret', '--secret=pin:1234', '--hmac=1',
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
    def test_check_dhchap_key_alias_takes_the_2x_key_option(self):
        # 2.x passed the secret in --key/-k and had no other option, while
        # the command this forwards to spells that --keydata and gives -k
        # to --keyring. Feed an empty stdin so a regression that loses the
        # secret fails here instead of blocking on a read.
        for form in (('-k', _PIN_KXCHAP_KEY), ('--key', _PIN_KXCHAP_KEY),
                     (f'--key={_PIN_KXCHAP_KEY}',)):
            with self.subTest(form=form):
                result = self._run_alias('check-dhchap-key', *form,
                                         stdin_data='')
                self.assertIn('Secret is valid', result.stdout)

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

    @unittest.skipUnless(_DEPRECATED_CMDS, 'built without deprecated commands')
    def test_gen_dhchap_key_alias_translates_key_length(self):
        # 2.x spelled the length '--key-length', which the command now
        # spells '--secret-length', so the alias has to rebuild it. Assert
        # on the payload rather than the exit status: an option silently
        # dropped in translation would still exit 0, at the default length.
        for key_len in (32, 48, 64):
            with self.subTest(key_len=key_len):
                result = self._run_alias('gen-dhchap-key',
                                         f'--key-length={key_len}')
                self.assertEqual(len(result.stdout.strip().split(':')[2]),
                                 4 * -(-(key_len + 4) // 3))

    def test_gen_kxchap_hmac_does_not_change_payload(self):
        # The payload is the secret; the hash identifier only records which
        # transformation the consumer is to apply, so the same secret must
        # encode to the same base64 string whichever one is selected.
        payload = _PIN_KXCHAP_KEY.split(':')[2]
        result = self._run('gen-kxchap-secret', '--secret=pin:1234',
                           '--hmac=1')
        self.assertEqual(result.stdout.strip(), f'DHHC-1:01:{payload}:')

    def test_gen_kxchap_invalid_hmac_fails(self):
        self._run('gen-kxchap-secret', '--hmac=9', expect_fail=True)

    def test_gen_kxchap_invalid_secret_length_fails(self):
        self._run('gen-kxchap-secret', '--secret-length=33', expect_fail=True)

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
    # check-kxchap-secret                                                 #
    # ------------------------------------------------------------------ #

    def test_check_kxchap_accepts_generated_key(self):
        result = self._run('check-kxchap-secret',
                           f'--keydata={_PIN_KXCHAP_KEY}')
        self.assertIn('Secret is valid', result.stdout)
        self.assertIn('HMAC 0', result.stdout)
        self.assertIn('length 32', result.stdout)

    def test_check_kxchap_accepts_every_generated_length(self):
        # gen and check apply the same length rule, so every pair gen
        # produces must survive the round trip, not just the 32 byte
        # default. The reported length is the secret's, not the digest
        # size the hash identifier names.
        for hmac in (0, 1, 2, 3):
            for secret_len in (32, 48, 64):
                with self.subTest(hmac=hmac, secret_len=secret_len):
                    gen = self._run('gen-kxchap-secret', f'--hmac={hmac}',
                                    f'--secret-length={secret_len}')
                    key = gen.stdout.strip()
                    result = self._run('check-kxchap-secret',
                                       f'--keydata={key}')
                    self.assertIn(f'HMAC {hmac}', result.stdout)
                    self.assertIn(f'length {secret_len}', result.stdout)

    def test_check_kxchap_reads_from_stdin(self):
        result = self._run('check-kxchap-secret',
                           stdin_data=_PIN_KXCHAP_KEY + '\n')
        self.assertIn('Secret is valid', result.stdout)

    def test_check_kxchap_rejects_malformed_key(self):
        result = self._run('check-kxchap-secret', '--keydata=not-a-key',
                           expect_fail=True)
        self.assertIn('Invalid secret header', result.stdout + result.stderr)

    def test_check_kxchap_rejects_tampered_key(self):
        # Flip the last character before the CRC to corrupt it while
        # keeping the string a valid-looking base64 header/length.
        tampered = _PIN_KXCHAP_KEY.replace('gajh:', 'gajj:')
        result = self._run('check-kxchap-secret', f'--keydata={tampered}',
                           expect_fail=True)
        self.assertIn('CRC mismatch', result.stdout + result.stderr)

    # ------------------------------------------------------------------ #
    # check-tls                                                           #
    # ------------------------------------------------------------------ #

    def test_check_tls_accepts_generated_key(self):
        result = self._run('check-tls', f'--keydata={_PIN_TLS_KEY}')
        self.assertIn('Configured PSK is valid', result.stdout)
        self.assertIn('HMAC 1', result.stdout)
        self.assertIn('length 32', result.stdout)

    def test_check_tls_reads_from_stdin(self):
        result = self._run('check-tls', stdin_data=_PIN_TLS_KEY + '\n')
        self.assertIn('Configured PSK is valid', result.stdout)

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
