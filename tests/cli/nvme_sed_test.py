#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for the sed plugin (plugins/sed/) and the libnvme sed module
it uses. Level 0 Discovery is answered as an admin passthru Security
Receive. The Opal operations are kernel ioctls, which libmock_nvme.c
forwards raw. The test decodes their arguments and checks them.

Usage: python3 nvme_sed_test.py <path-to-nvme-binary> <path-to-mock-lib>
"""
import errno
import os
import shutil
import struct
import sys
import tempfile
import unittest

from nvme_mock_ipc import (IOC_WRITE, MockIPCServer, make_mock_env,
                           resolve_mock_lib_path, run_nvme)

_NVME_BIN = (sys.argv[1]
             if len(sys.argv) > 1 and not sys.argv[1].startswith('-')
             else 'nvme')
_MOCK_LIB = resolve_mock_lib_path("./libmock_nvme.so")

# Opal ioctls missing from older linux/sed-opal.h. libnvme returns
# -ENOTSUP for them. Unset means all of them are available.
_OPTIONAL_IOCTLS = ('PSID_REVERT_TPR', 'REVERT_LSP', 'SET_SID_PW')
_SED_IOCTLS = set(os.environ.get('NVME_SED_IOCTLS',
                                 ','.join(_OPTIONAL_IOCTLS)).split(','))


def _requires_ioctl(name):
    return unittest.skipUnless(name in _SED_IOCTLS,
                               f'IOC_OPAL_{name} not in linux/sed-opal.h')

_NVME_OPCODE_SECURITY_RECV = 0x82
_NVME_SC_INVALID_FIELD = 0x2

# TCG Level 0 Discovery
_TCG_L0_SECP = 0x01
_TCG_L0_COMID = 0x0001
_TCG_L0_CODE_TPER = 0x0001
_TCG_L0_CODE_LOCKING = 0x0002
_TCG_L0_CODE_OPAL_V2 = 0x0203

_LOCKING_SUPPORTED = 1 << 0
_LOCKING_ENABLED = 1 << 1
_LOCKING_LOCKED = 1 << 2

_TCG_NOT_AUTHORIZED = 0x01

# linux/sed-opal.h: _IOW('p', nr, ...)
_OPAL_IOC_TYPE = ord('p')
_IOC_OPAL = {
    221: 'LOCK_UNLOCK',
    222: 'TAKE_OWNERSHIP',
    223: 'ACTIVATE_LSP',
    224: 'SET_PW',
    226: 'REVERT_TPR',
    227: 'LR_SETUP',
    232: 'PSID_REVERT_TPR',
    240: 'REVERT_LSP',
    241: 'SET_SID_PW',
}

# linux/fs.h: BLKRRPART _IO(0x12, 95)
_BLK_IOC_TYPE = 0x12
_BLKRRPART_NR = 95

_OPAL_ADMIN1 = 0
_OPAL_INCLUDED = 0
_OPAL_RO = 0x01
_OPAL_RW = 0x02
_OPAL_LK = 0x04
_OPAL_PRESERVE = 0x01

_OPAL_KEY_FMT = "BBB5x256s"
_OPAL_SESSION_FMT = "II" + _OPAL_KEY_FMT

_PASSWORD = "password1"
_NEW_PASSWORD = "password2"
_PSID = "0123456789ABCDEF0123456789ABCDEF"


def _pack_l0(locking_features, tper_only=False):
    """Pack a Level 0 Discovery response: TPer, Locking and Opal SSC V2
    feature descriptors, or only the TPer one. All fields are big-endian.
    The header length excludes the length field itself."""
    descs = struct.pack(">HBB12x", _TCG_L0_CODE_TPER, 0x10, 12)
    if not tper_only:
        descs += struct.pack(">HBBB11x", _TCG_L0_CODE_LOCKING, 0x10, 12,
                             locking_features)
        descs += struct.pack(">HBBHH12x", _TCG_L0_CODE_OPAL_V2, 0x10, 16,
                             0x1000, 1)
    hdr = struct.pack(">II8x32x", 48 + len(descs) - 4, 1)
    return hdr + descs


def _pack_l0_truncated():
    """Pack a Level 0 Discovery response whose Locking and Opal SSC V2
    descriptors have a data length of 0."""
    descs = struct.pack(">HBB12x", _TCG_L0_CODE_TPER, 0x10, 12)
    descs += struct.pack(">HBB", _TCG_L0_CODE_LOCKING, 0x10, 0)
    descs += struct.pack(">HBB", _TCG_L0_CODE_OPAL_V2, 0x10, 0)
    hdr = struct.pack(">II8x32x", 48 + len(descs) - 4, 1)
    return hdr + descs


def _unpack_key(fields):
    lr, key_len, key_type, key = fields
    return {'lr': lr, 'key_len': key_len, 'key_type': key_type,
            'key': key[:key_len].decode()}


def _unpack_session(fields):
    return {'sum': fields[0], 'who': fields[1],
            'key': _unpack_key(fields[2:6])}


def _decode_opal(name, bo, payload):
    """Decode the argument of an Opal ioctl into a dict."""
    if name in ('TAKE_OWNERSHIP', 'REVERT_TPR', 'PSID_REVERT_TPR'):
        return _unpack_key(struct.unpack(bo + _OPAL_KEY_FMT, payload))
    if name == 'ACTIVATE_LSP':
        f = struct.unpack(bo + _OPAL_KEY_FMT + "IB9s2x", payload)
        return {'key': _unpack_key(f[0:4]), 'sum': f[4],
                'num_lrs': f[5], 'lr': list(f[6])}
    if name == 'LR_SETUP':
        f = struct.unpack(bo + "QQII" + _OPAL_SESSION_FMT, payload)
        return {'range_start': f[0], 'range_length': f[1],
                'RLE': f[2], 'WLE': f[3], 'session': _unpack_session(f[4:])}
    if name == 'LOCK_UNLOCK':
        f = struct.unpack(bo + _OPAL_SESSION_FMT + "IH2x", payload)
        return {'session': _unpack_session(f[0:6]), 'l_state': f[6],
                'flags': f[7]}
    if name in ('SET_PW', 'SET_SID_PW'):
        f = struct.unpack(bo + _OPAL_SESSION_FMT + _OPAL_SESSION_FMT,
                          payload)
        return {'session': _unpack_session(f[0:6]),
                'new_user_pw': _unpack_session(f[6:12])}
    if name == 'REVERT_LSP':
        f = struct.unpack(bo + _OPAL_KEY_FMT + "II", payload)
        return {'key': _unpack_key(f[0:4]), 'options': f[4]}
    raise AssertionError(f"no decoder for {name}")


class SEDMockIPCServer(MockIPCServer):

    def __init__(self, sock_path):
        super().__init__(sock_path)
        self.l0 = _pack_l0(_LOCKING_SUPPORTED)
        self.l0_sc_status = 0
        self.passwords = []
        self.prompts = []
        # ioctl name -> ioctl() return value, or -errno
        self.ioctl_status = {}
        self.ioctls = []

    def handle_ioctl(self, conn, fd, request, opcode, nsid,
                     cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, lpo, req_len):
        secp = cdw10 >> 24
        spsp = (cdw10 >> 8) & 0xffff
        if (opcode == _NVME_OPCODE_SECURITY_RECV and
                secp == _TCG_L0_SECP and spsp == _TCG_L0_COMID):
            if self.l0_sc_status:
                self.send_response(conn, 0, sc_status=self.l0_sc_status)
            else:
                self.send_response(conn, 0, payload=self.l0[:req_len])
        else:
            self.send_response(conn, 0)

    def _respond(self, conn, name):
        status = self.ioctl_status.get(name, 0)
        if status < 0:
            self.send_response(conn, -1, errno_val=-status)
        else:
            self.send_response(conn, 0, sc_status=status)

    def handle_raw_ioctl(self, conn, fd, ioc, payload):
        if ioc.type == _OPAL_IOC_TYPE and ioc.nr in _IOC_OPAL:
            name = _IOC_OPAL[ioc.nr]
            if not ioc.dir & IOC_WRITE or len(payload) != ioc.size:
                raise AssertionError(f"{name}: bad argument {ioc}")
            self.ioctls.append(
                (name, _decode_opal(name, ioc.byte_order(), payload)))
            self._respond(conn, name)
        elif ioc.type == _BLK_IOC_TYPE and ioc.nr == _BLKRRPART_NR:
            self.ioctls.append(('BLKRRPART', None))
            self._respond(conn, 'BLKRRPART')
        else:
            super().handle_raw_ioctl(conn, fd, ioc, payload)

    def handle_getpass(self, conn, prompt):
        self.prompts.append(prompt)
        if not self.passwords:
            self.send_response(conn, -1, errno_val=errno.ENOTTY)
            return
        self.send_response(conn, 0, payload=self.passwords.pop(0).encode())


class SEDCLITest(unittest.TestCase):

    DEVICE = '/dev/nvme0n1'

    def setUp(self):
        self.sysfs_dir = tempfile.mkdtemp(prefix='nvme-sed-sysfs-', dir='/tmp')
        self.base_dir = tempfile.mkdtemp(prefix='nvme-sed-base-', dir='/tmp')
        self.ipc_dir = tempfile.mkdtemp(prefix='nvme-sed-ipc-', dir='/tmp')
        self.ipc_sock_path = os.path.join(self.ipc_dir, "ipc.sock")

        self.server = SEDMockIPCServer(self.ipc_sock_path)
        self.server.start()

        self.env = make_mock_env(_MOCK_LIB, self.ipc_sock_path)

    def tearDown(self):
        self.server.shutdown()
        self.server.join()

        shutil.rmtree(self.sysfs_dir, ignore_errors=True)
        shutil.rmtree(self.base_dir, ignore_errors=True)
        shutil.rmtree(self.ipc_dir, ignore_errors=True)

    def _sed(self, *args, expect_fail=False, stdin_data=None):
        result = run_nvme(_NVME_BIN, self.env, self.sysfs_dir, self.base_dir,
                          'sed', args[0], self.DEVICE, *args[1:],
                          stdin_data=stdin_data)
        if expect_fail:
            self.assertNotEqual(result.returncode, 0,
                                f'sed {args} was expected to fail but '
                                'succeeded')
        else:
            self.assertEqual(result.returncode, 0,
                             f'sed {args} failed:\nstdout:\n{result.stdout}\n'
                             f'stderr:\n{result.stderr}')
        return result

    def _ioctl_names(self):
        return [name for name, _ in self.server.ioctls]

    def _assert_key(self, key, password):
        self.assertEqual(key, {'lr': 0, 'key_len': len(password),
                               'key_type': _OPAL_INCLUDED, 'key': password})

    def _assert_session(self, session, password):
        self.assertEqual(session['sum'], 0)
        self.assertEqual(session['who'], _OPAL_ADMIN1)
        self._assert_key(session['key'], password)

    # ------------------------------------------------------------------ #
    # discover                                                           #
    # ------------------------------------------------------------------ #

    def test_discover(self):
        self.server.l0 = _pack_l0(_LOCKING_SUPPORTED | _LOCKING_ENABLED)
        res = self._sed('discover')
        self.assertRegex(res.stdout, r"Locking Supported\s+: yes")
        self.assertRegex(res.stdout, r"Locking Feature Enabled\s+: yes")
        self.assertRegex(res.stdout, r"Locked\s+: no")
        self.assertEqual(self.server.ioctls, [])

    def test_discover_without_ssc_fails(self):
        self.server.l0 = _pack_l0(0, tper_only=True)
        res = self._sed('discover', expect_fail=True)
        self.assertIn("device does not support SED Opal", res.stderr)

    def test_discover_truncated_descriptors_fails(self):
        self.server.l0 = _pack_l0_truncated()
        res = self._sed('discover', expect_fail=True)
        self.assertIn("device does not support SED Opal", res.stderr)

    def test_discover_nvme_status_fails(self):
        self.server.l0_sc_status = _NVME_SC_INVALID_FIELD
        self._sed('discover', expect_fail=True)

    # ------------------------------------------------------------------ #
    # initialize                                                         #
    # ------------------------------------------------------------------ #

    def test_initialize(self):
        self.server.passwords = [_PASSWORD, _PASSWORD]
        self._sed('initialize')
        self.assertEqual(self.server.prompts,
                         ["New Password: ", "Re-enter New Password: "])
        self.assertEqual(self._ioctl_names(),
                         ['TAKE_OWNERSHIP', 'ACTIVATE_LSP', 'LR_SETUP',
                          'SET_PW'])
        ownership, act, setup, set_pw = [a for _, a in self.server.ioctls]

        self._assert_key(ownership, _PASSWORD)

        self._assert_key(act['key'], _PASSWORD)
        self.assertEqual(act['sum'], 0)
        self.assertEqual(act['num_lrs'], 1)
        self.assertEqual(act['lr'][0], 0)

        self.assertEqual(setup['range_start'], 0)
        self.assertEqual(setup['range_length'], 0)
        self.assertEqual(setup['RLE'], 1)
        self.assertEqual(setup['WLE'], 1)
        self._assert_session(setup['session'], _PASSWORD)

        self._assert_session(set_pw['session'], _PASSWORD)
        self._assert_session(set_pw['new_user_pw'], _PASSWORD)

    def test_initialize_read_only(self):
        self.server.passwords = [_PASSWORD, _PASSWORD]
        self._sed('initialize', '--read-only')
        setup = dict(self.server.ioctls)['LR_SETUP']
        self.assertEqual(setup['RLE'], 1)
        self.assertEqual(setup['WLE'], 0)

    def test_initialize_initialized_drive_fails(self):
        self.server.l0 = _pack_l0(_LOCKING_SUPPORTED | _LOCKING_ENABLED)
        res = self._sed('initialize', expect_fail=True)
        self.assertIn("cannot initialize an initialized drive", res.stderr)
        self.assertEqual(self.server.ioctls, [])

    def test_initialize_password_mismatch_fails(self):
        self.server.passwords = [_PASSWORD, _NEW_PASSWORD]
        res = self._sed('initialize', expect_fail=True)
        self.assertIn("passwords don't match", res.stderr)
        self.assertEqual(self.server.ioctls, [])

    def test_initialize_bad_reentered_password_fails(self):
        """The re-entered password fails the length check. That must be
        an error, not a crash."""
        self.server.passwords = [_PASSWORD, "short"]
        res = self._sed('initialize', expect_fail=True)
        self.assertGreater(res.returncode, 0)
        self.assertIn("password is not long enough", res.stderr)
        self.assertEqual(self.server.ioctls, [])

    def test_initialize_longer_reentered_password_fails(self):
        """The re-entered password starts with the first one but is
        longer. It doesn't match."""
        self.server.passwords = [_PASSWORD, _PASSWORD + "xyz"]
        res = self._sed('initialize', expect_fail=True)
        self.assertIn("passwords don't match", res.stderr)
        self.assertEqual(self.server.ioctls, [])

    def test_initialize_take_ownership_status_fails(self):
        self.server.passwords = [_PASSWORD, _PASSWORD]
        self.server.ioctl_status['TAKE_OWNERSHIP'] = _TCG_NOT_AUTHORIZED
        res = self._sed('initialize', expect_fail=True)
        self.assertIn("failed to take device ownership - 1", res.stderr)
        self.assertEqual(self._ioctl_names(), ['TAKE_OWNERSHIP'])

    # ------------------------------------------------------------------ #
    # lock / unlock                                                      #
    # ------------------------------------------------------------------ #

    def _lock_unlock(self, *args, expect_fail=False):
        self.server.l0 = _pack_l0(_LOCKING_SUPPORTED | _LOCKING_ENABLED)
        self.server.passwords = [_PASSWORD]
        return self._sed(*args, '--ask-key', expect_fail=expect_fail)

    def test_lock(self):
        self._lock_unlock('lock')
        self.assertEqual(self.server.prompts, ["Password: "])
        self.assertEqual(self._ioctl_names(), ['LOCK_UNLOCK'])
        lock = self.server.ioctls[0][1]
        self._assert_session(lock['session'], _PASSWORD)
        self.assertEqual(lock['l_state'], _OPAL_LK)
        self.assertEqual(lock['flags'], 0)

    def test_lock_read_only(self):
        self._lock_unlock('lock', '--read-only')
        self.assertEqual(self.server.ioctls[0][1]['l_state'], _OPAL_RO)

    def test_unlock_rereads_partitions(self):
        self._lock_unlock('unlock')
        self.assertEqual(self._ioctl_names(), ['LOCK_UNLOCK', 'BLKRRPART'])
        self.assertEqual(self.server.ioctls[0][1]['l_state'], _OPAL_RW)

    def test_unlock_not_authorized_fails(self):
        self.server.ioctl_status['LOCK_UNLOCK'] = _TCG_NOT_AUTHORIZED
        res = self._lock_unlock('unlock', expect_fail=True)
        self.assertIn("failed locking or unlocking - 1", res.stderr)
        self.assertEqual(self._ioctl_names(), ['LOCK_UNLOCK'])

    def test_unlock_reread_failure_is_a_warning(self):
        self.server.ioctl_status['BLKRRPART'] = -errno.EBUSY
        res = self._lock_unlock('unlock')
        self.assertIn("failed re-reading partition", res.stderr)

    def test_unlock_truncated_locking_descriptor_fails(self):
        self.server.l0 = _pack_l0_truncated()
        res = self._sed('unlock', '--ask-key', expect_fail=True)
        self.assertIn("cannot lock/unlock an uninitialized drive", res.stderr)
        self.assertEqual(self.server.ioctls, [])

    def test_unlock_uninitialized_drive_fails(self):
        res = self._sed('unlock', '--ask-key', expect_fail=True)
        self.assertIn("cannot lock/unlock an uninitialized drive", res.stderr)
        self.assertEqual(self.server.ioctls, [])

    # ------------------------------------------------------------------ #
    # revert                                                             #
    # ------------------------------------------------------------------ #

    @_requires_ioctl('REVERT_LSP')
    def test_revert(self):
        self.server.l0 = _pack_l0(_LOCKING_SUPPORTED | _LOCKING_ENABLED)
        self.server.passwords = [_PASSWORD]
        self._sed('revert')
        self.assertEqual(self._ioctl_names(), ['REVERT_LSP', 'REVERT_TPR'])
        revert_lsp, revert_tpr = [a for _, a in self.server.ioctls]
        self._assert_key(revert_lsp['key'], _PASSWORD)
        self.assertEqual(revert_lsp['options'], _OPAL_PRESERVE)
        self._assert_key(revert_tpr, _PASSWORD)

    def test_revert_locked_drive_fails(self):
        self.server.l0 = _pack_l0(_LOCKING_SUPPORTED | _LOCKING_ENABLED |
                                  _LOCKING_LOCKED)
        res = self._sed('revert', expect_fail=True)
        self.assertIn("cannot revert drive while locked", res.stderr)
        self.assertEqual(self.server.ioctls, [])

    @_requires_ioctl('REVERT_LSP')
    def test_revert_lsp_not_authorized_skips_tper(self):
        self.server.l0 = _pack_l0(_LOCKING_SUPPORTED | _LOCKING_ENABLED)
        self.server.passwords = [_PASSWORD]
        self.server.ioctl_status['REVERT_LSP'] = _TCG_NOT_AUTHORIZED
        res = self._sed('revert', expect_fail=True)
        self.assertIn("incorrect password", res.stderr)
        self.assertEqual(self._ioctl_names(), ['REVERT_LSP'])

    @_requires_ioctl('PSID_REVERT_TPR')
    def test_revert_psid(self):
        self.server.passwords = [_PSID]
        self._sed('revert', '--psid', stdin_data="y\ny\n")
        self.assertEqual(self.server.prompts, ["PSID: "])
        self.assertEqual(self._ioctl_names(), ['PSID_REVERT_TPR'])
        self._assert_key(self.server.ioctls[0][1], _PSID)

    def test_revert_psid_not_confirmed(self):
        self._sed('revert', '--psid', stdin_data="n\n", expect_fail=True)
        self.assertEqual(self.server.ioctls, [])

    def test_revert_destructive(self):
        self.server.passwords = [_PASSWORD]
        self._sed('revert', '--destructive', stdin_data="y\ny\n")
        self.assertEqual(self._ioctl_names(), ['REVERT_TPR'])
        self._assert_key(self.server.ioctls[0][1], _PASSWORD)

    # ------------------------------------------------------------------ #
    # password                                                           #
    # ------------------------------------------------------------------ #

    def test_password(self):
        self.server.passwords = [_PASSWORD, _NEW_PASSWORD, _NEW_PASSWORD]
        self._sed('password')
        self.assertEqual(self.server.prompts,
                         ["Password: ", "New Password: ",
                          "Re-enter New Password: "])
        expected = ['SET_PW']
        if 'SET_SID_PW' in _SED_IOCTLS:
            expected.append('SET_SID_PW')
        self.assertEqual(self._ioctl_names(), expected)
        for _, new_pw in self.server.ioctls:
            self._assert_session(new_pw['session'], _PASSWORD)
            self._assert_session(new_pw['new_user_pw'], _NEW_PASSWORD)

    def test_password_not_authorized_skips_sid(self):
        self.server.passwords = [_PASSWORD, _NEW_PASSWORD, _NEW_PASSWORD]
        self.server.ioctl_status['SET_PW'] = _TCG_NOT_AUTHORIZED
        res = self._sed('password', expect_fail=True)
        self.assertIn("incorrect password", res.stderr)
        self.assertEqual(self._ioctl_names(), ['SET_PW'])

    def test_password_too_short_fails(self):
        self.server.passwords = ["short"]
        res = self._sed('password', expect_fail=True)
        self.assertIn("password is not long enough", res.stderr)
        self.assertEqual(self.server.ioctls, [])


if __name__ == '__main__':
    # Standalone run: strip the args parsed above, hand the rest to unittest.
    unittest_args = [sys.argv[0]]
    if len(sys.argv) > 3:
        unittest_args.extend(sys.argv[3:])
    unittest.main(argv=unittest_args)
