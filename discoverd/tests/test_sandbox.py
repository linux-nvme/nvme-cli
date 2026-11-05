#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""nvme-discoverd in a sandbox: --set-options test-base-dir/test-sysfs-dir.

The daemon runs without systemd and udev: its connection units run locally
and are recorded in <base>/units, and the test talks to it through the
control socket <base>/discoverd.sock. fake_nvme.py stands in for the nvme
binary of the units.

Usage: python3 test_sandbox.py <path-to-nvme-discoverd>
"""
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

# Capture the binary path from argv before unittest.main() strips it.
DISCOVERD = sys.argv.pop(1) if len(sys.argv) > 1 else 'nvme-discoverd'
FAKE_NVME = Path(__file__).resolve().parent / 'fake_nvme.py'

HOSTNQN = 'nqn.2014-08.org.nvmexpress:uuid:c0ffee00-0000-0000-0000-000000000001'
HOSTID = 'c0ffee00-0000-0000-0000-000000000001'
DC_NQN = 'nqn.2014-08.org.nvmexpress.discovery'
DC_TRADDR = '192.0.2.10'


def sh_quote(s):
    """Quote @s for the shell, as nvme-discoverd does."""
    return "'" + s.replace("'", "'\\''") + "'"


class Daemon:
    """One nvme-discoverd process in the sandbox, and its control socket."""

    def __init__(self, test, extra_env=None, set_options=None):
        env = dict(os.environ)
        env.update(extra_env or {})
        if set_options is None:
            set_options = [f'--set-options=test-base-dir={test.base},'
                           f'test-sysfs-dir={test.sysfs}']
        self.proc = subprocess.Popen(
            [DISCOVERD, '--config', str(test.conf),
             '--nvme-path', str(test.nvme), '--debug', *set_options],
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, encoding='utf-8')
        sock = test.base / 'discoverd.sock'
        for _ in range(200):
            if sock.exists() or self.proc.poll() is not None:
                break
            time.sleep(0.025)
        if not sock.exists():
            self.stop()
            raise RuntimeError(f'no control socket:\n{self.stderr}')
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(str(sock))
        self.io = self.sock.makefile('rw', encoding='utf-8')
        self.stderr = ''

    def request(self, line):
        self.io.write(line + '\n')
        self.io.flush()
        return self.io.readline().rstrip('\n')

    def sync(self):
        return self.request('sync')

    def dump(self):
        return json.loads(self.request('dump'))

    def stop(self):
        if getattr(self, 'sock', None):
            self.sock.close()
            self.sock = None
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
        self.stderr = self.proc.communicate(timeout=10)[1]
        return self.proc.returncode


class SandboxTest(unittest.TestCase):

    # libnvme confines the test base directory to /tmp.
    PREFIX = 'discoverd-sandbox-'

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix=self.PREFIX, dir='/tmp'))
        self.sysfs = self.base / 'sysroot'
        (self.sysfs / 'sys/class/nvme').mkdir(parents=True)
        self.conf = self.base / 'nvme-discoverd.conf'
        self.conf.write_text('', encoding='utf-8')
        self.nvme = self.base / 'nvme'
        self.nvme.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{FAKE_NVME}" "$@"\n',
            encoding='utf-8')
        self.nvme.chmod(stat.S_IRWXU)
        self.daemons = []

    def tearDown(self):
        for d in self.daemons:
            d.stop()
        shutil.rmtree(self.base)

    def start(self, extra_env=None, set_options=None):
        d = Daemon(self, extra_env, set_options)
        self.daemons.append(d)
        return d

    def configure_dc(self):
        """One TCP Discovery Controller in the sandbox's fabrics config."""
        (self.base / 'nvme-fabrics.conf').write_text(
            '[Host]\n'
            f'hostnqn = {HOSTNQN}\n'
            f'hostid  = {HOSTID}\n'
            '\n'
            '[Discovery Controller]\n'
            f'controller = transport=tcp;traddr={DC_TRADDR};trsvcid=8009\n',
            encoding='utf-8')

    def journal(self):
        path = self.base / 'units/journal'
        if not path.exists():
            return []
        return [json.loads(line) for line in
                path.read_text(encoding='utf-8').splitlines()]

    def test_control_socket(self):
        d = self.start()
        self.assertEqual(d.sync(), 'ok')
        self.assertEqual(d.dump(), {'controllers': []})
        self.assertEqual(d.request('uevent nvme remove nvme7'), 'ok')
        self.assertEqual(d.request('bogus'), 'error unknown request')
        self.assertEqual(d.stop(), 0)
        self.assertFalse((self.base / 'discoverd.sock').exists())
        # The state of /run/nvme/discoverd moved into the sandbox.
        self.assertTrue((self.base / 'discoverd/units').is_dir())

    def test_bad_set_options(self):
        for opts, msg in (('bogus=1', "unknown key 'bogus'"),
                          ('test-base-dir', 'needs a value'),
                          ('test-base-dir=/var/tmp/x', 'test-base-dir')):
            with self.subTest(opts=opts):
                p = subprocess.run(
                    [DISCOVERD, '--config', str(self.conf),
                     f'--set-options={opts}'],
                    stdin=subprocess.DEVNULL, capture_output=True,
                    encoding='utf-8', timeout=10)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn(msg, p.stderr)

    def test_connect_unit(self):
        """A configured DC is connected through a local unit."""
        self.configure_dc()
        d = self.start()
        self.assertEqual(d.sync(), 'ok')

        starts = [j for j in self.journal() if j['op'] == 'start']
        self.assertEqual(len(starts), 1)
        argv = starts[0]['exec_start']
        # The nvme of the unit sees the sandbox, too.
        self.assertEqual(argv[:3], [
            str(self.nvme),
            f'--set-options=test-sysfs-dir={self.sysfs},'
            f'test-base-dir={self.base}',
            'connect'])
        self.assertIn('--discovery', argv)
        self.assertIn('--owner=discoverd', argv)
        devid = [a for a in argv if a.startswith('--devid-file=')]
        self.assertEqual(len(devid), 1)
        self.assertTrue(devid[0].startswith(
            f'--devid-file={self.base}/discoverd/units/'))
        self.assertTrue(starts[0]['connection'])
        self.assertIn(sh_quote(f'{self.sysfs}/sys/class/nvme'),
                      starts[0]['exec_start_post'])
        self.assertIn('disconnect -d', starts[0]['exec_stop'])

        results = [j['result'] for j in self.journal()
                   if j['op'] == 'result']
        self.assertEqual(results, ['done'])
        self.assertEqual(
            (self.base / 'registry/nvme900/owner').read_text(
                encoding='utf-8').strip(), 'discoverd')
        # ExecStartPost recorded the unit of the device.
        self.assertEqual(
            (self.base / 'discoverd/controllers/nvme900/unit').read_text(
                encoding='utf-8').strip(), starts[0]['unit'])

        ctrls = d.dump()['controllers']
        self.assertEqual(len(ctrls), 1)
        self.assertEqual(ctrls[0]['unit'], starts[0]['unit'])
        self.assertEqual(ctrls[0]['devname'], 'nvme900')
        self.assertTrue(ctrls[0]['dc'])
        self.assertEqual(ctrls[0]['attempts'], 0)

    def test_adopt_after_restart(self):
        """A unit outlives the daemon, and the next run adopts it."""
        self.configure_dc()
        d = self.start()
        self.assertEqual(d.sync(), 'ok')
        self.assertEqual(d.stop(), 0)
        # Stopping the daemon disconnects nothing.
        self.assertTrue((self.sysfs / 'sys/class/nvme/nvme900').is_dir())

        d = self.start()
        self.assertEqual(d.sync(), 'ok')
        ops = [j['op'] for j in self.journal()]
        self.assertEqual(ops, ['start', 'result'],
                         'the second run must not start the unit again')
        ctrls = d.dump()['controllers']
        self.assertEqual([c['devname'] for c in ctrls], ['nvme900'])
        self.assertFalse((self.sysfs / 'sys/class/nvme/nvme901').exists())

    def test_failed_connect(self):
        """A failed connect is collected and retried later."""
        self.configure_dc()
        d = self.start({'FAKE_NVME_FAIL': '1'})
        self.assertEqual(d.sync(), 'ok')

        results = [j['result'] for j in self.journal()
                   if j['op'] == 'result']
        self.assertEqual(results, ['failed'])
        self.assertEqual(list((self.base / 'units').glob('*.service')), [])
        ctrls = d.dump()['controllers']
        self.assertEqual(len(ctrls), 1)
        self.assertIsNone(ctrls[0]['devname'])
        self.assertEqual(ctrls[0]['attempts'], 1)
        self.assertTrue(ctrls[0]['retry_pending'])

    def run_stop(self, unit):
        """Run @unit's ExecStop= and ExecStopPost=, as systemd does."""
        udir = self.base / 'units' / unit
        for name in ('exec_stop', 'exec_stop_post'):
            subprocess.run(['/bin/sh', '-c',
                            (udir / name).read_text(encoding='utf-8')],
                           check=False, timeout=10)

    def disconnects(self):
        log = (self.base / 'fake-nvme.log').read_text(encoding='utf-8')
        return [json.loads(line) for line in log.splitlines()
                if json.loads(line)[0] == 'disconnect']

    def connected_unit(self):
        self.configure_dc()
        d = self.start()
        self.assertEqual(d.sync(), 'ok')
        self.assertEqual(d.stop(), 0)
        unit = [j for j in self.journal() if j['op'] == 'start'][0]['unit']
        return unit

    def test_stop_disconnects_own_controller(self):
        unit = self.connected_unit()
        self.run_stop(unit)
        self.assertEqual(self.disconnects(), [['disconnect', '-d', 'nvme900']])
        self.assertFalse((self.sysfs / 'sys/class/nvme/nvme900').exists())
        # ExecStopPost removed the state.
        self.assertFalse(
            (self.base / 'discoverd/controllers/nvme900').exists())
        self.assertEqual(list((self.base / 'discoverd/units').iterdir()), [])

    def test_stop_keeps_reused_name(self):
        """The kernel gave the name to another controller: keep it."""
        unit = self.connected_unit()
        ctrl = self.sysfs / 'sys/class/nvme/nvme900'
        tmp = self.sysfs / 'nvme900.new'
        shutil.copytree(ctrl, tmp)
        shutil.rmtree(ctrl)
        tmp.rename(ctrl)  # same name, another inode
        self.run_stop(unit)
        self.assertEqual(self.disconnects(), [])
        self.assertTrue(ctrl.exists())

    def test_stop_keeps_other_units_controller(self):
        unit = self.connected_unit()
        (self.base / 'discoverd/controllers/nvme900/unit').write_text(
            'nvme-discoverd-other.service\n', encoding='utf-8')
        self.run_stop(unit)
        self.assertEqual(self.disconnects(), [])
        # ExecStopPost leaves the other unit's state alone.
        self.assertTrue(
            (self.base / 'discoverd/controllers/nvme900/unit').exists())

    def test_remove_event(self):
        """A removal sent through the control socket reconnects the DC."""
        self.configure_dc()
        d = self.start()
        self.assertEqual(d.sync(), 'ok')

        # The kernel lost the controller.
        ctrl = self.sysfs / 'sys/class/nvme/nvme900'
        for attr in ctrl.iterdir():
            attr.unlink()
        ctrl.rmdir()
        self.assertEqual(d.request('uevent nvme remove nvme900'), 'ok')
        self.assertEqual(d.sync(), 'ok')

        ops = [j['op'] for j in self.journal()]
        self.assertEqual(ops, ['start', 'result', 'restart', 'result'])
        ctrls = d.dump()['controllers']
        self.assertEqual([c['devname'] for c in ctrls], ['nvme900'])

    def test_reload(self):
        """SIGHUP re-reads the sandbox's fabrics configuration, each time."""
        self.configure_dc()
        d = self.start()
        self.assertEqual(d.sync(), 'ok')

        conf = self.base / 'nvme-fabrics.conf'
        for i, traddr in enumerate(('192.0.2.11', '192.0.2.12'), start=2):
            with conf.open('a', encoding='utf-8') as f:
                f.write(f'controller = transport=tcp;traddr={traddr};'
                        'trsvcid=8009\n')
            d.proc.send_signal(signal.SIGHUP)
            self.assertEqual(d.sync(), 'ok')
            starts = [j for j in self.journal() if j['op'] == 'start']
            self.assertEqual(len(starts), i, f'reload {i - 1}')
        self.assertEqual(d.stop(), 0, d.stderr)

    def test_repeated_set_options(self):
        """--set-options may be given once per key."""
        self.configure_dc()
        d = self.start(set_options=[
            f'--set-options=test-sysfs-dir={self.sysfs}',
            f'--set-options=test-base-dir={self.base}'])
        self.assertEqual(d.sync(), 'ok')
        self.assertTrue((self.sysfs / 'sys/class/nvme/nvme900').is_dir())
        argv = [j for j in self.journal() if j['op'] == 'start'][0][
            'exec_start']
        self.assertEqual(argv[1], f'--set-options=test-sysfs-dir={self.sysfs},'
                                  f'test-base-dir={self.base}')
        self.assertEqual(d.stop(), 0, d.stderr)


class OddPathSandboxTest(SandboxTest):
    """All of the above with characters the shell would split or expand
    in the sandbox's path."""

    PREFIX = "discoverd sandbox $HOME 'q' "


if __name__ == '__main__':
    unittest.main()
