# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""A host that boots from NVMe-oF, for the pre-OS/OS hand-over scenarios.

The pre-OS environment (the initrd) runs the real nvme binary under
libmock_nvme.so, as dracut's nvmf module does. After switch-root, the OS
environment runs the real nvme-discoverd in a sandbox (--set-options
test-base-dir/test-sysfs-dir): its connection units run locally and
exec the real nvme, also under libmock_nvme.so.

Fabric plays the targets and the kernel's fabrics layer: it accepts the
connects of the reachable targets, refuses a duplicate the way the kernel
does, creates the controllers in the test sysfs and serves the Discovery
Log Pages. Host.settle() plays udev: it announces new controllers and
removes the disconnected ones, until nvme-discoverd has nothing left to do.

See issue #4328 for the model: everything the pre-OS environment connects
is its own, and the OS environment must not disconnect it or connect it
again with other parameters.
"""
import errno
import json
import os
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from tests.cli.nvme_fabrics_mock_test import _pack_disc_log_entry
from tests.cli.nvme_mock import (CNS_CTRL, MOCK_LIB, NVME_BIN,
                                 MockController, id_ctrl)
from tests.cli.nvme_mock_ipc import make_mock_env, run_nvme

DISCOVERD_BIN = os.environ.get('NVME_DISCOVERD', 'nvme-discoverd')
# The host's own identity, /etc/nvme/hostnqn and hostid. dracut copies
# them into the initrd, so both environments share them.
HOST_ID = '0f11c8d0-2b4c-4a7e-9d1a-5e2f3c4b5a69'
HOST_NQN = f'nqn.2014-08.org.nvmexpress:uuid:{HOST_ID}'
DISC_NQN = 'nqn.2014-08.org.nvmexpress.discovery'
NBFT_TABLES = Path(__file__).resolve().parents[2] / 'libnvme/tests/nbft/tables'

_DISCOVERY_LOG_LID = 0x70


def _opts(payload):
    """The options of a fabrics connect string, and its flags."""
    opts, flags = {}, set()
    for part in payload.decode('utf-8', errors='replace').split(','):
        if '=' in part:
            key, val = part.split('=', 1)
            opts[key.strip()] = val.strip()
        elif part.strip():
            flags.add(part.strip())
    return opts, flags


class Target:
    """A port of an NVM subsystem or a Discovery Controller."""

    def __init__(self, transport, traddr, trsvcid, nqn, dlp=None,
                 host_traddr=None):
        self.transport = transport
        self.traddr = traddr
        self.trsvcid = trsvcid
        self.nqn = nqn
        self.host_traddr = host_traddr  # FC: the local port that sees it
        self.reachable = True
        # The entries of a DC's Discovery Log Page, as for
        # _pack_disc_log_entry().
        self.dlp = dlp or []

    @property
    def key(self):
        return (self.transport, self.traddr, self.trsvcid or '', self.nqn)


class Fabric(MockController):
    """The targets, and the kernel's side of a fabrics connect."""

    def __init__(self, sock_path, sysfs):
        super().__init__(sock_path)
        self.sysfs = Path(sysfs)
        self.targets = {}
        self.ctrls = {}        # instance -> connect options
        self.connects = []     # options of every connect, refused or not
        self.refused = []      # (options, errno)
        self.deleted = []      # devnames deleted, not reported yet
        self.identify[CNS_CTRL] = self.id_ctrl
        self.logs[_DISCOVERY_LOG_LID] = self.discovery_log

    def add_target(self, transport, traddr, trsvcid, nqn, dlp=None,
                   host_traddr=None):
        t = Target(transport, traddr, trsvcid, nqn, dlp, host_traddr)
        self.targets[t.key] = t
        if transport == 'fc':
            kick = self.sysfs / 'sys/class/fc/fc_udev_device/nvme_discovery'
            kick.parent.mkdir(parents=True, exist_ok=True)
            kick.touch()
        return t

    def fc_dcs(self):
        """The FC remote ports with the discovery role."""
        return [t for t in self.targets.values()
                if t.transport == 'fc' and t.nqn == DISC_NQN and
                t.reachable]

    def lookup_target(self, opts):
        # FC has no port: the connect says "none" or nothing.
        trsvcid = opts.get('trsvcid', '')
        if trsvcid == 'none':
            trsvcid = ''
        key = (opts.get('transport'), opts.get('traddr'), trsvcid,
               opts.get('nqn'))
        return self.targets.get(key)

    def _nvme_dir(self):
        return self.sysfs / 'sys/class/nvme'

    def _duplicate(self, opts):
        """The kernel's duplicate check (nvmf_ip_options_match() and
        nvmf_ctlr_matches_baseopts()): the same address, subsystem and
        host. A host_traddr or host_iface only counts if the new connect
        gives one."""
        for inst, c in self.ctrls.items():
            if not (self._nvme_dir() / f'nvme{inst}').exists():
                continue
            if any(c.get(k) != opts.get(k) for k in
                   ('transport', 'traddr', 'trsvcid', 'nqn', 'hostnqn',
                    'hostid')):
                continue
            if any(k in opts and c.get(k) != opts[k]
                   for k in ('host_traddr', 'host_iface')):
                continue
            return True
        return False

    def free_instance(self):
        """The kernel hands out the lowest free instance."""
        inst = 0
        while (self._nvme_dir() / f'nvme{inst}').exists():
            inst += 1
        return inst

    def handle_write(self, conn, payload):
        opts, flags = _opts(payload)
        self.connects.append(opts)
        target = self.lookup_target(opts)
        err = 0
        if not target or not target.reachable:
            err = errno.ECONNREFUSED
        elif 'duplicate_connect' not in flags and self._duplicate(opts):
            err = errno.EALREADY
        if err:
            self.refused.append((opts, err))
            self.send_response(conn, -1, errno_val=err)
            return

        inst = self.free_instance()
        opts['discovery'] = ('discovery' in flags or
                             opts.get('nqn') == DISC_NQN)
        self.ctrls[inst] = opts
        self.write_ctrl(inst, opts)
        self.send_response(conn, 0, payload=f'instance={inst}\n'.encode())

    def write_ctrl(self, inst, opts):
        """Create controller nvme@inst in sysfs, as the kernel shows it."""
        address = f"traddr={opts['traddr']}"
        if opts.get('trsvcid'):
            address += f",trsvcid={opts['trsvcid']}"
        if opts.get('host_traddr'):
            address += f",host_traddr={opts['host_traddr']}"
        if opts.get('host_iface'):
            address += f",host_iface={opts['host_iface']}"
        attrs = {
            'transport': opts['transport'],
            'address': address,
            'subsysnqn': opts['nqn'],
            'hostnqn': opts.get('hostnqn', ''),
            'hostid': opts.get('hostid', ''),
            'host_iface': opts.get('host_iface', ''),
            'cntrltype': 'discovery' if opts.get('discovery') else 'io',
            'state': 'live',
            'delete_controller': '',
            'dhchap_secret': 'none',
            'dhchap_ctrl_secret': 'none',
        }
        ctrl = self._nvme_dir() / f'nvme{inst}'
        ctrl.mkdir(parents=True)
        for attr, val in attrs.items():
            (ctrl / attr).write_text(f'{val}\n' if val else '',
                                     encoding='utf-8')
        subsys = self.sysfs / 'sys/class/nvme-subsystem' / f'nvme-subsys{inst}'
        subsys.mkdir(parents=True, exist_ok=True)
        (subsys / 'subsysnqn').write_text(f"{opts['nqn']}\n", encoding='utf-8')

        (subsys / f'nvme{inst}').mkdir(exist_ok=True)

    def handle_delete(self, conn, instance):
        """A write to delete_controller: the kernel deletes the
        controller before the write returns."""
        if (self._nvme_dir() / f'nvme{instance}').exists():
            self.remove_ctrl(instance)
            self.deleted.append(f'nvme{instance}')
        self.send_response(conn, 0)

    def remove_ctrl(self, inst):
        """The kernel deletes the controller."""
        shutil.rmtree(self._nvme_dir() / f'nvme{inst}', ignore_errors=True)
        shutil.rmtree(self.sysfs / 'sys/class/nvme-subsystem' /
                      f'nvme-subsys{inst}', ignore_errors=True)

    def id_ctrl(self, cmd):
        # libnvme reads a DC's own NQN from here (TP8013).
        nqn = self.ctrls.get(cmd.instance, {}).get('nqn', '')
        return id_ctrl(vid=0x105b, mn='Handover Target', subnqn=nqn)

    def discovery_log(self, cmd):
        opts = self.ctrls.get(cmd.instance, {})
        target = self.lookup_target(opts)
        entries = target.dlp if target else []
        header = struct.pack('<QQH', 1, len(entries), 0) + b'\0' * 1006
        log = header + b''.join(_pack_disc_log_entry(i + 1, e)
                                for i, e in enumerate(entries))
        return log[cmd.lpo:]


class Daemon:
    """nvme-discoverd in the host's sandbox, and its control socket."""

    def __init__(self, host, extra_args=()):
        self.host = host
        # Under "meson test --setup=valgrind", valgrind rewrites
        # LD_PRELOAD on every exec it traps, and nvme-discoverd would run
        # without the mock. As run_nvme() does, let a shell set it.
        env = dict(host.env)
        preload = env.pop('LD_PRELOAD', '')
        self.proc = subprocess.Popen(
            ['/bin/sh', '-c', f'export LD_PRELOAD={shlex.quote(preload)}; '
             'exec "$@"', 'nvme-discoverd',
             DISCOVERD_BIN, '--config', str(host.discoverd_conf),
             '--nvme-path', str(host.unit_nvme), '--debug',
             f'--set-options=test-base-dir={host.base},'
             f'test-sysfs-dir={host.sysfs}', *extra_args],
            env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=self._log_file(host))
        sock = host.base / 'discoverd.sock'
        for _ in range(400):
            if sock.exists() or self.proc.poll() is not None:
                break
            time.sleep(0.025)
        self.stderr = ''
        if not sock.exists():
            self.stop()
            raise RuntimeError(f'nvme-discoverd did not start:\n{self.stderr}')
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(60)
        self.sock.connect(str(sock))
        self.io = self.sock.makefile('rw', encoding='utf-8')

    def _log_file(self, host):
        """The daemon logs to stderr in the sandbox (and to the journal):
        into a file, as a pipe nobody reads would block it once full."""
        self.log_path = host.tmp / 'discoverd.log'
        self.log = open(self.log_path, 'a', encoding='utf-8')
        return self.log

    def _read_log(self):
        if not self.log.closed:
            self.log.close()
        return self.log_path.read_text(encoding='utf-8', errors='replace')

    def request(self, line):
        self.io.write(line + '\n')
        self.io.flush()
        reply = self.io.readline().rstrip('\n')
        if reply.startswith('error'):
            raise RuntimeError(f'{line!r}: {reply}')
        return reply

    def dump(self):
        return json.loads(self.request('dump'))['controllers']

    def stop(self):
        if getattr(self, 'sock', None):
            self.sock.close()
            self.sock = None
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
        self.proc.wait(timeout=30)
        self.stderr = self._read_log()
        return self.proc.returncode


class Host:
    """A host with its sysfs, /run and /etc in a sandbox under /tmp."""

    def __init__(self):
        # libnvme confines the test base directory to /tmp.
        self.tmp = Path(tempfile.mkdtemp(prefix='handover-', dir='/tmp'))
        self.sysfs = self.tmp / 'sysfs'
        self.base = self.tmp / 'base'
        for d in ('sys/class/nvme', 'sys/class/nvme-subsystem',
                  'sys/firmware/acpi/tables'):
            (self.sysfs / d).mkdir(parents=True)
        self.base.mkdir()
        (self.base / 'hostnqn').write_text(f'{HOST_NQN}\n', encoding='utf-8')
        (self.base / 'hostid').write_text(f'{HOST_ID}\n', encoding='utf-8')
        self.fabric = Fabric(str(self.tmp / 'ipc.sock'), self.sysfs)
        self.fabric.start()
        self.env = make_mock_env(MOCK_LIB, str(self.tmp / 'ipc.sock'))
        self.daemon = None
        self.disconnected = []  # devnames a disconnect deleted, in order
        self.announced = set()

        # The nvme of the connection units: the real one, in the sandbox.
        self.unit_nvme = self.tmp / 'nvme'
        self.unit_nvme.write_text(
            '#!/bin/sh\n'
            f'export LD_PRELOAD="{self.env["LD_PRELOAD"]}"\n'
            f'exec "{NVME_BIN}" --set-options '
            f'test-sysfs-dir={self.sysfs},test-base-dir={self.base} "$@"\n',
            encoding='utf-8')
        self.unit_nvme.chmod(0o755)
        self.discoverd_conf = self.base / 'nvme-discoverd.conf'
        self.discoverd_conf.write_text('', encoding='utf-8')

    def unit_env(self):
        """The environment of a unit's commands. Its nvme sets the
        preload itself (self.unit_nvme)."""
        env = dict(self.env)
        env.pop('LD_PRELOAD', None)
        return env

    def close(self):
        if self.daemon:
            self.daemon.stop()
            self.daemon = None
        # HANDOVER_LOG=1: show nvme-discoverd's log of each test.
        log = self.tmp / 'discoverd.log'
        if os.environ.get('HANDOVER_LOG') and log.exists():
            sys.stderr.write(log.read_text(encoding='utf-8',
                                           errors='replace'))
        self.fabric.shutdown()
        self.fabric.join()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- firmware and configuration ------------------------------------ #

    def nbft(self, table):
        """The firmware's NBFT, from libnvme/tests/nbft/tables."""
        shutil.copyfile(NBFT_TABLES / table,
                        self.sysfs / 'sys/firmware/acpi/tables/NBFT')

    def fabrics_conf(self, text):
        (self.base / 'nvme-fabrics.conf').write_text(text, encoding='utf-8')

    def discoverd_config(self, text):
        self.discoverd_conf.write_text(text, encoding='utf-8')

    # -- pre-OS environment -------------------------------------------- #

    def nvme(self, *args):
        """Run the real nvme in the sandbox, as the initrd does."""
        result = run_nvme(NVME_BIN, self.env, str(self.sysfs),
                          str(self.base), *args)
        self.check_fabric()
        self.announce_existing()
        return result

    def plant(self, transport, traddr, trsvcid, nqn, **opts):
        """A controller connected by something that writes no registry
        entry, e.g. an initrd with nvme-cli 2. Returns its devname."""
        opts = {'transport': transport, 'traddr': traddr,
                'trsvcid': trsvcid, 'nqn': nqn, **opts}
        inst = self.fabric.free_instance()
        opts['discovery'] = nqn == DISC_NQN or opts.pop('discovery', False)
        self.fabric.ctrls[inst] = opts
        self.fabric.write_ctrl(inst, opts)
        self.announced.add(f'nvme{inst}')
        return f'nvme{inst}'

    def announce_existing(self):
        """Controllers that exist before nvme-discoverd starts need no
        uevent: it finds them in sysfs."""
        self.announced |= set(self.devnames())

    # -- OS environment ------------------------------------------------ #

    def switch_root(self):
        """Leave the initrd. /run (the registry) and the
        controllers stay."""
        # What the tests check is what the OS environment disconnects;
        # the kernel reuses the names the initrd freed.
        self.pump()
        self.disconnected = []

    def start(self, extra_args=()):
        """Switch to the real root, and start nvme-discoverd there."""
        self.switch_root()
        self.daemon = Daemon(self, extra_args)
        self.settle()
        return self.daemon

    def stop(self):
        """Stop nvme-discoverd. Its units stay, as transient units do."""
        rc = self.daemon.stop()
        self.daemon = None
        self.pump()
        return rc

    def restart(self):
        self.stop()
        return self.start()

    def reload(self):
        """SIGHUP. The signal is pending before the control socket is
        readable, and the control socket has the lowest priority, so the
        sync of settle() comes after the reload."""
        self.daemon.proc.send_signal(signal.SIGHUP)
        self.settle()

    def uevent(self, line):
        self.daemon.request(f'uevent {line}')

    def pump(self):
        """Play the kernel and udev once: delete the controllers that got
        a disconnect, and report the changes. Returns the uevents."""
        events = []
        # An FC kickstart: one discovery event per remote DC port.
        kick = self.sysfs / 'sys/class/fc/fc_udev_device/nvme_discovery'
        if kick.exists() and kick.read_text().strip():
            kick.write_text('')
            for t in self.fabric.fc_dcs():
                events.append('fc change fc_udev_device '
                              'FC_EVENT=nvmediscovery '
                              f'NVMEFC_TRADDR={t.traddr} '
                              f'NVMEFC_HOST_TRADDR={t.host_traddr}')
        while self.fabric.deleted:
            name = self.fabric.deleted.pop(0)
            self.disconnected.append(name)
            self.announced.discard(name)
            events.append(f'nvme remove {name}')
        nvme_dir = self.sysfs / 'sys/class/nvme'
        for ctrl in sorted(nvme_dir.iterdir()):
            delete = ctrl / 'delete_controller'
            if delete.exists() and delete.read_text().strip() == '1':
                inst = int(ctrl.name[4:])
                self.fabric.remove_ctrl(inst)
                self.disconnected.append(ctrl.name)
                self.announced.discard(ctrl.name)
                events.append(f'nvme remove {ctrl.name}')
        for name in self.devnames():
            if name not in self.announced:
                self.announced.add(name)
                events.append(f'nvme add {name}')
        return events

    def check_fabric(self):
        if self.fabric.errors:
            raise RuntimeError('the fabric failed:\n' +
                               '\n'.join(self.fabric.errors))

    def settle(self, rounds=20):
        """Let nvme-discoverd and the kernel go back and forth until
        nothing changes any more."""
        self.check_fabric()
        for _ in range(rounds):
            self.daemon.request('sync')
            events = self.pump()
            if not events:
                return
            for ev in events:
                self.uevent(ev)
        raise RuntimeError('the host does not settle')

    def lose(self, devname):
        """The kernel lost the controller, e.g. after ctrl_loss_tmo."""
        self.fabric.remove_ctrl(int(devname[4:]))
        self.announced.discard(devname)
        self.uevent(f'nvme remove {devname}')
        self.settle()

    def aen(self, devname):
        """A Discovery Log Page Change AEN from DC @devname."""
        c = self.fabric.ctrls[int(devname[4:])]
        props = ["NVME_AEN=0x70f002", f"NVME_TRTYPE={c['transport']}",
                 f"NVME_TRADDR={c['traddr']}",
                 f"NVME_TRSVCID={c.get('trsvcid') or 'none'}",
                 f"NVME_HOST_TRADDR={c.get('host_traddr') or 'none'}",
                 f"NVME_HOST_IFACE={c.get('host_iface') or 'none'}"]
        self.uevent(f'nvme change {devname} ' + ' '.join(props))
        self.settle()

    def fc_discovery(self, traddr, host_traddr):
        self.uevent('fc change fc_udev_device FC_EVENT=nvmediscovery '
                    f'NVMEFC_TRADDR={traddr} NVMEFC_HOST_TRADDR={host_traddr}')
        self.settle()

    def shutdown(self):
        """Stop nvme-discoverd, then the units, as systemd does at
        shutdown: ExecStop=, then ExecStopPost=."""
        if self.daemon:
            self.stop()
        units = self.base / 'units'
        for unit in sorted(units.glob('*.service')) if units.exists() else []:
            for name in ('exec_stop', 'exec_stop_post'):
                cmd = unit / name
                if cmd.exists():
                    subprocess.run(['/bin/sh', '-c', cmd.read_text()],
                                   env=self.unit_env(),
                                   stdin=subprocess.DEVNULL,
                                   capture_output=True, check=False,
                                   timeout=60)
            shutil.rmtree(unit)
        self.pump()

    # -- observations -------------------------------------------------- #

    def devnames(self):
        return sorted((p.name for p in
                       (self.sysfs / 'sys/class/nvme').iterdir()),
                      key=lambda n: int(n[4:]))

    def ctrl(self, devname):
        """The connect options of a live controller."""
        return self.fabric.ctrls[int(devname[4:])]

    def find(self, nqn, traddr=None):
        """The devnames of the live controllers to @nqn (at @traddr)."""
        return [n for n in self.devnames()
                if self.ctrl(n)['nqn'] == nqn and
                (traddr is None or self.ctrl(n)['traddr'] == traddr)]

    def owner(self, devname):
        path = self.base / 'registry' / devname / 'owner'
        return path.read_text().strip() if path.exists() else None

    def journal(self):
        path = self.base / 'units/journal'
        if not path.exists():
            return []
        return [json.loads(line) for line in
                path.read_text(encoding='utf-8').splitlines()]

    def unit_starts(self):
        return [j for j in self.journal() if j['op'] == 'start']

    def loaded_units(self):
        units = self.base / 'units'
        return sorted(p.name for p in units.glob('*.service'))
