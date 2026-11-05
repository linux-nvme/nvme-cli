#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""A stand-in for the nvme binary in nvme-discoverd's connection units.

"connect" plays the kernel and nvme connect: it creates the controller in
the test sysfs, writes its name to --devid-file and records --owner in the
registry. "disconnect -d NAME" removes the controller. Every call is logged.

The sandbox comes from --set-options before the command, as for the real
nvme: test-sysfs-dir (the test sysfs root) and test-base-dir (the test base
directory, for the registry and the log). Without them it refuses to run.
FAKE_NVME_FAIL in the environment fails every connect.

Controller names start at nvme900, so that nothing can reach a real
/dev/nvmeN.
"""
import json
import os
import sys
from pathlib import Path

FIRST_INSTANCE = 900


def options(args):
    """--key=value options as a dict, --flag as True."""
    opts = {}
    for arg in args:
        if not arg.startswith('--'):
            continue
        key, sep, val = arg[2:].partition('=')
        opts[key] = val if sep else True
    return opts


def connect(sysfs, base, opts):
    nvme = sysfs / 'sys/class/nvme'
    nvme.mkdir(parents=True, exist_ok=True)
    instance = FIRST_INSTANCE
    while (nvme / f'nvme{instance}').exists():
        instance += 1
    name = f'nvme{instance}'
    ctrl = nvme / name
    ctrl.mkdir()

    address = f"traddr={opts['traddr']}"
    if opts.get('trsvcid'):
        address += f",trsvcid={opts['trsvcid']}"
    if opts.get('host-traddr'):
        address += f",host_traddr={opts['host-traddr']}"
    attrs = {
        'transport': opts['transport'],
        'address': address,
        'subsysnqn': opts['nqn'],
        'hostnqn': opts.get('hostnqn', ''),
        'hostid': opts.get('hostid', ''),
        'cntrltype': 'discovery' if opts.get('discovery') else 'io',
        'state': 'live',
    }
    for attr, val in attrs.items():
        (ctrl / attr).write_text(f'{val}\n', encoding='utf-8')

    if opts.get('owner'):
        reg = base / 'registry' / name
        reg.mkdir(parents=True, exist_ok=True)
        (reg / 'owner').write_text(f"{opts['owner']}\n", encoding='utf-8')

    if opts.get('devid-file'):
        Path(opts['devid-file']).write_text(f'{name}\n', encoding='utf-8')

    return 0


def disconnect(sysfs, args):
    name = args[args.index('-d') + 1]
    ctrl = sysfs / 'sys/class/nvme' / name
    if not ctrl.is_dir():
        return 1
    for attr in ctrl.iterdir():
        attr.unlink()
    ctrl.rmdir()
    return 0


def set_options(args):
    """Split off the leading --set-options as a dict."""
    opts = {}
    while args and args[0].startswith('--set-options'):
        if args[0] == '--set-options':
            val, args = args[1], args[2:]
        else:
            val, args = args[0].partition('=')[2], args[1:]
        for kv in val.split(','):
            key, _, v = kv.partition('=')
            opts[key] = v
    return opts, args


def main():
    so, args = set_options(sys.argv[1:])
    if 'test-sysfs-dir' not in so or 'test-base-dir' not in so:
        print(f'fake nvme: no sandbox in {sys.argv[1:]}', file=sys.stderr)
        return 1
    sysfs = Path(so['test-sysfs-dir'])
    base = Path(so['test-base-dir'])

    with open(base / 'fake-nvme.log', 'a', encoding='utf-8') as log:
        log.write(json.dumps(args) + '\n')

    if not args:
        return 1
    if args[0] == 'connect':
        if os.environ.get('FAKE_NVME_FAIL'):
            return 1
        return connect(sysfs, base, options(args[1:]))
    if args[0] == 'disconnect':
        return disconnect(sysfs, args[1:])
    return 1


if __name__ == '__main__':
    sys.exit(main())
