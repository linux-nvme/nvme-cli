#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""A build with nvme-discoverd installs none of the legacy autoconnect.

The legacy udev rule would connect in parallel to nvme-discoverd, and
the dracut configuration would pull it into the initrd (issues #4327 and
#4328). Only checked for -Dnvmf-autoconnect=auto: "enabled" installs both
on purpose.

Usage: python3 test_install.py <build directory>
Exits 77 (skipped) without meson's install manifest, e.g. with muon.
"""
import json
import sys
from pathlib import Path

LEGACY = (
    '70-nvmf-autoconnect.rules',
    '70-nvmf-autoconnect.conf',
    'nvmf-connect@.service',
    'nvmf-autoconnect.service',
    'nvmefc-boot-connections.service',
    'nvmf-connect.target',
    'nvmf-connect-nbft.service',
    '80-nvmf-connect-nbft.sh',
)


def main():
    manifest = Path(sys.argv[1]) / 'meson-info/intro-installed.json'
    if not manifest.exists():
        print(f'SKIP: no {manifest}')
        return 77

    installed = json.loads(manifest.read_text(encoding='utf-8')).values()
    found = sorted(path for path in installed
                   if Path(path).name in LEGACY)
    if found:
        print('installed with nvme-discoverd:\n  ' + '\n  '.join(found))
        return 1

    print(f'none of {len(LEGACY)} legacy autoconnect files is installed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
