# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
#

keysd_sources = files(
    'src/config.c',
    'src/creds.c',
    'src/import.c',
    'src/main.c',
)

keysd_inc = include_directories('src')

nvme_keysd = executable(
    'nvme-keysd',
    keysd_sources,
    include_directories: keysd_inc,
    dependencies: [
        ccan_dep,
        daemon_util_dep,
        libnvme_dep,
        libsystemd_dep,
        shared_dep,
    ],
    install: true,
    install_dir: sbindir,
)

if get_option('tests')
    subdir('tests')
endif

configure_file(
    input: 'systemd/nvme-keysd.service.in',
    output: 'nvme-keysd.service',
    configuration: substs,
    install: true,
    install_dir: systemddir,
)

# The encrypted credentials. Only root reads them.
install_emptydir(sysconfdir / 'nvme' / 'creds', install_mode: 'rwx------')

configure_file(
    input: 'etc/nvme/nvme-keysd.conf.in',
    output: 'nvme-keysd.conf',
    configuration: substs,
    install: true,
    install_dir: sysconfdir / 'nvme',
)
