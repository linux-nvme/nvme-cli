# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
#

discoverd_sources = files(
    'src/cache.c',
    'src/config.c',
    'src/dlp.c',
    'src/events.c',
    'src/fc.c',
    'src/log.c',
    'src/main.c',
    'src/state.c',
    'src/tid.c',
    'src/units.c',
)

discoverd_inc = include_directories('src')

# Absolute path to the nvme binary that the transient units exec (units.c).
nvme_bin_path = sbindir / 'nvme'

executable(
    'nvme-discoverd',
    discoverd_sources,
    include_directories: discoverd_inc,
    c_args: [
        '-DNVME_PATH="@0@"'.format(nvme_bin_path),
    ],
    dependencies: [
        ccan_dep,
        libnvme_dep,
        libsystemd_dep,
    ],
    install: true,
    install_dir: sbindir,
)

configure_file(
    input: 'systemd/nvme-discoverd.service.in',
    output: 'nvme-discoverd.service',
    configuration: substs,
    install: true,
    install_dir: systemddir,
)

# Unlike nvme-fabrics.conf (re-read on every connect/connect-all/discover,
# and holding host-specific connections an admin customizes), discoverd.conf
# is read once at daemon startup and holds only generic daemon knobs, so it
# installs directly as the live file rather than a .sample a user must copy.
configure_file(
    input: 'etc/nvme/discoverd.conf.in',
    output: 'discoverd.conf',
    configuration: substs,
    install: true,
    install_dir: sysconfdir / 'nvme',
)
