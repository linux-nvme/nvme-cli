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
        libnvme_dep,
        libsystemd_dep,
    ],
    install: true,
    install_dir: sbindir,
)
