# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
#

discoverd_sources = files(
    'src/config.c',
    'src/log.c',
    'src/main.c',
    'src/state.c',
)

discoverd_inc = include_directories('src')

executable(
    'nvme-discoverd',
    discoverd_sources,
    include_directories: discoverd_inc,
    dependencies: [
        libnvme_dep,
        libsystemd_dep,
    ],
    install: true,
    install_dir: sbindir,
)
