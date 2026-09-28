# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
#
# Code shared by the nvme-cli daemons. It needs libsystemd, so it cannot live
# in shared/, which is also built for Windows.

daemon_util_lib = static_library(
    'daemon-util',
    files(
        'log.c',
        'signals.c',
    ),
    dependencies: [
        ccan_dep,
        libsystemd_dep,
    ],
)

daemon_util_dep = declare_dependency(
    link_with: daemon_util_lib,
    include_directories: '..',
    dependencies: libsystemd_dep,
)
