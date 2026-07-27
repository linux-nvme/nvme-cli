# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
#
# Small utility library shared across nvme-cli, libnvme, nvme-discoverd, and
# the Python bindings. The utilities are split by topic (one concern per file),
# not lumped into a single header. Files with no real implementation (just
# static inline functions/macros) are header-only.

sources = [
    'array-util.c',
    'base64.c',
    'crc32.c',
    'fs-util.c',
    'ini.c',
    'parse-util.c',
]

# net-util.c wraps POSIX socket/interface APIs (ifaddrs.h, net/if.h) that
# MinGW does not provide. Only NVMe-oF code calls into it, and fabrics
# support is unavailable on Windows already (see want_fabrics), so it is
# excluded rather than stubbed.
if host_system != 'windows'
    sources += [
        'net-util.c',
    ]
endif

libshared = static_library(
    'shared',
    sources,
    install: false,
    dependencies: [ccan_dep],
)

shared_dep = declare_dependency(
    include_directories: '.',
    link_with: libshared,
)
