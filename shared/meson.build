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
    'assert-util.c',
    'base64-util.c',
    'crc32-util.c',
    'fs-util.c',
    'hex-util.c',
    'ini-util.c',
    'int-util.c',
    'parse-util.c',
    'progress-util.c',
    'suffix-util.c',
    'table-util.c',
    'time-util.c',
    'uint128-util.c',
    'uuid-util.c',
    'wrap-util.c',
]

if host_system == 'windows'
    sources += [
        'fs-util-win.c',
        'crypto-util-win.c',
        'proc-util-win.c',
        'sig-util-win.c',
    ]
else
    sources += [
        'fs-util-linux.c',
        'net-util-linux.c',
        'crypto-util-linux.c',
        'proc-util-linux.c',
        'sig-util-linux.c',
    ]
endif

shared_deps = [ccan_dep]
if host_system != 'windows'
    shared_deps += [openssl_dep]
endif

libshared = static_library(
    'shared',
    sources,
    install: false,
    dependencies: shared_deps,
)

shared_dep = declare_dependency(
    include_directories: '..',
    link_with: libshared,
)

if want_tests
    subdir('tests')
endif
