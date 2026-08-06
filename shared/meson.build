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
    'hex-util.c',
    'ini.c',
    'parse-util.c',
    'shr-assert.c',
    'suffix-util.c',
]

if host_system == 'windows'
    sources += [
        'fs-util-win.c',
        'crypto-util-win.c',
        'sig-util-win.c',
    ]
else
    sources += [
        'fs-util-linux.c',
        'net-util-linux.c',
        'crypto-util-linux.c',
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
    include_directories: '.',
    link_with: libshared,
)

if want_tests
    subdir('test')
endif
