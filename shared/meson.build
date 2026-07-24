# SPDX-License-Identifier: GPL-2.0-or-later
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
    'fs-util.c',
    'parse-util.c',
]

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
