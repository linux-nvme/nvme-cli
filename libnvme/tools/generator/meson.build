# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
# The accessor files (accessors.h, accessors.c, accessors.ld) are
# pre-generated and committed to the source tree.  They are NOT
# regenerated during a normal build.
#
# To regenerate them after changing private.h or the include/exclude lists:
#
#   meson compile -C <build-dir> update-accessors

# ---------------------------------------------------------------------------
# Developer-only helper: build the generator and regenerate if structs change.
# NOT executed during a normal build (build_by_default: false).
# Usage: meson compile -C <build-dir> update-accessors
# ---------------------------------------------------------------------------

# Generated source files go to src/nvme/ (alongside the library sources).
# The generated version script goes to src/ (alongside the other .ld files).
libnvme_src = libnvme_srcroot / 'src'
libnvme_src_nvme = libnvme_src / 'nvme'

generate_accessors = executable(
    'generate-accessors',
    [
        'generate-accessors.c',
    ],
    c_args: [
        '-D_GNU_SOURCE',
    ],
    dependencies: [
        config_dep,
    ],
    native: true,
    build_by_default: false,
)

run_target(
    'update-accessors',
    command: [
        'update-accessors.sh',
        generate_accessors,
        libnvme_src_nvme,
        libnvme_src,
        meson.current_source_dir() / 'generate-accessors-include.list',
        meson.current_source_dir() / 'generate-accessors-exclude.list',
        libnvme_src_nvme / 'private.h',
    ],
    depends: generate_accessors,
)
