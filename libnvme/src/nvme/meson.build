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
# To regenerate them after changing private.h or structs-to-include.txt:
#
#   meson compile -C <build-dir> update-accessors

# ---------------------------------------------------------------------------
# Developer-only helper: build the generator and regenerate if structs change.
# NOT executed during a normal build (build_by_default: false).
# Usage: meson compile -C <build-dir> update-accessors
# ---------------------------------------------------------------------------

accessors_ld_full_path = meson.current_source_dir() / 'accessors.ld'

generate_accessors = executable(
    'generate-accessors',
    'generate-accessors.c',
    c_args: ['-D_GNU_SOURCE'],
    dependencies: [
        config_dep,
    ],
    native: true,
    build_by_default: false,
)

run_target(
    'update-accessors',
    command: [
        meson.current_source_dir() / 'update-accessors.sh',
        generate_accessors,
        meson.current_source_dir(),
        meson.current_source_dir() / 'generate-accessors-include.list',
        meson.current_source_dir() / 'generate-accessors-exclude.list',
        meson.current_source_dir() / 'private.h',
    ],
    depends: generate_accessors,
)
