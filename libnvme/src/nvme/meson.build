# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
# Run generate-accessors to generate the setter/getter functions.

generated_h = 'accessors.h'
generated_c = 'accessors.c'
generated_ld = 'accessors.ld'

# List of header files to parse for structs
headers_to_scan = [
    '../nvme/private.h',
]

# Build the code generator tool
generate_accessors = executable(
    'generate-accessors',
    'generate-accessors.c',
    dependencies: [
        config_dep,
    ],
    native: true,
)

# Generate accessors code
accessors_ch_custom_tgt = custom_target(
    'accessors[.c.h.ld]',
    input: files(headers_to_scan),
    output: [
        generated_h,
        generated_c,
        generated_ld,
    ],
    command: [
        generate_accessors,
        '--h-out', '@OUTPUT0@',
        '--c-out', '@OUTPUT1@',
        '--ld-out', '@OUTPUT2@',
        '--incl', join_paths(meson.current_source_dir(), 'structs-to-include.txt'),
        '@INPUT@',
    ],
    build_by_default: true,
    install: true,
    install_dir: [
        get_option('includedir') / 'nvme',
        false,
        false,
    ],
    install_mode: 'rw-r--r--',
)

tgt_accessors_h = accessors_ch_custom_tgt[0]
tgt_accessors_c = accessors_ch_custom_tgt[1]
tgt_accessors_ld = accessors_ch_custom_tgt[2]

accessors_dep = declare_dependency(
    sources: [
        tgt_accessors_c,
        tgt_accessors_h,
    ],
    include_directories: '.',
)

if meson.version().version_compare('>=1.4.0')
    accessors_ld_full_path = tgt_accessors_ld.full_path()
else
    accessors_ld_full_path = meson.current_build_dir() / generated_ld
endif
