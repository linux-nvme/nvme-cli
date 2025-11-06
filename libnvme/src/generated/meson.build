# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
# Run generate-accessors to generate the setter/getter functions.

# List of header files to parse for structs
headers_to_scan = [
    '../nvme/private.h',
]

# Append full path to each member of headers_to_scan
headers_to_scan_full_path = []
foreach hdr : headers_to_scan
    headers_to_scan_full_path += join_paths(meson.current_source_dir(), hdr)
endforeach

# Generate accessors.c and accessors.h
accessors_ch_custom_tgt = custom_target(
    'accessors.[ch]',
    input: headers_to_scan_full_path,
    output: [
        'accessors.h',
        'accessors.c',
    ],
    command: [
        generate_accessors,
        '--h-out', '@OUTPUT0@',
        '--c-out', '@OUTPUT1@',
        '--incl', join_paths(meson.current_source_dir(), 'structs-to-include.txt'),
        '@INPUT@',
    ],
    build_by_default: true,
    install: true,
    install_dir: [
        'nvme',       # Install @OUTPUT0@=='accessors.h' in this directory.
        false,        # Do not install @OUTPUT1@=='accessors.c'
    ],
    install_mode: ['rw-r--r--', 0, 0],
)

generated_accessors_h = accessors_ch_custom_tgt[0]
generated_accessors_c = accessors_ch_custom_tgt[1]

if meson.version().version_compare('>=1.4.0')
    generated_accessors_h_path = generated_accessors_h.full_path()
else
    generated_accessors_h_path = meson.current_build_dir() / 'accessor.h'
endif

generated_accessors_dep = declare_dependency(
    sources: [
        accessors_ch_custom_tgt,
    ]
)
