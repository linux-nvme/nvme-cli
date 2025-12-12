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

# Build the code generator tool
generate_accessors = executable(
    'generate-accessors',
    'generate-accessors.c',
    c_args: [
        '-include', nvme_config_h_path,
    ],
    native: true,
)

# Generate accessors.c and accessors.h
accessors_ch_custom_tgt = custom_target(
    'accessors.[ch]',
    input: files(headers_to_scan),
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
    install_mode: 'rw-r--r--',
)

tgt_accessors_h = accessors_ch_custom_tgt[0]
tgt_accessors_c = accessors_ch_custom_tgt[1]

if meson.version().version_compare('>=1.4.0')
    accessors_h_full_path = tgt_accessors_h.full_path()
else
    accessors_h_full_path = meson.current_build_dir() / 'accessors.h'
endif

hdrs_incdir = []
foreach hdr : headers_to_scan
    hdrs_incdir += include_directories(fs.parent(hdr))
endforeach
accessors_incdir = [incdir, ] + hdrs_incdir

libaccessors = static_library(
    'accessors', # produces libaccessors.a
    tgt_accessors_c,
    install: false,
    include_directories: accessors_incdir,
    c_args: [
        '-include', nvme_config_h_path,
    ],
    dependencies: [
        config_dep,
    ],
)
