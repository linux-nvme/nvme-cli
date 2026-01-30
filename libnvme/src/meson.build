# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
sources = [
    'nvme/base64.c',
    'nvme/crc32.c',
    'nvme/ioctl.c',
    'nvme/log.c',
    'nvme/nbft.c',
    'nvme/util.c',
]

# Platform-specific sources
if is_windows
    # Windows-specific sources (exclude Linux networking, fabrics, and filesystem code)
    sources += [
        'nvme/windows-stubs.c',  # Stubs for excluded functions
    ]
else
    # Linux-specific sources (include networking and fabrics support)
    sources += [
        'nvme/fabrics.c',
        'nvme/filters.c',
        'nvme/linux.c',
        'nvme/mi-mctp.c',
        'nvme/mi.c',
        'nvme/tree.c',
        'nvme/sysfs.c',
    ]
endif

if json_c_dep.found()
    sources += 'nvme/json.c'
else
    sources += 'nvme/no-json.c'
endif

# Generate accessors (setter/getter functions)
subdir('nvme')  # declares: accessors_dep, accessors_ld_full_path

deps = [
    config_dep,
    ccan_dep,
    json_c_dep,
    keyutils_dep,
    libdbus_dep,
    liburing_dep,
    openssl_dep,
]

# Skipping accessor generation for now on Windows. Needs to be ported.
if not is_windows
    deps += [
        accessors_dep,
    ]
endif

# Add Windows-specific networking libraries
if is_windows
    deps += [
        cc.find_library('ws2_32'),
        cc.find_library('wsock32'),
        cc.find_library('iphlpapi'),
        cc.find_library('bcrypt'),  # For BCryptGenRandom in nvme_uuid_random
    ]
endif

ldfile = 'libnvme.ld'

libnvme_link_args = [
    '-Wl,--version-script=@0@'.format(meson.current_source_dir() / ldfile),
]
# Skipping accessor generation for now on Windows. Needs to be ported.
if not is_windows
    libnvme_link_args += [
        '-Wl,--version-script=@0@'.format(accessors_ld_full_path),
    ]
endif

libnvme = library(
    'nvme', # produces libnvme.so
    sources,
    version: libnvme_so_version,
    link_args: libnvme_link_args,
    dependencies: deps,
    install: true,
)

pkg = import('pkgconfig')
pkg.generate(libnvme,
    filebase: 'libnvme',
    name: 'libnvme',
    version: libnvme_so_version,
    description: 'Manage "libnvme" subsystem devices (Non-volatile Memory Express)',
    url: 'https://github.com/linux-nvme/nvme-cli/',
)

libnvme_dep = declare_dependency(
    dependencies: [
        json_c_dep.partial_dependency(compile_args: true, includes: true),
    ],
    link_with: libnvme,
    include_directories: '.',
)

# test library with all symbols visible, to use for MI unit tests. Should
# match libnvme above, but with no version script, and install: false.
libnvme_test = library(
    'nvme-test', # produces libnvme-test.so
    sources,
    dependencies: deps,
    install: false,
)

libnvme_test_dep = declare_dependency(
    link_with: libnvme_test,
    include_directories: '.',
)

mode = 'rw-r--r--'
install_headers(
    [
       'libnvme.h',
       'libnvme-mi.h',
    ],
    install_mode: mode,
)
install_headers(
    [
        'nvme/fabrics.h',
        'nvme/filters.h',
        'nvme/ioctl.h',
        'nvme/linux.h',
        'nvme/log.h',
        'nvme/nbft.h',
        'nvme/tree.h',
        'nvme/types.h',
        'nvme/util.h',
        'nvme/mi.h',
    ],
    subdir: 'nvme',
    install_mode: mode,
)

# Install platform abstraction headers
install_headers([
        'nvme/platform/platform_includes.h',
        'nvme/platform/platform_linux.h',
        'nvme/platform/platform_windows.h',
    ],
    subdir: 'nvme/platform',
    install_mode: mode,
)
