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
    'nvme/fabrics.c',
    'nvme/filters.c',
    'nvme/ioctl.c',
    'nvme/linux.c',
    'nvme/log.c',
    'nvme/mi-mctp.c',
    'nvme/mi.c',
    'nvme/nbft.c',
    'nvme/sysfs.c',
    'nvme/tree.c',
    'nvme/util.c',
]

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
    accessors_dep,
]

ldfile = 'libnvme.ld'

libnvme = library(
    'nvme', # produces libnvme.so
    sources,
    version: libnvme_so_version,
    link_args: [
        '-Wl,--version-script=@0@'.format(meson.current_source_dir() / ldfile),
        '-Wl,--version-script=@0@'.format(accessors_ld_full_path),
    ],
    dependencies: deps,
    install: true,
)

# Explicitly create the symlinks in the same directory. When building the
# PyPI package (pipx run build --sdist), the symbolic link don't get installed
# unless we explicitly set them as below.
# 1st: libnvme.so.X -> libnvme.so.X.Y.Z
major_version = libnvme_so_version.split('.')[0]
install_symlink(
    'libnvme.so.@0@'.format(major_version),
    pointing_to: 'libnvme.so.@0@'.format(libnvme_so_version),
    install_dir: get_option('libdir'),
)

# 2nd: libnvme.so -> libnvme.so.X
major_version = libnvme_so_version.split('.')[0]
install_symlink(
    'libnvme.so',
    pointing_to: 'libnvme.so.@0@'.format(major_version),
    install_dir: get_option('libdir'),
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
