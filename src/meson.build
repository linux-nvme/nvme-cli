# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
sources = [
    'nvme/cleanup.c',
    'nvme/fabrics.c',
    'nvme/filters.c',
    'nvme/ioctl.c',
    'nvme/linux.c',
    'nvme/log.c',
    'nvme/tree.c',
    'nvme/util.c',
]

mi_sources = [
    'nvme/cleanup.c',
    'nvme/log.c',
    'nvme/mi.c',
    'nvme/mi-mctp.c',
]

if conf.get('CONFIG_JSONC')
    sources += 'nvme/json.c'
endif

deps = [
    json_c_dep,
    openssl_dep,
]

mi_deps = [
    libdbus_dep,
]

source_dir = meson.current_source_dir()
mapfile = 'libnvme.map'
version_script_arg = join_paths(source_dir, mapfile)
mi_mapfile = 'libnvme-mi.map'
mi_version_script_arg = join_paths(source_dir, mi_mapfile)

libnvme = library(
    'nvme', # produces libnvme.so
    sources,
    version: library_version,
    link_args: ['-Wl,--version-script=' + version_script_arg],
    dependencies: deps,
    link_depends: mapfile,
    include_directories: [incdir, internal_incdir],
    install: true,
    link_with: libccan,
)

pkg = import('pkgconfig')
pkg.generate(libnvme,
    filebase: meson.project_name(),
    name: meson.project_name(),
    version: meson.project_version(),
    description: 'Manage "libnvme" subsystem devices (Non-volatile Memory Express)',
    url: 'http://github.com/linux-nvme/libnvme/',
)

libnvme_dep = declare_dependency(
    include_directories: ['.'],
    dependencies: [
      json_c_dep.partial_dependency(compile_args: true, includes: true),
    ],
    link_with: libnvme,
)

libnvme_mi = library(
    'nvme-mi', # produces libnvme-mi.so
    mi_sources,
    version: library_version,
    link_args: ['-Wl,--version-script=' + mi_version_script_arg],
    dependencies: mi_deps,
    link_depends: mi_mapfile,
    include_directories: [incdir, internal_incdir],
    install: true,
    link_with: libccan,
)

libnvme_mi_dep = declare_dependency(
    include_directories: ['.'],
    link_with: libnvme_mi,
)

# test library with all symbols visible, to use for MI unit tests. Should
# match libnvme_mi above, but with no version script, and install: false.
libnvme_mi_test = library(
    'nvme-mi-test', # produces libnvme-mi-test.so
    mi_sources,
    dependencies: mi_deps,
    include_directories: [incdir, internal_incdir],
    install: false,
    link_with: libccan,
)

libnvme_mi_test_dep = declare_dependency(
    include_directories: ['.'],
    link_with: libnvme_mi_test,
)

pkg.generate(libnvme_mi,
    filebase: 'libnvme-mi',
    name: 'libnvme-mi',
    version: meson.project_version(),
    description: 'Manage "libnvme" subsystem devices (Non-volatile Memory Express) over Management Interface',
    url: 'http://github.com/linux-nvme/libnvme/',
)

mode = ['rw-r--r--', 0, 0]
install_headers('libnvme.h', install_mode: mode)
install_headers('libnvme-mi.h', install_mode: mode)
install_headers([
        'nvme/api-types.h',
        'nvme/fabrics.h',
        'nvme/filters.h',
        'nvme/ioctl.h',
        'nvme/linux.h',
        'nvme/log.h',
        'nvme/tree.h',
        'nvme/types.h',
        'nvme/util.h',
        'nvme/mi.h',
    ],
    subdir: 'nvme',
    install_mode: mode,
)
