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
    config_h,
]

if conf.get('CONFIG_JSONC')
    sources += 'nvme/json.c'
endif

deps = [
    libuuid,
    json_c,
]

source_dir = meson.current_source_dir()
mapfile = 'libnvme.map'
version_script_arg = join_paths(source_dir, mapfile)

libnvme = library(
    'nvme', # produces libnvme.so
    sources,
    version: libnvme_version,
    soversion: '1',
    link_args: ['-Wl,--version-script=' + version_script_arg],
    dependencies: deps,
    link_depends: mapfile,
    include_directories: incdir,
    install: true,
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
    include_directories: incdir,
    link_with: libnvme,
)

mode = ['rw-r--r--', 0, 0]
install_headers('libnvme.h', install_mode: mode)
install_headers([
        'nvme/fabrics.h',
        'nvme/filters.h',
        'nvme/ioctl.h',
        'nvme/log.h',
        'nvme/tree.h',
        'nvme/types.h',
        'nvme/util.h',
    ],
    subdir: 'nvme',
    install_mode: mode,
)
