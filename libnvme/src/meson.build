# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
sources = [
    'nvme/accessors.c',
    'nvme/base64.c',
    'nvme/cmds.c',
    'nvme/crc32.c',
    'nvme/filters.c',
    'nvme/ioctl.c',
    'nvme/lib.c',
    'nvme/linux.c',
    'nvme/log.c',
    'nvme/mi-mctp.c',
    'nvme/mi.c',
    'nvme/sysfs.c',
    'nvme/tree.c',
    'nvme/util.c',
]
headers = [
    'nvme/accessors.h',
    'nvme/cmds.h',
    'nvme/filters.h',
    'nvme/ioctl.h',
    'nvme/lib-types.h',
    'nvme/lib.h',
    'nvme/linux.h',
    'nvme/mi.h',
    'nvme/tree.h',
    'nvme/types.h',
    'nvme/util.h',
]

if want_fabrics
    sources += [
        'nvme/fabrics.c',
        'nvme/nbft.c',
    ]
    headers += [
        'nvme/fabrics.h',
        'nvme/nbft.h',
    ]
endif

if json_c_dep.found()
    sources += 'nvme/json.c'
else
    sources += 'nvme/no-json.c'
endif

subdir('nvme')  # declares: accessors_ld_full_path

deps = [
    config_dep,
    ccan_dep,
    json_c_dep,
    keyutils_dep,
    libdbus_dep,
    liburing_dep,
    openssl_dep,
]

nvme_ld = meson.current_source_dir() / 'libnvme.ld'
nvmf_ld = meson.current_source_dir() / 'libnvmf.ld'

link_args = [
    '-Wl,--version-script=@0@'.format(nvme_ld),
    '-Wl,--version-script=@0@'.format(accessors_ld_full_path),
]

libconf = configuration_data()
if want_fabrics
    link_args += '-Wl,--version-script=@0@'.format(nvmf_ld)
    libconf.set('FABRICS_INCLUDE',
                '#include <nvme/fabrics.h>\n#include <nvme/nbft.h>')
else
    libconf.set('FABRICS_INCLUDE', '')
endif

libnvme_header = configure_file(
    input: 'libnvme.h.in',
    output: 'libnvme.h',
    configuration: libconf,
    install: true,
    install_dir: prefixdir / get_option('includedir')
)

libnvme = library(
    'nvme', # produces libnvme.so
    sources,
    version: libnvme_so_version,
    link_args: link_args,
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
       'libnvme-mi.h',
    ],
    install_mode: mode,
)
install_headers(
    headers,
    subdir: 'nvme',
    install_mode: mode,
)
