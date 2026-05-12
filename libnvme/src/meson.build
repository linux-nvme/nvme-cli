# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
sources = []
if host_system == 'windows'
    sources += [
        'nvme/mem-win.c',
    ]
else
    sources += [
        'nvme/accessors.c',
        'nvme/base64.c',
        'nvme/crc32.c',
        'nvme/filters.c',
        'nvme/ioctl.c',
        'nvme/lib.c',
        'nvme/linux.c',
        'nvme/log.c',
        'nvme/mem-linux.c',
        'nvme/nvme-cmds.c',
        'nvme/sysfs.c',
        'nvme/tree.c',
        'nvme/util.c',
    ]
endif
headers = [
    'nvme/accessors.h',
    'nvme/endian.h',
    'nvme/filters.h',
    'nvme/ioctl.h',
    'nvme/lib-types.h',
    'nvme/lib.h',
    'nvme/linux.h',
    'nvme/mem.h',
    'nvme/nvme-cmds.h',
    'nvme/nvme-types.h',
    'nvme/tree.h',
    'nvme/types.h',
    'nvme/util.h',
]

if want_fabrics
    sources += [
        'nvme/accessors-fabrics.c',
        'nvme/fabrics.c',
        'nvme/nbft.c',
        'nvme/util-fabrics.c',
    ]
    headers += [
        'nvme/accessors-fabrics.h',
        'nvme/fabrics.h',
        'nvme/nbft-types.h',
        'nvme/nbft.h',
    ]
else
    sources += [
        'nvme/no-fabrics.c',
    ]
endif

if want_mi
    sources += [
        'nvme/mi-mctp.c',
        'nvme/mi.c',
    ]
    headers += [
        'nvme/mi-types.h',
        'nvme/mi.h',
    ]
else
    sources += [
        'nvme/no-mi.c'
    ]
endif

if liburing_dep.found()
    sources += 'nvme/uring.c'
else
    sources += 'nvme/no-uring.c'
endif

if json_c_dep.found() and want_fabrics
    sources += 'nvme/json.c'
else
    sources += 'nvme/no-json.c'
endif

deps = [
    ccan_dep,
    config_dep,
    json_c_dep,
    keyutils_dep,
    libdbus_dep,
    liburing_dep,
    openssl_dep,
]
if host_system == 'windows'
    deps += [
        kernel32_dep
    ]
endif

nvme_ld = meson.current_source_dir() / 'libnvme.ld'
nvmf_ld = meson.current_source_dir() / 'libnvmf.ld'
accessors_ld = meson.current_source_dir() / 'accessors.ld'
nvmf_accessors_ld = meson.current_source_dir() / 'accessors-fabrics.ld'

link_args = [
    '-Wl,--version-script=@0@'.format(nvme_ld),
    '-Wl,--version-script=@0@'.format(accessors_ld),
]

libconf = configuration_data()
if want_fabrics
    link_args += [
        '-Wl,--version-script=@0@'.format(nvmf_ld),
        '-Wl,--version-script=@0@'.format(nvmf_accessors_ld),
    ]
    libconf.set('FABRICS_INCLUDE',
                '#include <nvme/fabrics.h>\n#include <nvme/nbft.h>\n#include <nvme/accessors-fabrics.h>')
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
    c_args: ['-fvisibility=hidden'],
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
    headers,
    subdir: 'nvme',
    install_mode: mode,
)
if want_mi
    install_headers(
        [
           'libnvme-mi.h',
        ],
        install_mode: mode,
    )
endif

