# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>

python3_prog = find_program('python3', required: false)
if python3_prog.found()
    test(
        'libnvme - check-public-symbols',
        python3_prog,
        args: [
            files('../tools/check-public-symbols.py'),
            meson.project_source_root() / 'libnvme',
        ],
    )
    _ld_args = ['--ld', nvme_ld, '--ld', accessors_ld]
    if want_fabrics
        _ld_args += ['--ld', nvmf_ld, '--ld', nvmf_accessors_ld]
    endif
    _hdr_args = []
    foreach hdr : headers
        _hdr_args += ['--header', meson.project_source_root() / 'libnvme' / 'src' / hdr]
    endforeach
    test(
        'libnvme - check-public-headers',
        python3_prog,
        args: [files('../tools/check-public-headers.py')] + _ld_args + _hdr_args,
    )
endif

# These tests all require interaction with a real NVMe device, so we don't
# define as meson unit-tests, and therefore get run as part of the 'test'
# target. However, they're available for developer use, when hardware is
# available.
main = executable(
    'main-test',
    ['test.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_test_dep,
    ],
)

if cxx_available
    cpp = executable(
        'test-cpp',
        ['cpp.cc'],
        dependencies: [
            config_dep,
            ccan_dep,
            libnvme_dep,
        ],
    )

    test('libnvme - cpp-dump', cpp)

    misc = executable(
        'test-misc',
        ['misc.cc'],
        dependencies: [
            config_dep,
            ccan_dep,
            libnvme_dep,
        ],
    )
    test('libnvme - cpp-misc', misc)

endif

register = executable(
    'test-register',
    ['register.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_dep,
    ],
)

zns = executable(
    'test-zns',
    ['zns.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_test_dep,
    ],
)

if want_mi
    mi = executable(
        'test-mi',
        ['mi.c', 'utils.c'],
        dependencies: [
            config_dep,
            ccan_dep,
            libnvme_test_dep,
        ],
    )

    test('libnvme - mi', mi)

    mi_mctp = executable(
        'test-mi-mctp',
        ['mi-mctp.c', 'utils.c'],
        dependencies: [
            config_dep,
            ccan_dep,
            libnvme_test_dep,
        ],
    )

    test('libnvme - mi-mctp', mi_mctp)
endif

uuid = executable(
    'test-uuid',
    ['uuid.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_dep,
    ],
)

test('libnvme - uuid', uuid)

if want_fabrics
    uriparser = executable(
        'test-uriparser',
        ['uriparser.c'],
        dependencies: [
            config_dep,
            ccan_dep,
            libnvme_dep,
        ],
    )

    test('libnvme - uriparser', uriparser)

    test_fabrics = executable(
        'test-fabrics',
        ['test-fabrics.c'],
        # -fgnu89-inline: '#define static' (used to expose static helpers
        # for unit testing) turns 'static inline' into plain 'inline'.
        # Under C99, plain 'inline' has external linkage and may require an
        # external symbol definition that doesn't exist for header-only
        # inline functions.  GNU89 semantics treat it as an inlining hint
        # only, avoiding the linker failure in -static builds.
        c_args: ['-fgnu89-inline'],
        dependencies: [
            config_dep,
            ccan_dep,
            libnvme_test_dep,
        ],
    )

    test('libnvme - fabrics', test_fabrics)
endif

if conf.get('HAVE_NETDB')
    mock_ifaddrs = library(
        'mock-ifaddrs',
        ['mock-ifaddrs.c', ],
    )

    # See comment in test/ioctl/meson.build explaining how LD_PRELOAD is used
    mock_ifaddrs_env = environment()
    mock_ifaddrs_env.append('LD_PRELOAD', mock_ifaddrs.full_path())
    mock_ifaddrs_env.set('ASAN_OPTIONS', 'verify_asan_link_order=0')

    tree = executable(
        'tree',
        ['tree.c'],
        dependencies: [
            config_dep,
            ccan_dep,
            libnvme_test_dep,
        ],
        link_with: mock_ifaddrs,
    )

    test('libnvme - tree', tree, env: mock_ifaddrs_env)

    test_util = executable(
        'test-util',
        ['test-util.c'],
        dependencies: [
            config_dep,
            ccan_dep,
            libnvme_test_dep,
        ],
    )
    test('libnvme - util', test_util)
endif

psk = executable(
    'test-psk',
    ['psk.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_dep,
    ],
)

test('libnvme - psk', psk)

subdir('ioctl')
if want_fabrics
    subdir('nbft')
endif

if json_c_dep.found()
    subdir('sysfs')
    subdir('config')
endif

if openssl_dep.found()
    hkdf_add1 = executable(
        'hkdf_add1',
        ['hkdf_add1.c'],
        dependencies: openssl_dep,
    )
endif

foreach hdr : [
    'endian',
    'fabrics',
    'filters',
    'ioctl',
    'lib',
    'lib-types',
    'linux',
    'mi',
    'nbft',
    'nbft-types',
    'nvme-cmds',
    'nvme-types',
    'tree',
    'util',
]
    hdr_conf = configuration_data()
    hdr_conf.set('HDR', hdr)
    src = configure_file(
        input: 'test-header.c.in',
        output: 'test-header-' + hdr + '.c',
        configuration: hdr_conf,
    )
    exe = executable(
        'test-header-' + hdr,
        src,
        dependencies: [libnvme_dep],
    )
    test('libnvme - header/' + hdr, exe)
endforeach
