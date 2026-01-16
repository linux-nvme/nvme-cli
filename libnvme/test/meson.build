# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>

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
        libnvme_dep,
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
        libnvme_dep,
    ],
)

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
            libnvme_dep,
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
subdir('nbft')

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
