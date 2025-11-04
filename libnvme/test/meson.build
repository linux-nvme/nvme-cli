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
    dependencies: [libnvme_dep],
    include_directories: [incdir, internal_incdir]
)

if cxx_available
    cpp = executable(
        'test-cpp',
        ['cpp.cc'],
        dependencies: libnvme_dep,
        include_directories: [incdir, internal_incdir]
    )

    test('cpp-dump', cpp)

    misc = executable(
        'test-misc',
        ['misc.cc'],
        dependencies: libnvme_dep,
        include_directories: [incdir, internal_incdir]
    )
    test('cpp-misc', misc)

endif

register = executable(
    'test-register',
    ['register.c'],
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir]
)

zns = executable(
    'test-zns',
    ['zns.c'],
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir]
)

mi = executable(
    'test-mi',
    ['mi.c', 'utils.c'],
    dependencies: libnvme_mi_test_dep,
    include_directories: [incdir, internal_incdir]
)

test('mi', mi)

mi_mctp = executable(
    'test-mi-mctp',
    ['mi-mctp.c', 'utils.c'],
    dependencies: libnvme_mi_test_dep,
    include_directories: [incdir, internal_incdir],
)

test('mi-mctp', mi_mctp)

uuid = executable(
    'test-uuid',
    ['uuid.c'],
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir]
)

test('uuid', uuid)

uriparser = executable(
    'test-uriparser',
    ['uriparser.c'],
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir]
)

test('uriparser', uriparser)

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
        dependencies: libnvme_dep,
        include_directories: [incdir, internal_incdir],
        link_with: mock_ifaddrs,
    )

    test('tree', tree, env: mock_ifaddrs_env)

    test_util = executable(
        'test-util',
        ['test-util.c'],
        include_directories: [incdir, internal_incdir]
    )
    test('util', test_util)
endif

psk = executable(
    'test-psk',
    ['psk.c'],
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir]
)

test('psk', psk)

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
