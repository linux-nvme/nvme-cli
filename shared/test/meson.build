# SPDX-License-Identifier: LGPL-2.1-or-later

test_array_util = executable(
    'test-array-util',
    ['test-array-util.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        shared_dep,
    ],
)

test('shared - array-util', test_array_util)

test_base64 = executable(
    'test-base64',
    ['test-base64.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        shared_dep,
    ],
)

test('shared - base64', test_base64)

test_crc32 = executable(
    'test-crc32',
    ['test-crc32.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - crc32', test_crc32)

test_ini = executable(
    'test-ini',
    ['test-ini.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - ini', test_ini)
