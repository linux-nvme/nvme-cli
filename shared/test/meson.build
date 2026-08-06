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

if host_system != 'windows'
    test_ini = executable(
        'test-ini',
        ['test-ini.c'],
        dependencies: [
            config_dep,
            shared_dep,
        ],
    )

    test('shared - ini', test_ini)
endif

test_parse_util = executable(
    'test-parse-util',
    ['test-parse-util.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - parse-util', test_parse_util)

test_hex_util = executable(
    'test-hex-util',
    ['test-hex-util.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - hex-util', test_hex_util)

test_table = executable(
    'test-table',
    ['test-table.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - table', test_table)

test_suffix_util = executable(
    'test-suffix-util',
    ['test-suffix-util.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        shared_dep,
    ],
)

test('shared - suffix-util', test_suffix_util)

test_hash_util = executable(
    'test-hash-util',
    ['test-hash-util.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - hash-util', test_hash_util)

test_string_util = executable(
    'test-string-util',
    ['test-string-util.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - string-util', test_string_util)

test_io_util = executable(
    'test-io-util',
    ['test-io-util.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - io-util', test_io_util)

test_fs_util = executable(
    'test-fs-util',
    ['test-fs-util.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - fs-util', test_fs_util)

if host_system != 'windows'
    test_net_util = executable(
        'test-net-util',
        ['test-net-util.c'],
        dependencies: [
            config_dep,
            shared_dep,
        ],
    )

    test('shared - net-util', test_net_util)
endif

if host_system != 'windows'
    test_crypto_util = executable(
        'test-crypto-util',
        ['test-crypto-util.c'],
        dependencies: [
            config_dep,
            shared_dep,
        ],
    )

    test('shared - crypto-util', test_crypto_util)
endif

if host_system != 'windows'
    test_sig_util = executable(
        'test-sig-util',
        ['test-sig-util.c'],
        dependencies: [
            config_dep,
            shared_dep,
        ],
    )

    test('shared - sig-util', test_sig_util)
endif

if host_system != 'windows'
    test_shr_assert = executable(
        'test-shr-assert',
        ['test-shr-assert.c'],
        dependencies: [
            config_dep,
            shared_dep,
        ],
    )

    test('shared - shr-assert', test_shr_assert)
endif
