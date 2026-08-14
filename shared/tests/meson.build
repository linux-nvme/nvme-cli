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

test_base64_util = executable(
    'test-base64-util',
    ['test-base64-util.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        shared_dep,
    ],
)

test('shared - base64-util', test_base64_util)

test_crc32_util = executable(
    'test-crc32-util',
    ['test-crc32-util.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - crc32-util', test_crc32_util)

test_ini_util = executable(
    'test-ini-util',
    ['test-ini-util.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - ini-util', test_ini_util)

test_parse_util = executable(
    'test-parse-util',
    ['test-parse-util.c'],
    dependencies: [
        config_dep,
        ccan_dep,
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

test_cleanup_util = executable(
    'test-cleanup-util',
    ['test-cleanup-util.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - cleanup-util', test_cleanup_util)

test_wrap_util = executable(
    'test-wrap-util',
    ['test-wrap-util.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - wrap-util', test_wrap_util)

test_temp_util = executable(
    'test-temp-util',
    ['test-temp-util.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - temp-util', test_temp_util)

test_time_util = executable(
    'test-time-util',
    ['test-time-util.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - time-util', test_time_util)

test_progress_util = executable(
    'test-progress-util',
    ['test-progress-util.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - progress-util', test_progress_util)

test_table_util = executable(
    'test-table-util',
    ['test-table-util.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - table-util', test_table_util)

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

test_uint128_util = executable(
    'test-uint128-util',
    ['test-uint128-util.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        shared_dep,
    ],
)

test('shared - uint128-util', test_uint128_util)

test_int_util = executable(
    'test-int-util',
    ['test-int-util.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - int-util', test_int_util)

test_uuid_util = executable(
    'test-uuid-util',
    ['test-uuid-util.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - uuid-util', test_uuid_util)

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

test_mmio_util = executable(
    'test-mmio-util',
    ['test-mmio-util.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        shared_dep,
    ],
)

test('shared - mmio-util', test_mmio_util)

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

test_crypto_util_deps = [
    config_dep,
    shared_dep,
]
if host_system == 'windows'
    test_crypto_util_deps += [bcrypt_dep]
endif

test_crypto_util = executable(
    'test-crypto-util',
    ['test-crypto-util.c'],
    dependencies: test_crypto_util_deps,
)

test('shared - crypto-util', test_crypto_util)

test_sig_util = executable(
    'test-sig-util',
    ['test-sig-util.c'],
    dependencies: [
        config_dep,
        shared_dep,
    ],
)

test('shared - sig-util', test_sig_util)

if host_system != 'windows'
    test_assert_util = executable(
        'test-assert-util',
        ['test-assert-util.c'],
        dependencies: [
            config_dep,
            shared_dep,
        ],
    )

    test('shared - assert-util', test_assert_util)
endif
