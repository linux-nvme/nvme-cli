# SPDX-License-Identifier: GPL-2.0-or-later

test_uint128 = executable(
    'test-uint128',
    ['test-uint128.c', '../util/types.c', '../util/suffix.c'],
    include_directories: [incdir, '..'],
    dependencies: [libnvme_dep],
)

test('uint128', test_uint128)

test_suffix_si_parse = executable(
    'test-suffix-si-parse',
    ['test-suffix-si-parse.c', '../util/suffix.c'],
    include_directories: [incdir, '..'],
    dependencies: [libnvme_dep],
)

test('suffix_si_parse', test_suffix_si_parse)

test_suffix_binary_parse = executable(
    'test-suffix-binary-parse',
    ['test-suffix-binary-parse.c', '../util/suffix.c'],
    include_directories: [incdir, '..'],
    dependencies: [libnvme_dep],
)

test('suffix_binary_parse', test_suffix_binary_parse)

test_uint128_si = executable(
    'test-uint128-si',
    ['test-uint128-si.c', '../util/types.c', '../util/suffix.c'],
    include_directories: [incdir, '..'],
    dependencies: [libnvme_dep],
)

test('uint128-si', test_uint128_si)
