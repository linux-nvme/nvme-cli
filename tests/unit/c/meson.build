# SPDX-License-Identifier: GPL-2.0-or-later

test_argconfig_parse = executable(
    'test-argconfig-parse',
    ['test-argconfig-parse.c', '../../../src/argconfig.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_dep,
        shared_dep,
    ],
)

test('nvme-cli - argconfig-parse', test_argconfig_parse, suite: 'unit')

test_argconfig_diff = executable(
    'test-argconfig-diff',
    [
        'test-argconfig-diff.c',
        'argconfig-getopt-ref.c',
        '../../../src/argconfig.c',
    ],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_dep,
        shared_dep,
    ],
)

test('nvme-cli - argconfig-diff', test_argconfig_diff, suite: 'unit')

test_global_config = executable(
    'test-global-config',
    [
        'test-global-config.c',
        '../../../src/argconfig.c',
        '../../../src/global-config.c',
        '../../../src/global-options.c',
    ],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_dep,
        shared_dep,
    ],
)

test('nvme-cli - global-config', test_global_config, suite: 'unit')

test_plugin = executable(
    'test-plugin',
    ['test-plugin.c', '../../../src/plugin.c', '../../../src/argconfig.c',
     '../../../src/privsep.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_dep,
        shared_dep,
        json_c_dep,
    ],
)

test('nvme-cli - plugin-dispatch', test_plugin, suite: 'unit')

test_bitfields = executable(
    'test-bitfields',
    ['test-bitfields.c', '../../../src/bitfields.c'],
    include_directories: '../../../src',
    dependencies: [config_dep],
)

test('nvme-cli - bitfields', test_bitfields, suite: 'unit')

test_regs = executable(
    'test-regs',
    [
        'test-regs.c',
        '../../../src/nvme-regs.c',
        '../../../src/bitfields.c',
    ],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_dep,
    ],
)

test('nvme-cli - regs', test_regs, suite: 'unit')

if want_top
    test_iostat = executable(
        'test-iostat',
        ['test-iostat.c', '../../../src/nvme-iostat.c'],
        include_directories: '../../../src',
        dependencies: [config_dep, libnvme_dep],
    )

    test('nvme-cli - iostat', test_iostat, suite: 'unit')
endif
