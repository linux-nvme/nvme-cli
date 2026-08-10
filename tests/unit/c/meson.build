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

test('nvme-cli - argconfig_parse', test_argconfig_parse)

test_global_config = executable(
    'test-global-config',
    ['test-global-config.c', '../../../src/global-config.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        shared_dep,
    ],
)

test('nvme-cli - global-config', test_global_config)
