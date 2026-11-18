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
    ['test-bitfields.c', '../../../plugins/cmds-regs/bitfields.c'],
    include_directories: '../../../plugins/cmds-regs',
    dependencies: [config_dep],
)

test('nvme-cli - bitfields', test_bitfields, suite: 'unit')

test_regs = executable(
    'test-regs',
    [
        'test-regs.c',
        '../../../plugins/cmds-regs/nvme-regs.c',
        '../../../plugins/cmds-regs/bitfields.c',
    ],
    include_directories: '../../../plugins/cmds-regs',
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
        ['test-iostat.c', '../../../plugins/cmds-list/nvme-iostat.c'],
        include_directories: '../../../src',
        dependencies: [config_dep, libnvme_dep],
    )

    test('nvme-cli - iostat', test_iostat, suite: 'unit')
endif

if want_plugin_modules
    # A module outside of the module directory, for path names
    test_plugin_modules = [shared_module(
        'outside',
        'plugin-test-module.c',
        name_prefix: '',
        name_suffix: 'so',
        c_args: ['-DTEST_ABI=NVME_PLUGIN_ABI', '-DTEST_NAME="outside"',
                 '-DTEST_ID=outside'],
        dependencies: [config_dep, shared_dep.partial_dependency(includes: true)],
        override_options: ['b_lundef=false'],
    )]
    subdir('plugin-modules')

    test_plugin_loader = executable(
        'test-plugin-loader',
        ['test-plugin-loader.c', '../../../src/plugin-loader.c'],
        include_directories: [include_directories('../../../src'),
                              plugin_names_inc],
        dependencies: [config_dep, ccan_dep, dl_dep],
        export_dynamic: true,
    )
    test('nvme-cli - plugin-loader', test_plugin_loader, suite: 'unit',
         depends: test_plugin_modules,
         env: {'NVME_PLUGIN_DIR': test_plugin_module_dir})
endif
