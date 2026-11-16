# SPDX-License-Identifier: GPL-2.0-or-later
#
# The module directory of test-plugin-loader

# name: [the id of its symbols, defines]
foreach name, def : {
    'good': ['good', ['-DTEST_ABI=NVME_PLUGIN_ABI']],
    'with-dash': ['with_dash', ['-DTEST_ABI=NVME_PLUGIN_ABI']],
    'misnamed': ['good', ['-DTEST_ABI=NVME_PLUGIN_ABI']],
    'stale': ['stale', ['-DTEST_ABI="0.0-stale"']],
    'noinit': ['noinit', ['-DTEST_ABI=NVME_PLUGIN_ABI', '-DTEST_NO_INIT']],
    'broken': ['broken', ['-DTEST_ABI=NVME_PLUGIN_ABI', '-DTEST_UNRESOLVED']],
}
    test_plugin_modules += shared_module(
        name,
        '../plugin-test-module.c',
        name_prefix: '',
        name_suffix: 'so',
        c_args: def[1] + ['-DTEST_NAME="@0@"'.format(name),
                          '-DTEST_ID=' + def[0]],
        dependencies: [config_dep, shared_dep.partial_dependency(includes: true)],
        override_options: ['b_lundef=false'],
    )
endforeach
test_plugin_module_dir = meson.current_build_dir()
