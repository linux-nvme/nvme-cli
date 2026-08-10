# SPDX-License-Identifier: GPL-2.0-or-later
#
# Micron plugin tests

micron_tests = [
    'micron_clear_pcie_correctable_errors_test.py',
    'micron_vs_drive_info_test.py',
    'micron_vs_internal_log_test.py',
    'micron_vs_pcie_stats_test.py',
    'micron_vs_temperature_stats_test.py',
]

test_env = environment()
test_env.prepend('PATH', meson.project_build_root())

foreach t : micron_tests
    t_name = t.split('.')[0]
    test(
        'micron - @0@'.format(t_name),
        python3,
        args: [
            e2e_runner,
            '--source-root', meson.project_source_root(),
            '--config', e2e_config_file,
            'tests.e2e.plugins.micron.@0@'.format(t_name),
        ],
        env: test_env,
        timeout: 500,
        protocol: 'tap',
        is_parallel: false,
        suite: 'micron',
    )
endforeach
