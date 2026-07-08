# SPDX-License-Identifier: GPL-2.0-or-later
#
# Micron plugin tests

micron_tests = [
    'micron_vs_drive_info_test.py',
    'micron_vs_internal_log_test.py',
]

python_module = import('python')
python3 = python_module.find_installation('python3')

test_env = environment()
test_env.prepend('PATH', meson.project_build_root())

tap_runner = meson.project_source_root() / 'tests' / 'tap_runner.py'

foreach t : micron_tests
    t_name = t.split('.')[0]
    test(
        'micron - @0@'.format(t_name),
        python3,
        args: [
            tap_runner,
            '--start-dir', meson.project_source_root(),
            'tests.plugins.micron.@0@'.format(t_name),
        ],
        env: test_env,
        timeout: 500,
        protocol: 'tap',
        is_parallel: false,
        suite: 'micron',
    )
endforeach
