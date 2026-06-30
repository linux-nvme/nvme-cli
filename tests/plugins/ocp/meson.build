# SPDX-License-Identifier: GPL-2.0-or-later
#
# OCP plugin tests

ocp_tests = [
    'ocp_smart_add_log_test.py',
]

python_module = import('python')
python3 = python_module.find_installation('python3')

test_env = environment()
test_env.prepend('PATH', meson.project_build_root())

tap_runner = meson.project_source_root() / 'tests' / 'tap_runner.py'

foreach t : ocp_tests
    t_name = t.split('.')[0]
    test(
        'ocp - @0@'.format(t_name),
        python3,
        args: [
            tap_runner,
            '--start-dir', meson.project_source_root(),
            'tests.plugins.ocp.@0@'.format(t_name),
        ],
        env: test_env,
        timeout: 500,
        protocol: 'tap',
        is_parallel: false,
        suite: 'ocp',
    )
endforeach
