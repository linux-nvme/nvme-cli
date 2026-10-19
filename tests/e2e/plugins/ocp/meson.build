# SPDX-License-Identifier: GPL-2.0-or-later
#
# OCP plugin tests

ocp_tests = [
    'ocp_internal_log_test.py',
    'ocp_smart_add_log_test.py',
]

test_env = environment()
test_env.prepend('PATH', meson.project_build_root())

foreach t : ocp_tests
    t_name = t.split('.')[0]
    name = t_name.replace('ocp_', '').replace('_test', '').replace('_', '-')
    test(
        'ocp - e2e-' + name,
        python3,
        args: [
            e2e_runner,
            '--source-root', meson.project_source_root(),
            '--config', e2e_config_file,
            'tests.e2e.plugins.ocp.@0@'.format(t_name),
        ],
        env: test_env,
        timeout: 500,
        protocol: 'tap',
        is_parallel: false,
        suite: 'e2e',
    )
endforeach
