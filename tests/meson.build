# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>

infra = [
    'config.json',
    'nvme_test.py',
    'nvme_test_io.py',
    'nvme_test_logger.py',
    'nvme_simple_template_test.py',
    'tap_runner.py',
]

tests = [
    'nvme_attach_detach_ns_test.py',
    'nvme_compare_test.py',
    'nvme_create_max_ns_test.py',
    'nvme_error_log_test.py',
    'nvme_flush_test.py',
    'nvme_format_test.py',
    'nvme_fw_log_test.py',
    'nvme_get_features_test.py',
    'nvme_id_ctrl_test.py',
    'nvme_id_ns_test.py',
    'nvme_read_write_test.py',
    'nvme_smart_log_test.py',
    'nvme_writeuncor_test.py',
    'nvme_writezeros_test.py',
    'nvme_copy_test.py',
    'nvme_dsm_test.py',
    'nvme_verify_test.py',
    'nvme_lba_status_log_test.py',
    'nvme_get_lba_status_test.py',
    'nvme_ctrl_reset_test.py',
]

python_module = import('python')

python = python_module.find_installation('python3')

foreach t : tests
    t_name = t.split('.')[0]
    test(
        'nvme-cli - @0@'.format(t_name),
        python,
        args: [
            meson.current_source_dir() / 'tap_runner.py',
            '--start-dir', meson.current_source_dir(),
            t_name,
        ],
        env: ['PATH=' + meson.project_build_root() + ':/usr/bin:/usr/sbin'],
        timeout: 500,
        protocol: 'tap',
        is_parallel: false,
    )
endforeach

mypy = find_program(
    'mypy',
    required : false,
)
flake8 = find_program(
    'flake8',
    required : false,
)
linter_script = files('run_py_linters.py')

if mypy.found() and flake8.found()
    run_target(
        'lint-python',
        command : [python, linter_script, 'lint'],
    )
else
    message('Mypy or Flake8 not found. Python linting disabled')
endif


autopep8 = find_program(
    'autopep8',
    required : false,
)
isort = find_program(
    'isort',
    required : false,
)

if autopep8.found() and isort.found()
    run_target(
        'format-python',
        command : [python, linter_script, 'format'],
    )
else
    message('autopep8 or isort not found. Python formatting disabled')
endif
