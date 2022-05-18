# SPDX-License-Identifier: GPL-2.0-or-later

tests = [
  'nvme_attach_detach_ns_test',
  'nvme_compare_test',
  'nvme_create_max_ns_test',
  'nvme_error_log_test',
  'nvme_flush_test',
  'nvme_format_test',
  'nvme_fw_log_test',
  'nvme_get_features_test',
  'nvme_id_ctrl_test',
  'nvme_id_ns_test',
  'nvme_read_write_test',
  'nvme_simple_template_test',
  'nvme_smart_log_test',
  'nvme_test_io',
  'nvme_test_logger',
  'nvme_test',
  'nvme_writeuncor_test',
  'nvme_writezeros_test',
  'nvme_copy_test',
  'nvme_dsm_test',
  'nvme_verify_test',
  'nvme_lba_status_log_test',
  'nvme_get_lba_status_test',
]

runtests = find_program('nose2', required : false)

if runtests.found()
  foreach t : tests
    test(t, runtests,
         args: ['--verbose', '--start-dir', meson.current_source_dir(), t],
         workdir: meson.current_source_dir(),
         env: ['PATH=' + meson.build_root() + ':/usr/bin:/usr/sbin'],
         timeout: 500)
  endforeach
endif

python_module = import('python')

python = python_module.find_installation('python3')

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
    message('autopep8 or isort not found. Python formating disabled')
endif
