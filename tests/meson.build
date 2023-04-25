# SPDX-License-Identifier: GPL-2.0-or-later

infra = [
  'config.json',
  'nvme_test.py',
  'nvme_test_io.py',
  'nvme_test_logger.py',
  'nvme_simple_template_test.py',
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

runtests = find_program('nose2', required : false)

if meson.version().version_compare('>= 0.56')
    nvmecli_path = meson.project_build_root()
else
    nvmecli_path = meson.build_root()
endif

if runtests.found()
  foreach file : infra + tests
    configure_file(
      input: file,
      output: file,
      copy: true)
  endforeach

  foreach t : tests
    t_name = t.split('.')[0]
    test(t_name, runtests,
         args: ['--verbose', '--start-dir', meson.current_build_dir(), t_name],
         env: ['PATH=' + nvmecli_path + ':/usr/bin:/usr/sbin'],
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
