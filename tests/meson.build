# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
#
# All nvme-cli test suites live under this directory:
#   unit/ - fast C and Python unit tests; no built binary or hardware needed
#   cli/  - tests that exercise the built nvme binary; no hardware needed
#   e2e/  - tests that need a real (or emulated) NVMe device; opt-in via
#           -De2e-tests=true since they read and write to /dev/nvme0
#
# unit/ and cli/ are gated by the general 'tests' option (on by default);
# e2e/ is gated by the hardware-only 'e2e-tests' option.

if get_option('tests')
    subdir('unit')
    subdir('cli')
endif

if get_option('e2e-tests')
    subdir('e2e')
endif

mypy = find_program(
    'mypy',
    required : false,
)
flake8 = find_program(
    'flake8',
    required : false,
)
lint_python3 = find_program('python3', required: false)
linter_script = files('run_py_linters.py')

if lint_python3.found() and mypy.found() and flake8.found()
    run_target(
        'lint-python',
        command : [lint_python3, linter_script, 'lint'],
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

if lint_python3.found() and autopep8.found() and isort.found()
    run_target(
        'format-python',
        command : [lint_python3, linter_script, 'format'],
    )
else
    message('autopep8 or isort not found. Python formatting disabled')
endif
