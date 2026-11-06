# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
#
# nvme-dashboard is the dashboard of the tests (.github/workflows), see
# Documentation/TESTING.md. It runs from the source tree, nothing here is
# built or installed: only its unit tests run, and its linters on request.

if python3.found()
    test(
        'nvme-dashboard - unit',
        python3,
        # An I/O without an explicit encoding breaks on Windows
        # (cp1252): make it an error everywhere.
        args: ['-X', 'warn_default_encoding', '-W', 'error::EncodingWarning',
               '-m', 'unittest', 'discover', '-s', 'tests'],
        workdir: meson.current_source_dir(),
        suite: 'unit',
        timeout: 120,
    )
endif

# The checks of its pyproject.toml: meson compile -C BUILD lint-dashboard
ruff = find_program('ruff', required: false)
mypy_dashboard = find_program('mypy', required: false)
if ruff.found() and mypy_dashboard.found()
    run_target(
        'lint-dashboard',
        command: [find_program('sh'), '-c',
                  'cd "$1" && "$2" check . && "$2" format --check . && "$3"',
                  'lint-dashboard', meson.current_source_dir(), ruff,
                  mypy_dashboard],
    )
else
    message('ruff or mypy not found: no lint-dashboard target')
endif
