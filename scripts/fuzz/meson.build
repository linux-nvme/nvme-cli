# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
#
# nvme-fuzz builds, runs and evaluates the fuzz targets in tests/fuzz, see
# Documentation/TESTING.md. It runs from the source tree, nothing here is
# built or installed: only its unit tests run, and its linters on request.

if python3.found()
    test(
        'nvme-fuzz - unit',
        python3,
        args: ['-m', 'unittest', 'discover', '-s', 'tests'],
        workdir: meson.current_source_dir(),
        suite: 'unit',
        timeout: 120,
    )
endif

# The checks of its pyproject.toml: meson compile -C BUILD lint-fuzz-tool
ruff = find_program('ruff', required: false)
mypy_fuzz = find_program('mypy', required: false)
if ruff.found() and mypy_fuzz.found()
    run_target(
        'lint-fuzz-tool',
        command: [find_program('sh'), '-c',
                  'cd "$1" && "$2" check . && "$2" format --check . && "$3"',
                  'lint-fuzz-tool', meson.current_source_dir(), ruff,
                  mypy_fuzz],
    )
else
    message('ruff or mypy not found: no lint-fuzz-tool target')
endif
