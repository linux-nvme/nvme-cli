# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
#
# nvme-nightly is the tooling of the nightly tests (.github/workflows), see
# Documentation/TESTING.md. It runs from the source tree, nothing here is
# built or installed: only its unit tests run, and its linters on request.

if python3.found()
    test(
        'nvme-nightly - unit',
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

# The checks of its pyproject.toml: meson compile -C BUILD lint-nightly-tool
ruff = find_program('ruff', required: false)
mypy_nightly = find_program('mypy', required: false)
if ruff.found() and mypy_nightly.found()
    run_target(
        'lint-nightly-tool',
        command: [find_program('sh'), '-c',
                  'cd "$1" && "$2" check . && "$2" format --check . && "$3"',
                  'lint-nightly-tool', meson.current_source_dir(), ruff,
                  mypy_nightly],
    )
else
    message('ruff or mypy not found: no lint-nightly-tool target')
endif
