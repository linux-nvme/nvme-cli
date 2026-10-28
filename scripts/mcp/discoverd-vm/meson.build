# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
#
# discoverd-vm-mcp is an MCP server which tests, in a VM, what a system
# shutdown does to the nvme-discoverd connection units and the file
# systems mounted on them, see README.md. It runs from the
# source tree, nothing here is built or installed: only its unit tests
# run, and its linter on request. The tests need no VM.

# The scenario tests skip themselves with Python older than 3.11, which
# has no tomllib
if python3.found()
    test(
        'discoverd-vm-mcp - unit',
        python3,
        args: ['-m', 'unittest', 'discover', '-s', 'tests'],
        workdir: meson.current_source_dir(),
        suite: 'unit',
        timeout: 60,
    )
endif

# The checks of its pyproject.toml: meson compile -C BUILD lint-discoverd-vm-mcp
if ruff.found()
    run_target(
        'lint-discoverd-vm-mcp',
        command: [find_program('sh'), '-c',
                  'cd "$1" && "$2" check . && "$2" format --check .',
                  'lint-discoverd-vm-mcp', meson.current_source_dir(), ruff],
    )
endif
