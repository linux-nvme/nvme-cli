# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
#
# nvme-mcp is an MCP server which lets an agent watch the I/O of the NVMe
# subsystems with nvme top, see README.md. It runs from the source tree,
# nothing here is built or installed: only its unit tests run, and its
# linters on request.

# It drives nvme top, which only Linux has
if python3.found() and want_top
    test(
        'nvme-mcp - unit',
        python3,
        args: ['-m', 'unittest', 'discover', '-s', 'tests'],
        workdir: meson.current_source_dir(),
        suite: 'unit',
        timeout: 120,
    )
endif

# The checks of its pyproject.toml: meson compile -C BUILD lint-mcp-tool
ruff = find_program('ruff', required: false)
mypy_mcp = find_program('mypy', required: false)
if ruff.found() and mypy_mcp.found()
    run_target(
        'lint-mcp-tool',
        command: [find_program('sh'), '-c',
                  'cd "$1" && "$2" check . && "$2" format --check . && "$3"',
                  'lint-mcp-tool', meson.current_source_dir(), ruff,
                  mypy_mcp],
    )
else
    message('ruff or mypy not found: no lint-mcp-tool target')
endif
