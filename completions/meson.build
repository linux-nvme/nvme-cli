# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
# The shell completions (bash-nvme-completion.sh, _nvme, nvme-completion.ps1)
# are pre-generated from the compiled nvme binary and committed to the source
# tree.  They are NOT regenerated during a normal build.
#
# To regenerate them after adding or changing a command or option:
#
#   meson compile -C <build-dir> update-completions
#
# CI verifies they are in sync (without modifying the tree) via:
#
#   meson compile -C <build-dir> check-completions

install_data(
    'bash-nvme-completion.sh',
    rename: 'nvme',
    install_dir: datadir / 'bash-completion/completions',
)
install_data(
    '_nvme',
    install_dir: datadir / 'zsh/site-functions',
)

# The metadata dump lives in the "utils" plugin and needs json-c, and the
# generator needs python3; define the targets only when all are present.
_py3 = find_program('python3', required: false)
if json_c_dep.found() and _py3.found() and 'utils' in selected_plugins
    _update_completions = files('update-completions.sh')
    _generator = files('generate-completions.py')
    _completions_dir = meson.current_source_dir()

    # Shared by both targets; check-completions just appends --check to run the
    # same generation read-only.
    _completions_cmd = [
        _update_completions,
        nvme_exe,
        _py3,
        _generator,
        _completions_dir,
    ]

    run_target(
        'update-completions',
        command: _completions_cmd,
        depends: nvme_exe,
    )

    run_target(
        'check-completions',
        command: _completions_cmd + ['--check'],
        depends: nvme_exe,
    )
endif

# ---------------------------------------------------------------------------
# Shell test suites: each drives the real completion entry point and exits
# non-zero on failure.  They need the matching interpreter installed.
# ---------------------------------------------------------------------------
_bash = find_program('bash', required: false)
if want_tests and _bash.found()
    test(
        'nvme-cli - bash-completion',
        _bash,
        args: [files('test-bash-completion.sh')],
        timeout: 120,
    )
endif

_zsh = find_program('zsh', required: false)
if want_tests and _zsh.found()
    test(
        'nvme-cli - zsh-completion',
        _zsh,
        args: [files('test-zsh-completion.sh')],
        timeout: 120,
    )
endif

_pwsh = find_program('pwsh', required: false)
if want_tests and _pwsh.found()
    test(
        'nvme-cli - powershell-completion',
        _pwsh,
        args: ['-File', files('test-powershell-completion.ps1')],
        timeout: 120,
    )
endif
