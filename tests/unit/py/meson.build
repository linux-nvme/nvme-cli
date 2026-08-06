# SPDX-License-Identifier: GPL-2.0-or-later
#
# Python unit tests that need no NVMe hardware.  The C equivalents live in
# ../c/; the CLI-driven tests in ../../cli/; the device tests in ../../e2e/.
#
# python3 is found once, in ../../meson.build.

if python3.found()
    # dump-command-metadata is compiled out without json-c, so its test only
    # makes sense when json-c is available.  Tests added here that don't
    # depend on json-c belong outside this inner guard.
    if want_json_c
        test(
            'nvme-cli - command-metadata-schema',
            python3,
            args: [
                files('test_command_metadata_schema.py'),
                nvme_exe,
                meson.project_source_root() / 'plugins' / 'utils' / 'command-metadata-schema.json',
            ],
            depends: nvme_exe,
            timeout: 120,
        )
    endif

    # Argument handling of the completion generator; needs no nvme binary or
    # json-c (it feeds a minimal model on stdin), so it lives outside the guard.
    test(
        'nvme-cli - generate-completions-args',
        python3,
        args: [
            files('test_generate_completions_args.py'),
            meson.project_source_root() / 'completions' / 'generate-completions.py',
        ],
        timeout: 60,
    )
endif
