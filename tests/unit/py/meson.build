# SPDX-License-Identifier: GPL-2.0-or-later
#
# Python unit tests that need no NVMe hardware.  The C equivalents live in
# ../c/; the CLI-driven tests in ../../cli/; the device tests in ../../e2e/.
#
# python3 is found once, in ../../meson.build.

if python3.found()
    # dump-command-metadata lives in the "utils" plugin and is compiled out
    # without json-c, so its test only makes sense when both are present.
    # Tests added here that don't depend on json-c/utils belong outside this
    # inner guard.
    if want_json_c and 'utils' in selected_plugins
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

    # The generated completion scripts must not depend on the order commands,
    # plugins, or options arrive in; this shuffles the committed fixture and
    # checks each shell's output is byte-identical. Committed inputs, no binary.
    test(
        'nvme-cli - generate-completions-stable',
        python3,
        args: [
            files('test_generate_completions_stable.py'),
            meson.project_source_root() / 'completions' / 'generate-completions.py',
            meson.project_source_root() / 'completions' / 'test-command-metadata.json',
        ],
        timeout: 60,
    )

    # Commands, plugins, sub-commands, and options must be listed
    # alphabetically; this checks each shell's generated output is sorted.
    # Complements the stability test above. Committed inputs, no binary.
    test(
        'nvme-cli - generate-completions-sorted',
        python3,
        args: [
            files('test_generate_completions_sorted.py'),
            meson.project_source_root() / 'completions' / 'generate-completions.py',
            meson.project_source_root() / 'completions' / 'test-command-metadata.json',
        ],
        timeout: 60,
    )

    # The completion test fixture is a hand-written, synthetic metadata model;
    # validate it against the schema so a schema change the fixture no longer
    # satisfies is caught. Both inputs are committed, so no binary needed.
    test(
        'nvme-cli - completion-fixture-schema',
        python3,
        args: [
            files('test_completion_fixture_schema.py'),
            meson.project_source_root() / 'completions' / 'test-command-metadata.json',
            meson.project_source_root() / 'plugins' / 'utils' / 'command-metadata-schema.json',
        ],
        timeout: 60,
    )
endif
