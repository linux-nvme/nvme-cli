# SPDX-License-Identifier: GPL-2.0-or-later
#
# Python unit tests that need no NVMe hardware.  The C equivalents live in
# unit/; the device/integration tests in tests/.

py3 = find_program('python3', required: false)

if py3.found()
    # dump-command-metadata is compiled out without json-c, so its test only
    # makes sense when json-c is available.  Tests added here that don't
    # depend on json-c belong outside this inner guard.
    if want_json_c
        test(
            'nvme-cli - command-metadata-schema',
            py3,
            args: [
                files('test_command_metadata_schema.py'),
                nvme_exe,
                meson.project_source_root() / 'command-metadata-schema.json',
            ],
            depends: nvme_exe,
            timeout: 120,
        )
    endif
endif
