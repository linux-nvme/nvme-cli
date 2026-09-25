# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
# Hardware-free micron plugin tests.

micron_mock_tests = [
    'micron_drive_model_mock_test.py',
    'micron_options_mock_test.py',
]

if json_c_dep.found()
    if have_mock_nvme
        foreach t : micron_mock_tests
            test('nvme-cli - @0@'.format(t.split('.')[0]),
                python3,
                args: [files(t), nvme_exe, mock_nvme_lib],
                env: cli_test_env,
                depends: [nvme_exe, mock_nvme_lib],
                suite: ['micron', 'micron-cli'])
        endforeach
    endif

    test('nvme-cli - micron-plugin-version',
         python3,
         args: [files('micron_plugin_version_test.py'), nvme_exe],
         env: cli_test_env,
         depends: nvme_exe,
         suite: ['micron', 'micron-cli'])
endif
