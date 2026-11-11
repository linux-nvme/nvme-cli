# SPDX-License-Identifier: GPL-2.0-or-later

if have_mock_nvme
    test('transcend - healthvalue',
         python3,
         args: [files('transcend_healthvalue_mock_test.py'), nvme_exe,
                mock_nvme_lib],
         env: cli_test_env,
         depends: [nvme_exe, mock_nvme_lib],
         suite: 'mock')

    test('transcend - badblock',
         python3,
         args: [files('transcend_badblock_mock_test.py'), nvme_exe,
                mock_nvme_lib],
         env: cli_test_env,
         depends: [nvme_exe, mock_nvme_lib],
         suite: 'mock')
endif
