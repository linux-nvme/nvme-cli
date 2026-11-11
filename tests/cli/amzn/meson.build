# SPDX-License-Identifier: GPL-2.0-or-later

if have_mock_nvme
    test('amzn - id-ctrl',
         python3,
         args: [files('amzn_id_ctrl_mock_test.py'), nvme_exe,
                mock_nvme_lib],
         env: cli_test_env,
         depends: [nvme_exe, mock_nvme_lib],
         suite: 'mock')

    test('amzn - stats',
         python3,
         args: [files('amzn_stats_mock_test.py'), nvme_exe,
                mock_nvme_lib],
         env: cli_test_env,
         depends: [nvme_exe, mock_nvme_lib],
         suite: 'mock')
endif
