# SPDX-License-Identifier: GPL-2.0-or-later

if json_c_dep.found() and have_mock_nvme
    test('solidigm - id-ctrl',
         python3,
         args: [files('solidigm_id_ctrl_mock_test.py'), nvme_exe,
                mock_nvme_lib],
         env: cli_test_env,
         depends: [nvme_exe, mock_nvme_lib],
         suite: 'mock')

    test('solidigm - smart-log-add',
         python3,
         args: [files('solidigm_smart_log_mock_test.py'), nvme_exe,
                mock_nvme_lib],
         env: cli_test_env,
         depends: [nvme_exe, mock_nvme_lib],
         suite: 'mock')

    test('solidigm - temp-stats',
         python3,
         args: [files('solidigm_temp_stats_mock_test.py'), nvme_exe,
                mock_nvme_lib],
         env: cli_test_env,
         depends: [nvme_exe, mock_nvme_lib],
         suite: 'mock')
endif
