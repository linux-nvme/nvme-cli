# SPDX-License-Identifier: GPL-2.0-or-later

if have_mock_nvme
    test('mangoboost - id-ctrl',
         python3,
         args: [files('mangoboost_id_ctrl_mock_test.py'), nvme_exe,
                mock_nvme_lib],
         env: cli_test_env,
         depends: [nvme_exe, mock_nvme_lib],
         suite: 'mock')
endif
