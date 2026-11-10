# SPDX-License-Identifier: GPL-2.0-or-later

if json_c_dep.found() and have_mock_nvme
    test('dell - id-ctrl',
         python3,
         args: [files('dell_id_ctrl_mock_test.py'), nvme_exe,
                mock_nvme_lib],
         env: cli_test_env,
         depends: [nvme_exe, mock_nvme_lib],
         suite: 'mock')
endif
