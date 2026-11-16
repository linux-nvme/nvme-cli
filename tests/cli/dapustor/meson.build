# SPDX-License-Identifier: GPL-2.0-or-later

if have_mock_nvme
    test('dapustor - smart-log-add',
         python3,
         args: [files('dapustor_smart_log_mock_test.py'), nvme_exe,
                mock_nvme_lib],
         env: cli_test_env,
         depends: nvme_runtime + [mock_nvme_lib],
         suite: 'mock')
endif
