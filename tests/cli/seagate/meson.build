# SPDX-License-Identifier: GPL-2.0-or-later
#
# Hardware-free Seagate plugin tests.

if have_mock_nvme and json_c_dep.found()
    test('nvme-cli - seagate-vs-smart-add-log-cli',
         python3,
         args: [files('seagate_vs_smart_add_log_mock_test.py'), nvme_exe,
                mock_nvme_lib],
         env: cli_test_env,
         depends: [nvme_exe, mock_nvme_lib],
         suite: ['seagate', 'seagate-cli'])
endif
