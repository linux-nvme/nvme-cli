# SPDX-License-Identifier: GPL-2.0-or-later
#
# Hardware-free wdc plugin tests.

if have_mock_nvme
    wdc_test_env = cli_test_env
    wdc_test_env.set('NVME_TEST_JSON', json_c_dep.found() ? '1' : '0')
    test('wdc - commands',
         python3,
         args: [files('wdc_mock_test.py'), nvme_exe, mock_nvme_lib],
         env: wdc_test_env,
         depends: [nvme_exe, mock_nvme_lib],
         timeout: 120,
         suite: 'mock')
endif
