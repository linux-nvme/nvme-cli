# SPDX-License-Identifier: GPL-2.0-or-later

if have_mock_nvme
    test('netapp - explicit-device',
         python3,
         args: [files('netapp_explicit_device_mock_test.py'), nvme_exe,
                mock_nvme_lib],
         env: cli_test_env,
         depends: [nvme_exe, mock_nvme_lib],
         suite: 'mock')
endif
