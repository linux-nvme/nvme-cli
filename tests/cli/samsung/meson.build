# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Samsung Electronics Co., Ltd.
#
# Authors: Hyuntae Kim <h1219.kim@samsung.com>
#
# Hardware-free Samsung plugin tests.

if have_mock_nvme
    test('nvme-cli - samsung-cli',
         python3,
         args: [files('nvme_samsung_test.py'), nvme_exe, mock_nvme_lib],
         env: cli_test_env,
         depends: [nvme_exe, mock_nvme_lib],
         suite: ['samsung', 'samsung-cli'])

    if want_mi
        test('nvme-cli - samsung-mctp-cli',
             python3,
             args: [files('nvme_samsung_mctp_test.py'), nvme_exe, mock_mctp_lib],
             env: cli_test_env,
             depends: [nvme_exe, mock_mctp_lib],
             suite: ['samsung', 'samsung-cli'])
    endif
endif
