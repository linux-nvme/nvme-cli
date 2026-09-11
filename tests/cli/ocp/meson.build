# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
# Hardware-free ocp plugin tests.

ocp_mock_tests = [
    'ocp_smart_add_log_mock_test.py',
]

# Most of these suites go through -o json, and the ocp JSON printer
# (ocp-print-json.c) is only built with json-c.
if json_c_dep.found() and have_mock_nvme
    foreach t : ocp_mock_tests
        test('nvme-cli - @0@'.format(t.split('.')[0]),
             python3,
             args: [files(t), nvme_exe, mock_nvme_lib],
             env: cli_test_env,
             depends: [nvme_exe, mock_nvme_lib],
             suite: ['ocp', 'ocp-cli'])
    endforeach
endif
