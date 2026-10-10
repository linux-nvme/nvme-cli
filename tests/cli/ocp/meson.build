# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
# Hardware-free ocp plugin tests.

# Most of these suites go through -o json, and the ocp JSON printer
# (ocp-print-json.c) is only built with json-c. Without it, internal-log
# decodes to normal text by default, which has a suite of its own.
if json_c_dep.found()
    ocp_mock_tests = [
        'ocp_device_capability_log_mock_test.py',
        'ocp_internal_log_event_fifo_mock_test.py',
        'ocp_internal_log_mock_test.py',
        'ocp_smart_add_log_mock_test.py',
    ]
else
    ocp_mock_tests = [
        'ocp_internal_log_no_json_mock_test.py',
    ]
endif

if have_mock_nvme
    foreach t : ocp_mock_tests
        test('nvme-cli - @0@'.format(t.split('.')[0]),
             python3,
             args: [files(t), nvme_exe, mock_nvme_lib],
             env: cli_test_env,
             depends: [nvme_exe, mock_nvme_lib],
             suite: ['ocp', 'ocp-cli'],
             timeout: 120)
    endforeach
endif
