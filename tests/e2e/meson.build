# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
#
# Tests that need a real (or emulated) NVMe device and will read and write
# data to /dev/nvme0. Only built when -De2e-tests=true is passed at
# configure time. CLI-only tests that need no hardware live in ../cli/.

tests = [
    'nvme_attach_detach_ns_test.py',
    'nvme_compare_test.py',
    'nvme_create_max_ns_test.py',
    'nvme_error_log_test.py',
    'nvme_flush_test.py',
    'nvme_format_test.py',
    'nvme_fw_log_test.py',
    'nvme_get_features_test.py',
    'nvme_id_ctrl_test.py',
    'nvme_id_ns_test.py',
    'nvme_read_write_test.py',
    'nvme_qpif_test.py',
    'nvme_smart_log_test.py',
    'nvme_writeuncor_test.py',
    'nvme_writezeros_test.py',
    'nvme_copy_test.py',
    'nvme_dsm_test.py',
    'nvme_verify_test.py',
    'nvme_lba_status_log_test.py',
    'nvme_get_lba_status_test.py',
    'nvme_ctrl_reset_test.py',
]

python_module = import('python')

python = python_module.find_installation('python3')

test_env = environment()
test_env.prepend('PATH', meson.project_build_root())

foreach t : tests
    t_name = t.split('.')[0]
    test(
        'nvme-cli - @0@'.format(t_name),
        python,
        args: [
            meson.project_source_root() / 'tests' / 'tap_runner.py',
            '--start-dir', meson.project_source_root(),
            'tests.e2e.@0@'.format(t_name),
        ],
        env: test_env,
        timeout: 500,
        protocol: 'tap',
        is_parallel: false,
    )
endforeach

subdir('plugins')
