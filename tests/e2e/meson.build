# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
#
# Tests that need a real (or emulated) NVMe device and will read and write
# data to the configured device. Only built when -De2e-tests=true is passed
# at configure time. CLI-only tests that need no hardware live in ../cli/.
#
# These tests are destructive (they create/delete namespaces and overwrite
# data), so the target device must be given explicitly via -De2e-controller=
# and -De2e-ns1= -- there is no default to fall back on. The resulting
# configuration is written once, here at setup time, to e2e_config_file and
# handed to every test via 'nvme-cli-e2e --config'.

if not python3.found()
    error('e2e-tests=true requires python3, which was not found')
endif

e2e_controller = get_option('e2e-controller')
e2e_ns1 = get_option('e2e-ns1')

if e2e_controller == '' or e2e_ns1 == ''
    error(
        'e2e-tests=true requires -De2e-controller=<ctrl device> and ' +
        '-De2e-ns1=<namespace device> to be set explicitly, e.g.\n' +
        '  -De2e-controller=/dev/nvme0 -De2e-ns1=/dev/nvme0n1\n' +
        'These tests read and write real data and create/delete ' +
        'namespaces on the given device, so refusing to guess a default.'
    )
endif

e2e_cdata = configuration_data()
e2e_cdata.set('CONTROLLER', e2e_controller)
e2e_cdata.set('NS1', e2e_ns1)
e2e_cdata.set('LOG_DIR', get_option('e2e-log-dir'))
e2e_cdata.set('LOG_LEVEL', get_option('e2e-log-level'))
e2e_cdata.set('NVME_BIN', get_option('e2e-nvme-bin'))
e2e_cdata.set('VALIDATE_PCI_DEVICE',
              get_option('e2e-validate-pci-device') ? 'true' : 'false')

e2e_config_file = configure_file(
    input : 'e2e-config.json.in',
    output : 'e2e-config.json',
    configuration : e2e_cdata,
)

e2e_runner = meson.project_source_root() / 'tests' / 'nvme-cli-e2e'

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

test_env = environment()
test_env.prepend('PATH', meson.project_build_root())

foreach t : tests
    t_name = t.split('.')[0]
    test(
        'nvme-cli - @0@'.format(t_name),
        python3,
        args: [
            e2e_runner,
            '--source-root', meson.project_source_root(),
            '--config', e2e_config_file,
            'tests.e2e.@0@'.format(t_name),
        ],
        env: test_env,
        timeout: 500,
        protocol: 'tap',
        is_parallel: false,
    )
endforeach

subdir('plugins')
