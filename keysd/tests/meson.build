# SPDX-License-Identifier: GPL-2.0-or-later

test_config = executable(
    'test-keysd-config',
    ['test-config.c', '../src/config.c'],
    include_directories: keysd_inc,
    dependencies: [
        ccan_dep,
        daemon_util_dep,
        shared_dep,
    ],
)

test('nvme-keysd - config', test_config)
