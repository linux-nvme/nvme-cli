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

test('nvme-keysd - --help', nvme_keysd, args: ['--help'])
test('nvme-keysd - unknown option', nvme_keysd,
     args: ['--bogus'], should_fail: true)
test('nvme-keysd - missing --config', nvme_keysd,
     args: ['--config', '/nonexistent/nvme-keysd.conf'],
     should_fail: true)
test('nvme-keysd - missing --creds-dir', nvme_keysd,
     args: ['--creds-dir', '/nonexistent/creds'], should_fail: true)
test('nvme-keysd - missing --fabrics-config', nvme_keysd,
     args: ['--fabrics-config', '/nonexistent/config.ini'],
     should_fail: true)
