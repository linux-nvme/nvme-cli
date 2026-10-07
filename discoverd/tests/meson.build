# SPDX-License-Identifier: GPL-2.0-or-later

test_dlp = executable(
    'test-dlp',
    ['test-dlp.c', '../src/dlp.c', '../src/tid.c'],
    include_directories: discoverd_inc,
    dependencies: [
        ccan_dep,
        daemon_util_dep,
        libnvme_dep,
        libsystemd_dep,
        shared_dep,
    ],
)

test('nvme-discoverd - dlp', test_dlp)

test_tid = executable(
    'test-tid',
    ['test-tid.c', '../src/tid.c'],
    include_directories: discoverd_inc,
    dependencies: [
        ccan_dep,
        libnvme_dep,
        libsystemd_dep,
        shared_dep,
    ],
)

test('nvme-discoverd - tid', test_tid)

test_config = executable(
    'test-config',
    ['test-config.c', '../src/config.c'],
    include_directories: discoverd_inc,
    dependencies: [
        ccan_dep,
        daemon_util_dep,
        libnvme_dep,
        libsystemd_dep,
        shared_dep,
    ],
)

test('nvme-discoverd - config', test_config)

test_netif = executable(
    'test-netif',
    ['test-netif.c', '../src/netif.c'],
    include_directories: discoverd_inc,
    dependencies: [
        ccan_dep,
        daemon_util_dep,
        libnvme_dep,
        libsystemd_dep,
        shared_dep,
    ],
)

test('nvme-discoverd - netif', test_netif)

test_inventory = executable(
    'test-inventory',
    ['test-inventory.c', '../src/inventory.c', '../src/tid.c'],
    c_args: [
        '-DNBFT_TABLES="@0@"'.format(
            meson.project_source_root() / 'libnvme/tests/nbft/tables'),
    ],
    include_directories: discoverd_inc,
    dependencies: [
        ccan_dep,
        daemon_util_dep,
        libnvme_dep,
        libsystemd_dep,
        shared_dep,
    ],
)

test('nvme-discoverd - inventory', test_inventory)

test('nvme-discoverd - --help', nvme_discoverd, args: ['--help'])
test('nvme-discoverd - unknown option', nvme_discoverd,
     args: ['--bogus'], should_fail: true)
test('nvme-discoverd - missing --nvme-path', nvme_discoverd,
     args: ['--nvme-path', '/nonexistent/nvme'], should_fail: true)
test('nvme-discoverd - missing --config', nvme_discoverd,
     args: ['--config', '/nonexistent/nvme-discoverd.conf'],
     should_fail: true)
