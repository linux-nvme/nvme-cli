# SPDX-License-Identifier: GPL-2.0-or-later

test_dlp = executable(
    'test-dlp',
    ['test-dlp.c', '../src/dlp.c', '../src/log.c', '../src/tid.c'],
    include_directories: discoverd_inc,
    dependencies: [
        ccan_dep,
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
    ['test-config.c', '../src/config.c', '../src/log.c'],
    include_directories: discoverd_inc,
    dependencies: [
        ccan_dep,
        libnvme_dep,
        libsystemd_dep,
        shared_dep,
    ],
)

test('nvme-discoverd - config', test_config)

test_netif = executable(
    'test-netif',
    ['test-netif.c', '../src/netif.c', '../src/log.c'],
    include_directories: discoverd_inc,
    dependencies: [
        ccan_dep,
        libnvme_dep,
        libsystemd_dep,
        shared_dep,
    ],
)

test('nvme-discoverd - netif', test_netif)
