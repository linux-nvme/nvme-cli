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
