# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of nvme.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>

ana = executable(
    'test-ana',
    ['ana.c', 'util.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_test_dep,
    ],
)
test('libnvme - ana', ana)

async = executable(
    'test-async',
    ['async.c', 'util.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_test_dep,
    ],
)
test('libnvme - async', async)

if want_fabrics
    discovery = executable(
        'test-discovery',
        ['discovery.c', 'util.c'],
        dependencies: [
            config_dep,
            ccan_dep,
            libnvme_test_dep,
        ],
    )
    test('libnvme - discovery', discovery)
endif

features = executable(
    'test-features',
    ['features.c', 'util.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_test_dep,
    ],
)
test('libnvme - features', features)

identify = executable(
    'test-identify',
    ['identify.c', 'util.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_test_dep,
    ],
)
test('libnvme - identify', identify)

logs = executable(
    'test-logs',
    ['logs.c', 'util.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_test_dep,
    ],
)
test('libnvme - logs', logs)

zns = executable(
    'test-zns',
    ['zns.c', 'util.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_test_dep,
    ],
)
test('libnvme - zns', zns)

misc = executable(
    'test-misc',
    ['misc.c', 'util.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_test_dep,
    ],
)
test('libnvme - misc', misc)
