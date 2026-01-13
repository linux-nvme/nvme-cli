# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#

# Skip examples on Windows for now due to missing err.h and other incompatibilities
if not is_windows

executable(
    'telemetry-listen',
    ['telemetry-listen.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_dep,
    ],
)

executable(
    'display-columnar',
    ['display-columnar.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_dep,
    ],
)

executable(
    'display-tree',
    ['display-tree.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_dep,
    ],
)

executable(
    'discover-loop',
    ['discover-loop.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_dep,
    ],
)

executable(
    'mi-mctp',
    ['mi-mctp.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_dep,
    ],
)

executable(
    'mi-mctp-csi-test',
    ['mi-mctp-csi-test.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_dep,
        threads_dep,
    ],
)

executable(
    'mi-mctp-ae',
    ['mi-mctp-ae.c'],
    dependencies: [
        config_dep,
        ccan_dep,
        libnvme_dep,
    ],
)

if libdbus_dep.found()
    executable(
        'mi-conf',
        ['mi-conf.c'],
        dependencies: [
            config_dep,
            ccan_dep,
            libnvme_dep,
            libdbus_dep,
        ],
    )
endif

endif # Windows exclusion
