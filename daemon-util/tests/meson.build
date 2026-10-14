# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>

test_resolve = executable(
    'test-daemon-util-resolve',
    ['test-resolve.c'],
    dependencies: [
        ccan_dep,
        daemon_util_dep,
    ],
)

test('daemon-util - resolve', test_resolve)
