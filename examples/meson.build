# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
executable(
    'telemetry-listen',
    ['telemetry-listen.c'],
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir]
)

executable(
    'display-columnar',
    ['display-columnar.c'],
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir]
)

executable(
    'display-tree',
    ['display-tree.c'],
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir]
)

executable(
    'discover-loop',
    ['discover-loop.c'],
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir]
)
