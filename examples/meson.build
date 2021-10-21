# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
executable(
    'telemetry-listen',
    ['telemetry-listen.c', ccan_config_h],
    link_with: libnvme,
    include_directories: incdir)

executable(
    'display-columnar',
    ['display-columnar.c'],
    link_with: libnvme,
    include_directories: incdir)

executable(
    'discover-loop',
    ['discover-loop.c', ccan_config_h],
    link_with: libnvme,
    include_directories: incdir)

