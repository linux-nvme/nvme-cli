# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
configurator = executable(
    'configurator',
    ['tools/configurator/configurator.c'],
    c_args: ['-D_GNU_SOURCE'],
)

config_h = custom_target(
    'config.h',
    output:  'config.h',
    capture: true,
    command: [configurator, ]
)


