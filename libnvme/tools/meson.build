# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
generate_accessors = executable(
    'generate-accessors',
    'generate-accessors.c',
    c_args: [
        '-include', config_h_path,
    ],
    native: true,
)
