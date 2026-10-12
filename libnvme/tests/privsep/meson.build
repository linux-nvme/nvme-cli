# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>

privsep_proto_test = executable(
    'test-privsep-proto',
    ['proto.c', '../ioctl/util.c'],
    dependencies: [
        config_dep,
        libnvme_dep,
    ],
    include_directories: include_directories('../../src'),
)

test(
    'libnvme - privsep-proto',
    privsep_proto_test,
    args: [privsep_helper.full_path()],
    depends: [privsep_helper],
)
