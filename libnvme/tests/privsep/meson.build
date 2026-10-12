# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>

mock_ioctl = library(
    'mock-ioctl',
    ['mock-ioctl.c'],
    dependencies: [
        cc.find_library('dl', required: false),
    ],
    install: false,
)

privsep_test = executable(
    'test-privsep',
    ['privsep.c', '../ioctl/util.c'],
    dependencies: [
        ccan_dep,
        config_dep,
        libnvme_dep,
    ],
)

privsep_env = environment()
privsep_env.set('ASAN_OPTIONS', 'verify_asan_link_order=0')

test(
    'libnvme - privsep',
    privsep_test,
    args: [privsep_helper.full_path(), mock_ioctl.full_path()],
    depends: [privsep_helper, mock_ioctl],
    env: privsep_env,
)

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
