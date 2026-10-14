# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>

privsep_helper = executable(
    'nvme-privsep-helper',
    ['helper.c'],
    dependencies: [
        ccan_dep,
        config_dep,
        libnvme_dep,
    ],
    include_directories: include_directories('../src'),
    install: true,
    install_dir: libexecdir,
    install_tag: 'runtime',
)
