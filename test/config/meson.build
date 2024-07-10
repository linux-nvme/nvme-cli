# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2024 SUSE LLC.
#
# Authors: Daniel Wagner <dwagner@suse.de>

diff = find_program('diff', required : false)
if diff.found()
    config_dump = executable(
        'test-config-dump',
        ['config-dump.c'],
        dependencies: libnvme_dep,
        include_directories: [incdir],
    )

    config_data = [
        'config-pcie',
    ]

    config_diff = find_program('config-diff.sh')

    foreach t_file : config_data
        test(
            t_file,
            config_diff,
            args : [
                meson.current_build_dir(),
                config_dump.full_path(),
                files('data'/t_file + '.tar.xz'),
                files('data'/t_file + '.json'),
                files('data'/t_file + '.out'),
            ],
            depends : config_dump,
        )
    endforeach
endif
