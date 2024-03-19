# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2024 SUSE LLC.
#
# Authors: Daniel Wagner <dwagner@suse.de>

diff = find_program('diff', required : false)
if diff.found()
    sysfs_tree_print = executable(
        'sysfs-tree-print',
        ['sysfs.c'],
        dependencies: libnvme_dep,
        include_directories: [incdir],
    )

    sysfs_files= [
        'nvme-sysfs-tw-carbon-6.8.0-rc1+'
    ]

    sysfs_tree_diff = find_program('sysfs-tree-diff.sh')

    foreach t_file : sysfs_files
        test(
            'sysfs',
            sysfs_tree_diff,
            args : [
                meson.current_build_dir(),
                sysfs_tree_print.full_path(),
                files('data'/t_file + '.tar.xz'),
                files('data'/t_file + '.out'),
            ],
            depends : sysfs_tree_print,
        )
    endforeach
endif
