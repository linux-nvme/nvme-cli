# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2024 SUSE LLC.
#
# Authors: Daniel Wagner <dwagner@suse.de>

diff = find_program('diff', required : false)
if diff.found()
    tree_dump = executable(
        'test-tree-dump',
        ['tree-dump.c'],
        dependencies: libnvme_dep,
        include_directories: [incdir],
    )

    tree_data = [
        'tree-pcie',
        'tree-apple-nvme',
    ]

    tree_diff = find_program('tree-diff.sh')

    foreach t_file : tree_data
        test(
            t_file,
            tree_diff,
            args : [
                meson.current_build_dir(),
                tree_dump.full_path(),
                files('data'/t_file + '.tar.xz'),
                files('data'/t_file + '.out'),
            ],
            depends : tree_dump,
        )
    endforeach
endif
