# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2024 SUSE LLC.
#
# Authors: Daniel Wagner <dwagner@suse.de>

diff = find_program('diff', required : false)
if diff.found()
    tree_scan = executable(
        'test-tree-scan',
        ['tree-scan.c'],
        dependencies: libnvme_dep,
    )

    tree_data = [
        'tree-pcie',
        'tree-apple-nvme',
    ]

    tree_diff = find_program('tree-diff.sh')

    foreach t_file : tree_data
        test(
            'libnvme - @0@'.format(t_file),
            tree_diff,
            args : [
                meson.current_build_dir(),
                tree_scan.full_path(),
                files('data'/t_file + '.tar.xz'),
                files('data'/t_file + '.out'),
            ],
            depends : tree_scan,
        )
    endforeach

    if want_fabrics
        tree_scan_hostnqn = executable(
            'test-tree-scan-hostnqn',
            ['tree-scan-hostnqn.c'],
            dependencies: libnvme_dep,
        )

        foreach t_file : tree_data
            test(
                'libnvme - @0@-hostnqn'.format(t_file),
                tree_diff,
                args : [
                    meson.current_build_dir(),
                    tree_scan_hostnqn.full_path(),
                    files('data'/t_file + '.tar.xz'),
                    files('data'/t_file + '-hostnqn.out'),
                ],
                depends : tree_scan_hostnqn,
            )
        endforeach
    endif
endif
