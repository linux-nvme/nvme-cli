# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2024 SUSE LLC.
#
# Authors: Daniel Wagner <dwagner@suse.de>

diff = find_program('diff', required : false)
if diff.found()

  srcdir = meson.current_source_dir()
  builddir = meson.current_build_dir()

    config_dump = executable(
        'test-config-dump',
        ['config-dump.c'],
        dependencies: libnvme_dep,
        include_directories: [incdir],
    )

    config_data = [
        'config-pcie',
        'config-pcie-with-tcp-config',
    ]

    config_diff = find_program('config-diff.sh')

    foreach t_file : config_data
        test(
            t_file,
            config_diff,
            args : [
                config_dump.full_path(),
                builddir,
                srcdir + '/data/' + t_file + '.out',
                '--sysfs-tar', srcdir + '/data/' + t_file + '.tar.xz',
                '--config-json', srcdir +   '/data/' + t_file + '.json',
            ],
            depends : config_dump,
        )
    endforeach

    test_hostnqn_order = executable(
        'test-hostnqn-order',
        ['hostnqn-order.c'],
        dependencies: libnvme_dep,
        include_directories: [incdir],
    )

    test(
        'hostnqn-order',
        config_diff,
        args : [
            test_hostnqn_order.full_path(),
            builddir,
            srcdir + '/data/hostnqn-order.out',
            '--sysfs-tar', srcdir + '/data/hostnqn-order.tar.xz',
            '--config-json', srcdir + '/data/hostnqn-order.json',
        ],
        depends : test_hostnqn_order,
    )

endif
