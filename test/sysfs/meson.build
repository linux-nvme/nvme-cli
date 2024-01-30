# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2024 SUSE LLC.
#
# Authors: Daniel Wagner <dwagner@suse.de>


sysfs = executable(
    'test-sysfs',
    ['sysfs.c'],
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir]
)

sysfs_files= [
    'nvme-sysfs-tw-carbon-6.8.0-rc1+'
]

setup = find_program('setup.sh')

foreach t_file : sysfs_files
    r = run_command(setup, files('data'/t_file + '.tar.xz'), meson.current_build_dir(), check: true)
    i = r.stdout().strip()
    e0 = 'LIBNVME_SYSFS_PATH=' + i
    e1 = 'LIBNVME_HOSTNQN=nqn.2014-08.org.nvmexpress:uuid:ce4fee3e-c02c-11ee-8442-830d068a36c6'
    e2 = 'LIBNVME_HOSTID=ce4fee3e-c02c-11ee-8442-830d068a36c6'
    test('sysfs', sysfs, args : [ i, t_file + '.out', files('data'/t_file + '.out') ], env : [ e0, e1, e2 ])
endforeach
