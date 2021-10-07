# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
python3 = import('python').find_installation('python3')
swig = find_program('swig', required: true)
pymod_swig = custom_target(
    'nvme.py',
    input:   ['nvme.i', config_h],
    output:  ['nvme.py', 'nvme_wrap.c'],
    command: [swig, '-python', '-py3', '-o', '@OUTPUT1@', '@INPUT0@'],
    install: true,
    install_dir: [python3.get_install_dir(pure: false, subdir: 'libnvme'), false],
)

pynvme_clib = python3.extension_module(
    '_nvme',
    pymod_swig[1],
    dependencies : python3.dependency(),
    include_directories: incdir,
    link_with: libnvme_static,
    install: true,
    subdir: 'libnvme',
)

python3.install_sources(
    ['__init__.py', ],
    pure: false,
    subdir: 'libnvme',
)
