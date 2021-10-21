# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#

want_python = get_option('python')
if want_python != 'false'
    python3 = import('python').find_installation('python3')
    py3_dep = python3.dependency(required: want_python == 'true')
    swig = find_program('swig', required: want_python == 'true')
    have_python_support = py3_dep.found() and swig.found()
else
    have_python_support = false
endif

if have_python_support
    pymod_swig = custom_target(
        'nvme.py',
        input:   ['nvme.i', config_host_h, ccan_config_h],
        output:  ['nvme.py', 'nvme_wrap.c'],
        command: [swig, '-python', '-py3', '-o', '@OUTPUT1@', '@INPUT0@'],
        install: true,
        install_dir: [python3.get_install_dir(pure: false, subdir: 'libnvme'), false],
    )

    pynvme_clib = python3.extension_module(
        '_nvme',
        pymod_swig[1],
        dependencies : py3_dep,
        include_directories: incdir,
        link_with: libnvme,
        install: true,
        subdir: 'libnvme',
    )

    python3.install_sources(
        ['__init__.py', ],
        pure: false,
        subdir: 'libnvme',
    )
endif
