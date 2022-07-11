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
    header_found = cc.has_header('Python.h', dependencies: py3_dep)
    have_python_support = py3_dep.found() and swig.found() and header_found
else
    have_python_support = false
endif

if have_python_support
    pymod_swig = custom_target(
        'nvme.py',
        input:   ['nvme.i'],
        output:  ['nvme.py', 'nvme_wrap.c'],
        command: [swig, '-python', '-py3', '-o', '@OUTPUT1@', '@INPUT0@'],
        install: true,
        install_dir: [python3.get_install_dir(pure: false, subdir: 'libnvme'), false],
    )

    pynvme_clib = python3.extension_module(
        '_nvme',
        pymod_swig[1],
        dependencies : [libnvme_dep, py3_dep],
        include_directories: [incdir, internal_incdir],
        link_with: [libccan],
        install: true,
        subdir: 'libnvme',
    )

    # Little hack to copy file __init__.py to the build directory. 
    # This is needed to create the proper directory layout to run the tests.
    # It's a hack because we don't really "configure" file __init__.py and we
    # could simply install directly from the source tree with:
    #   python3.install_sources(['__init__.py', ], pure:false, subdir:'libnvme')
    # However, since we need __init__.py in the build directory to run the tests
    # we resort to this hack to copy it.
    configure_file(
        input:  '__init__.py', 
        output: '__init__.py',
        configuration: conf,
        install_dir: python3.get_install_dir(pure: false, subdir: 'libnvme'),
    )

    # Set the PYTHONPATH so that we can run the 
    # tests directly from the build directory.
    test_env = environment()
    test_env.append('MALLOC_PERTURB_', '0')
    test_env.append('PYTHONPATH', join_paths(meson.current_build_dir(), '..'))
    test_env.append('PYTHONMALLOC', 'malloc')

    # Test section
    test('[Python] import libnvme', python3, args: ['-c', 'from libnvme import nvme'], env: test_env, depends: pynvme_clib)

    py_tests = [ 
        [ 'create ctrl object', files('tests/create-ctrl-obj.py') ], 
    ]
    foreach test: py_tests
        description = test[0]
        py_script   = test[1]
        test('[Python] ' + description, python3, args: [py_script, ], env: test_env, depends: pynvme_clib)
    endforeach
endif
