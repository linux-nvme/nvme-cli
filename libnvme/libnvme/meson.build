# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
if want_python
    r = run_command(swig, ['-version'], check: true)  # Returns: "\nSWIG Version 4.1.1\n\nCompiled with ..."
    swig_version = r.stdout().split('\n')[1].split()[2].strip()
    if swig_version.version_compare('<4.1.0')
        swig_cmd = [swig, '-python', '-py3', '-o', '@OUTPUT1@', '@INPUT0@']
    else
        swig_cmd = [swig, '-python', '-o', '@OUTPUT1@', '@INPUT0@']
    endif

    pymod_swig = custom_target(
        'nvme.py',
        input:   ['nvme.i'],
        output:  ['nvme.py', 'nvme_wrap.c'],
        command: swig_cmd,
        install: true,
        install_dir: [python3.get_install_dir(pure: false, subdir: 'libnvme'), false],
    )
    nvme_py = pymod_swig[0]
    nvme_wrap_c = pymod_swig[1]

    if meson.version().version_compare('>=1.4.0')
        nvme_py_path = nvme_py.full_path()
    else
        nvme_py_path = meson.current_build_dir() / 'nvme.py'
    endif

    pynvme_clib = python3.extension_module(
        '_nvme',
        nvme_wrap_c,
        dependencies : [libnvme_dep, py3_dep, config_dep],
        include_directories: [incdir, ],
        link_with: [libccan],
        install: true,
        subdir: 'libnvme',
    )

    # Declare python3_libnvme_dep so that parent meson projects can use
    # this as a fallback dependency. In other words, if a meson project
    # uses nvme-cli as a subproject, it will be possible to refer to the
    # python nvme.py module using this dependency. This basically sets the
    # variable "nvme_py_path" to the full path of the nvme.py file that
    # was built by SWIG above.
    python3_libnvme_dep = declare_dependency(
        sources: nvme_py,
        variables: {
            'nvme_py_path': nvme_py_path,
        },
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
    test_env.set('MALLOC_PERTURB_', '90')
    test_env.prepend('PYTHONPATH', join_paths(meson.current_build_dir(), '..'))
    test_env.set('PYTHONMALLOC', 'malloc')

    # Test section
    test('libnvme - python-import-libnvme', python3, args: ['-c', 'from libnvme import nvme'], env: test_env, depends: pynvme_clib)

    py_tests = [ 
        [ 'create-ctrl-object', [ files('tests/create-ctrl-obj.py'), ] ],
        [ 'sigsegv-during-gc', [ files('tests/gc.py'), ] ],
        [ 'read-nbft-file', [ files('tests/test-nbft.py'), '--filename', join_paths(meson.current_source_dir(), 'tests', 'NBFT') ] ],
    ]
    foreach test: py_tests
        description = test[0]
        args = test[1]
        test('libnvme - python-' + description, python3, args: args, env: test_env, depends: pynvme_clib)
    endforeach
endif
