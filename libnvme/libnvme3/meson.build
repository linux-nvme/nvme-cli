# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
if want_python
    if not cc.has_header_symbol('Python.h', 'Py_NewRef', dependencies: py3_dep)
        warning('Python < 3.10 detected: Py_NewRef compatibility shim will be used')
    endif

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
        depend_files: [
            'accessors.i',
            'accessors-fabrics.i',
            'attr-accessors.i',
            'nvme-manual-bridges.i',
            'fctx_field_tables.h',
        ],
        install: true,
        install_dir: [python3.get_install_dir(pure: false, subdir: libnvme_api_name), false],
        install_tag: ['python-runtime', 'python-runtime'],
    )
    nvme_py = pymod_swig[0]
    nvme_wrap_c = pymod_swig[1]

    pynvme_clib = python3.extension_module(
        '_nvme',
        nvme_wrap_c,
        dependencies: [config_dep, ccan_dep, libnvme_dep, py3_dep],
        include_directories: include_directories('.'),
        install: true,
        install_tag: 'python-runtime',
        subdir: libnvme_api_name,
    )

    # Declare python3_libnvme_dep so that parent meson projects can use
    # this as a fallback dependency. In other words, if a meson project
    # uses nvme-cli as a subproject, it will be possible to refer to the
    # python nvme.py module using this dependency. This basically sets the
    # variable "nvme_py_path" to the full path of the nvme.py file that
    # was built by SWIG above.
    if meson.version().version_compare('>=1.4.0')
        nvme_py_path = nvme_py.full_path()
    else
        nvme_py_path = meson.current_build_dir() / 'nvme.py'
    endif
    python3_libnvme_dep = declare_dependency(
        sources: nvme_py,
        variables: {
            'nvme_py_path': nvme_py_path,
        },
    )

    # The tests import libnvme3 from the build directory, so the package
    # files must be there next to _nvme.so.
    py_sources = [
        configure_file(
            input:  '__init__.py',
            output: '__init__.py',
            configuration: conf,
        ),
        configure_file(
            input:  '_exceptions.py',
            output: '_exceptions.py',
            copy:   true,
        ),
    ]
    python3.install_sources(py_sources, pure: false, subdir: libnvme_api_name)

    # Set the PYTHONPATH so that we can run the 
    # tests directly from the build directory.
    test_env = environment()
    test_env.set('MALLOC_PERTURB_', '90')
    test_env.prepend('PYTHONPATH', join_paths(meson.current_build_dir(), '..'))
    test_env.set('PYTHONMALLOC', 'malloc')

    # Test section
    test('libnvme - python-import-libnvme', python3, args: ['-c', 'from libnvme3 import nvme'], env: test_env, depends: pynvme_clib)

    py_tests = [
        [ 'create-ctrl-object', [ files('tests/create-ctrl-obj.py'), ] ],
        [ 'sigsegv-during-gc', [ files('tests/gc.py'), ] ],
        [ 'read-nbft-file', [ files('tests/test-nbft.py'), '--filename', join_paths(meson.current_source_dir(), 'tests', 'NBFT') ] ],
        [ 'object-properties-and-errors', [ files('tests/test-objects.py'), ] ],
        [ 'registry', [ files('tests/test-registry.py'), ] ],
        [ 'config', [ files('tests/test-config.py'), ] ],
        [ 'setattr-guards', [ files('tests/test-setattr.py'), ] ],
        [ 'ctrl-crypto', [ files('tests/test-ctrl-crypto.py'), ] ],
    ]
    foreach test: py_tests
        description = test[0]
        args = test[1]
        test('libnvme - python-' + description, python3, args: args, env: test_env, depends: pynvme_clib)
    endforeach
endif
