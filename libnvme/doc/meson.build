# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2022 Dell Inc.
# Copyright (c) 2022 SUSE LLC
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
# Authors: Daniel Wagner <dwagner@suse.de>
#

api_files = [
    'accessors-fabrics.h',
    'accessors.h',
    'fabrics.h',
    'filters.h',
    'ioctl.h',
    'lib-types.h',
    'lib.h',
    'linux.h',
    'mi-types.h',
    'mi.h',
    'nbft-types.h',
    'nbft.h',
    'nvme-cmds.h',
    'nvme-types.h',
    'tree.h',
    'util.h',
]

api_paths = []
foreach f: api_files
    api_paths += files('../src/nvme/' + f)
endforeach

sphinx_sources = [
    'conf.py',
    'api.rst',
    'index.rst',
    'quickstart.rst',
    'installation.rst',
    'mi.rst',
    'config-schema.json'
]

static_sources = []
foreach file : sphinx_sources
    static_sources += configure_file(
        input: file + '.in',
        output: file,
        configuration: substs,
    )
endforeach

subdir('rst')

top_source_dir = meson.current_source_dir() + '/../'

kernel_doc = find_program(top_source_dir + 'scripts/kernel-doc')
kernel_doc_check = files(top_source_dir + 'scripts/kernel-doc-check')
# Find the path to bash and use it so we don't pick up the WSL bash in Windows.
bash_prog = find_program('bash', required: true)

test('libnvme - kdoc', bash_prog, args: [kernel_doc_check] + api_paths)

if want_docs != 'false'
    if want_docs == 'all' or want_docs == 'man'
        mandir = join_paths(get_option('mandir'), 'man2')
        list_man_pages = find_program(top_source_dir + 'scripts/list-man-pages.sh')
        if want_docs_build
            foreach apif : api_paths
                c = run_command(list_man_pages, apif, check: true)
                man_pages = c.stdout().split()
                foreach page : man_pages
                    doc_tgts += custom_target(
                        page.underscorify() + '_man',
                        input: apif,
                        output: page + '.2',
                        capture: true,
                        command: [
                            kernel_doc,
                            '-module', 'libnvme',
                            '-man',
                            '-function',
                            page,
                            apif,
                        ],
                        install: true,
                        install_dir: mandir,
                    )
                endforeach
            endforeach
        else
            if want_docs == 'all' or want_docs == 'man'
                list_pre_compiled = find_program(top_source_dir + 'scripts/list-pre-compiled.sh')
                m = run_command(list_pre_compiled, check: true)
                man_pages = m.stdout().strip().split('\n')
                install_data(man_pages, install_dir: mandir)
            endif
        endif
    endif

    if want_docs == 'all' or want_docs == 'html'
        htmldir = join_paths(get_option('htmldir'), 'nvme')
        sphinx_build = find_program('sphinx-build-3', 'sphinx-build')
        if sphinx_build.found() and want_docs_build
            doc_tgts += custom_target(
                'generate_doc_html',
                input: [static_sources, rst],
                output: 'html',
                command: [
                    sphinx_build,
                    '-b', 'html',
                    '@OUTDIR@',
                    '@OUTDIR@' + '/html',
                ],
                install: true,
                install_dir: htmldir
            )
        else
            # The HTML doc is not ready yet.
            # if want_docs == 'all' or want_docs == 'html'
            #  install_subdir('html', install_dir: htmldir)
            # endif
        endif
    endif
endif
