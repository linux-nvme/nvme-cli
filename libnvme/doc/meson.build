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
    'config.h',
    'crypto.h',
    'exclusion.h',
    'fabrics.h',
    'generated/accessors-fabrics.h',
    'generated/accessors.h',
    'generated/attr-accessors.h',
    'ioctl.h',
    'lib-types.h',
    'lib.h',
    'mem.h',
    'mi-types.h',
    'mi.h',
    'nbft.h',
    'nvme-cmds-base.h',
    'nvme-cmds-fabrics.h',
    'nvme-cmds-mi.h',
    'nvme-cmds-nvm.h',
    'nvme-cmds-zns.h',
    'nvme-cmds.h',
    'nvme-types-base.h',
    'nvme-types-fabrics.h',
    'nvme-types-mi.h',
    'nvme-types-nbft.h',
    'nvme-types-nvm.h',
    'nvme-types-slm.h',
    'nvme-types-zns.h',
    'registry.h',
    'scan.h',
    'tid.h',
    'tree.h',
    'util.h',
]

api_paths = []
foreach f: api_files
    api_paths += files('../src/nvme/' + f)
endforeach

sed_api_files = [
    'sed.h',
    'tcg-types.h',
]

sed_api_paths = []
foreach f: sed_api_files
    sed_api_paths += files('../src/sed/' + f)
endforeach

# The headers to document, relative to src/.
doc_files = []
foreach f: api_files
    doc_files += 'nvme/' + f
endforeach
doc_paths = api_paths
if want_sed
    foreach f: sed_api_files
        doc_files += 'sed/' + f
    endforeach
    doc_paths += sed_api_paths
endif

api_includes = []
foreach f: doc_files
    api_includes += '.. include::   rst/@0@.rst'.format(
        f.split('/')[-1].replace('.h', ''))
endforeach
configure_file(
    input: 'api.rst.in',
    output: 'api.rst',
    configuration: {'API_INCLUDES': '\n'.join(api_includes)},
)

sphinx_sources = [
    'conf.py',
    'index.rst',
    'quickstart.rst',
    'installation.rst',
    'mi.rst',
]

static_sources = []
foreach file : sphinx_sources
    static_sources += configure_file(
        input: file + '.in',
        output: file,
        configuration: substs,
    )
endforeach

rst_tgts = []
subdir('rst')

top_source_dir = meson.current_source_dir() + '/../'

kernel_doc = find_program(top_source_dir + 'scripts/kernel-doc')
kernel_doc_check = files(top_source_dir + 'scripts/kernel-doc-check')

bash_prog = find_program('bash', required: false)
if bash_prog.found()
    test('libnvme - kdoc', bash_prog, args: [kernel_doc_check] + api_paths + sed_api_paths)
endif

if want_docs != 'false'
    if want_docs == 'all' or want_docs == 'man'
        mandir = get_option('mandir') / 'man2'
        list_man_pages = find_program(top_source_dir + 'scripts/list-man-pages.sh')
        if want_docs_build
            foreach apif : doc_paths
                c = run_command(list_man_pages, apif, check: true)
                man_pages = c.stdout().split()
                foreach page : man_pages
                    doc_tgts += custom_target(
                        page.underscorify() + '_man',
                        input: apif,
                        output: page + '-' + libnvme_api_name + '.2',
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
                        install_tag: 'man',
                    )
                endforeach
            endforeach
        else
            if want_docs == 'all' or want_docs == 'man'
                list_pre_compiled = find_program(top_source_dir + 'scripts/list-pre-compiled.sh')
                m = run_command(list_pre_compiled, check: true)
                man_pages = m.stdout().strip().split('\n')
                install_data(man_pages, install_dir: mandir, install_tag: 'man')
            endif
        endif
    endif

    if want_docs == 'all' or want_docs == 'html'
        htmldir = get_option('htmldir') / libnvme_api_name / 'nvme'
        if want_docs_build
            sphinx_build = find_program('sphinx-build-3', 'sphinx-build')
            doc_tgts += custom_target(
                'generate_doc_html',
                input: [static_sources, rst_tgts],
                output: 'html',
                command: [
                    sphinx_build,
                    '-b', 'html',
                    '@OUTDIR@',
                    '@OUTDIR@' + '/html',
                ],
                install: true,
                install_dir: htmldir,
                install_tag: 'doc',
            )
        else
            # The HTML doc is not ready yet.
            # if want_docs == 'all' or want_docs == 'html'
            #  install_subdir('html', install_dir: htmldir)
            # endif
        endif
    endif
endif
