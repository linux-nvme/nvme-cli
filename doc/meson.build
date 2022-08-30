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
  'filters.h',
  'ioctl.h',
  'linux.h',
  'log.h',
  'mi.h',
  'tree.h',
  'types.h',
  'fabrics.h',
  'util.h'
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
  static_sources += configure_file(input: file + '.in',
                                   output: file,
                                   configuration: substs)
endforeach

subdir('rst')

want_docs = get_option('docs')
want_docs_build = get_option('docs-build')
kernel_doc = find_program('kernel-doc')
kernel_doc_check = find_program('kernel-doc-check')

test('kdoc', kernel_doc_check, args: api_paths)

if want_docs != 'false'

  conf = configuration_data()
  conf.set('SYSCONFDIR', sysconfdir)

  if want_docs == 'all' or want_docs == 'man'
    mandir = join_paths(get_option('mandir'), 'man2')
    list_man_pages = find_program('list-man-pages.sh')
    if want_docs_build
      foreach apif : api_paths
        subst = configure_file(
            input: apif,
            output: '@BASENAME@.subst',
            configuration: conf)
        c = run_command(list_man_pages, subst, check: true)
        man_pages = c.stdout().split()
        foreach page : man_pages
          custom_target(
            page.underscorify() + '_man',
            input: subst,
            output: page + '.2',
            capture: true,
            command: [kernel_doc,
                      '-module', 'libnvme',
                      '-man',
                      '-function',
                      page,
                      subst],
            install: true,
            install_dir: mandir)
        endforeach
      endforeach
    else
      if want_docs == 'all' or want_docs == 'man'
        list_pre_compiled = find_program('list-pre-compiled.sh')
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
      custom_target(
        'generate_doc_html',
        input: [static_sources, rst],
        output: 'html',
        command: [sphinx_build,
                  '-b', 'html',
                   '@OUTDIR@',
                   '@OUTDIR@' + '/html'],
        install: true,
        install_dir: htmldir)
    else
      # The HTML doc is not ready yet.
      # if want_docs == 'all' or want_docs == 'html'
      #  install_subdir('html', install_dir: htmldir)
      # endif
    endif
  endif
endif
