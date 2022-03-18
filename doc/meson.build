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
  'tree.h',
  'types.h',
  'fabrics.h',
  'util.h'
]

sphinx_sources = [
    'conf.py',
    'index.rst',
    'config-schema.json'
]

want_docs = get_option('docs')
want_docs_build = get_option('docs-build')
if want_docs != 'false'
  kernel_doc = find_program('kernel-doc')

  conf = configuration_data()
  conf.set('SYSCONFDIR', sysconfdir)

  if want_docs == 'all' or want_docs == 'man'
    mandir = join_paths(get_option('mandir'), 'man2')
    list_man_pages = find_program('list-man-pages.sh')
    if want_docs_build
      foreach apif : api_files
        foreach file : files('../src/nvme/' + apif)
          subst = configure_file(
              input: file,
              output: '@BASENAME@.msubst',
              configuration: conf)
          c = run_command(list_man_pages, subst)
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
      endforeach
    else
      if want_docs == 'all' or want_docs == 'man'
        install_subdir('man', install_dir: mandir)
      endif
    endif
  endif

  if want_docs == 'all' or want_docs == 'html'
    htmldir = join_paths(get_option('htmldir'), 'nvme')
    sphinx_build = find_program('sphinx-build-3', 'sphinx-build')
    if sphinx_build.found() and want_docs_build
      cat = find_program('cat')
      rsts = []
      foreach apif : api_files
        afile = files('../src/nvme/' + apif)
        subst = configure_file(
            input: afile,
            output: '@BASENAME@.hsubst',
            configuration: conf)
        rst = custom_target(
          apif.underscorify() + '_rst',
          input: subst,
          output: '@BASENAME@._rst',
          capture: true,
          command: [kernel_doc,
                    '-rst',
                    '@INPUT@'])
        rsts += rst
      endforeach
      libnvme = custom_target(
	'libnvme',
        command: [ cat, '@INPUT@' ],
        capture: true,
        input: rsts,
        output: 'libnvme.rst')
      static_sources = []
      foreach file : sphinx_sources
	static_sources += configure_file(input: file, output: file, copy: true)
      endforeach
      custom_target(
        'generate_doc_html',
        input: [static_sources, libnvme],
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
