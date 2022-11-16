want_docs = get_option('docs')

if want_docs != 'false'
  want_docs_build = get_option('docs-build')
  rstdir = get_option('rstdir')
  if want_docs_build
    kernel_doc = find_program('../kernel-doc')

    conf = configuration_data()
    conf.set('SYSCONFDIR', sysconfdir)

    if want_docs == 'all' or want_docs == 'rst' or want_docs == 'html'
      foreach apif : api_files
        afile = files('../../src/nvme/' + apif)
        subst = configure_file(
            input: afile,
            output: '@BASENAME@.subst',
            configuration: conf)
        rst = custom_target(
          apif.underscorify() + '_rst',
          input: subst,
          output: '@BASENAME@.rst',
          capture: true,
          command: [kernel_doc,
                    '-rst',
                    '@INPUT@'],
          install: true,
          install_dir: rstdir)
      endforeach
    endif
  else
    # no prebuild docs
  endif
endif
