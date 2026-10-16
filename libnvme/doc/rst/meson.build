top_source_dir = meson.current_source_dir() + '/../../'
kernel_doc = find_program(top_source_dir + 'scripts/kernel-doc')
rst_conf = configuration_data(
    {
        'SYSCONFDIR' : sysconfdir,
    }
)
foreach docf : doc_files
    afile = files(top_source_dir + 'src/' + docf)
    subst = configure_file(
        input: afile,
        output: '@BASENAME@.subst',
        configuration: rst_conf,
    )
    rst = custom_target(
        docf.underscorify() + '_rst',
        input: subst,
        output: '@BASENAME@.rst',
        capture: true,
        command: [
            kernel_doc,
            '-rst',
            '@INPUT@',
        ],
    )
    doc_tgts += rst
    rst_tgts += rst
endforeach
