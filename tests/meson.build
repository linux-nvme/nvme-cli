tests = [
  'nvme_attach_detach_ns_test',
  'nvme_compare_test',
  'nvme_create_max_ns_test',
  'nvme_error_log_test',
  'nvme_flush_test',
  'nvme_format_test',
  'nvme_fw_log_test',
  'nvme_get_features_test',
  'nvme_id_ctrl_test',
  'nvme_id_ns_test',
  'nvme_read_write_test',
  'nvme_simple_template_test',
  'nvme_smart_log_test',
  'nvme_test_io',
  'nvme_test_logger',
  'nvme_test',
  'nvme_writeuncor_test',
  'nvme_writezeros_test',
]

runtests = find_program('nose2', required : false)

if runtests.found()
  foreach t : tests
    test(t, runtests,
         args: ['--verbose', '--start-dir', meson.current_source_dir(), t],
         workdir: meson.current_source_dir(),
         env: ['PATH=' + meson.build_root() + ':/usr/bin:/usr/sbin'],
         timeout: 500)
  endforeach
endif
