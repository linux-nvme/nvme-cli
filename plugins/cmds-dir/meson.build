# SPDX-License-Identifier: GPL-2.0-or-later

plugin_name = 'dir'

plugin_sources += [
    'plugins/cmds-dir/dir-plugin.c',
    'plugins/cmds-dir/dir-print.c',
    'plugins/cmds-dir/dir-print-stdout.c',
    'plugins/cmds-dir/dir-print-binary.c',
]

if json_c_dep.found()
  plugin_sources += [
      'plugins/cmds-dir/dir-print-json.c',
  ]
endif
