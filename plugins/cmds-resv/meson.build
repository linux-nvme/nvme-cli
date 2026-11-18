# SPDX-License-Identifier: GPL-2.0-or-later

plugin_name = 'resv'

plugin_sources += [
    'plugins/cmds-resv/resv-plugin.c',
    'plugins/cmds-resv/resv-print.c',
    'plugins/cmds-resv/resv-print-stdout.c',
    'plugins/cmds-resv/resv-print-binary.c',
]

if json_c_dep.found()
  plugin_sources += [
      'plugins/cmds-resv/resv-print-json.c',
  ]
endif
