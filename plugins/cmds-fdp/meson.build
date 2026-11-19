# SPDX-License-Identifier: GPL-2.0-or-later

plugin_name = 'fdp'

plugin_sources += [
    'plugins/cmds-fdp/fdp.c',
    'plugins/cmds-fdp/fdp-print.c',
    'plugins/cmds-fdp/fdp-print-stdout.c',
    'plugins/cmds-fdp/fdp-print-binary.c',
]

if json_c_dep.found()
  plugin_sources += [
      'plugins/cmds-fdp/fdp-print-json.c',
  ]
endif
