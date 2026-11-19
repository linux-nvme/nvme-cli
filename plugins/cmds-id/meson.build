# SPDX-License-Identifier: GPL-2.0-or-later

plugin_name = 'id'

plugin_sources += [
    'plugins/cmds-id/id-plugin.c',
    'plugins/cmds-id/nvme-models.c',
    'plugins/cmds-id/id-print.c',
    'plugins/cmds-id/id-print-stdout.c',
    'plugins/cmds-id/id-print-binary.c',
]

if json_c_dep.found()
  plugin_sources += [
      'plugins/cmds-id/id-print-json.c',
  ]
endif
