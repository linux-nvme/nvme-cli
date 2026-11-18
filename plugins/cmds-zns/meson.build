# SPDX-License-Identifier: GPL-2.0-or-later

plugin_name = 'zns'

# zns list prints its table with the row printer of nvme list
plugin_needs = ['cmds-list']

plugin_sources += [
    'plugins/cmds-zns/zns.c',
    'plugins/cmds-zns/zns-print.c',
    'plugins/cmds-zns/zns-print-stdout.c',
    'plugins/cmds-zns/zns-print-binary.c',
]

if json_c_dep.found()
  plugin_sources += [
      'plugins/cmds-zns/zns-print-json.c',
  ]
endif
