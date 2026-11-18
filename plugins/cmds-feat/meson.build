# SPDX-License-Identifier: GPL-2.0-or-later

plugin_name = 'feat'

plugin_sources += [
    'plugins/cmds-feat/feat-nvme.c',
    'plugins/cmds-feat/feat-cmds.c',
    'plugins/cmds-feat/feat-print.c',
    'plugins/cmds-feat/feat-print-stdout.c',
    'plugins/cmds-feat/feat-print-binary.c',
]

if json_c_dep.found()
  plugin_sources += [
      'plugins/cmds-feat/feat-print-json.c',
  ]
endif

plugin_commands = [
    'get-feature',
    'set-feature',
]
