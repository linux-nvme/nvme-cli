# SPDX-License-Identifier: GPL-2.0-or-later

plugin_name = 'log'

plugin_sources += [
    'plugins/cmds-log/log-plugin.c',
    'plugins/cmds-log/get-log.c',
    'plugins/cmds-log/log-print.c',
    'plugins/cmds-log/log-print-stdout.c',
    'plugins/cmds-log/log-print-binary.c',
]

if json_c_dep.found()
  plugin_sources += [
      'plugins/cmds-log/log-print-json.c',
  ]
endif

# get-log, a top-level command
plugin_commands = ['get-log']
