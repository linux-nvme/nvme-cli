# SPDX-License-Identifier: GPL-2.0-or-later

plugin_name = 'lm'

plugin_sources += [
    'plugins/cmds-lm/lm-nvme.c',
    'plugins/cmds-lm/lm-print.c',
    'plugins/cmds-lm/lm-print-stdout.c',
    'plugins/cmds-lm/lm-print-binary.c',
]

if json_c_dep.found()
  plugin_sources += [
      'plugins/cmds-lm/lm-print-json.c',
  ]
endif
