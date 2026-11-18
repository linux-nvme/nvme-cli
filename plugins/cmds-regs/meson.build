# SPDX-License-Identifier: GPL-2.0-or-later
#
# The commands of the controller registers. plugins/meson.build always
# builds this plugin.

plugin_extension = false

plugin_sources += [
    'plugins/cmds-regs/cmds-regs-plugin.c',
    'plugins/cmds-regs/regs-print.c',
    'plugins/cmds-regs/regs-print-stdout.c',
    'plugins/cmds-regs/regs-print-binary.c',
]

if json_c_dep.found()
  plugin_sources += [
      'plugins/cmds-regs/regs-print-json.c',
  ]
endif

plugin_commands = [
    'show-regs',
    'set-reg',
    'get-reg',
    'set-property',
    'get-property',
]
