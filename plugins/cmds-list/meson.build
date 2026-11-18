# SPDX-License-Identifier: GPL-2.0-or-later
#
# The device enumeration commands, which show the devices found in sysfs.

plugin_extension = false

plugin_sources += [
    'plugins/cmds-list/cmds-list-plugin.c',
    'plugins/cmds-list/cmds-list-print.c',
    'plugins/cmds-list/cmds-list-print-stdout.c',
]

if json_c_dep.found()
  plugin_sources += [
      'plugins/cmds-list/cmds-list-print-json.c',
  ]
endif

plugin_commands = [
    'list',
    'list-subsys',
    'show-topology',
]

if want_top
  plugin_sources += [
      'plugins/cmds-list/cmds-list-print-stdout-top.c',
  ]
  plugin_commands += [
      'top',
  ]
endif
