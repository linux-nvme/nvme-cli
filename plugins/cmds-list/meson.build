# SPDX-License-Identifier: GPL-2.0-or-later
#
# The device enumeration commands, which show the devices found in sysfs.

plugin_extension = false

plugin_sources += [
    'plugins/cmds-list/cmds-list-plugin.c',
]

plugin_commands = [
    'list',
    'list-subsys',
    'show-topology',
]

if want_top
  plugin_commands += [
      'top',
  ]
endif
