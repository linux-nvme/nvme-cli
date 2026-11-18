# SPDX-License-Identifier: GPL-2.0-or-later
#
# The I/O commands. plugins/meson.build always builds this plugin.

plugin_extension = false

plugin_sources += [
    'plugins/cmds-io/cmds-io-plugin.c',
    'plugins/cmds-io/cmds-io-print.c',
    'plugins/cmds-io/cmds-io-print-stdout.c',
    'plugins/cmds-io/cmds-io-print-binary.c',
]

if json_c_dep.found()
  plugin_sources += [
      'plugins/cmds-io/cmds-io-print-json.c',
  ]
endif

plugin_commands = [
    'dsm',
    'copy',
    'flush',
    'compare',
    'read',
    'write',
    'write-zeroes',
    'write-uncor',
    'verify',
    'get-lba-status',
    'capacity-mgmt',
]
