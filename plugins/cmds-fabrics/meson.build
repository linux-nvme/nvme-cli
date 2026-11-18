# SPDX-License-Identifier: GPL-2.0-or-later
#
# The fabrics top-level commands. plugins/meson.build builds this plugin
# with -Dfabrics. The config plugin uses its functions.

plugin_extension = false

if want_fabrics
  plugin_sources += [
      'plugins/cmds-fabrics/cmds-fabrics-plugin.c',
      'plugins/cmds-fabrics/config-convert.c',
      'plugins/cmds-fabrics/fabrics.c',
      'plugins/cmds-fabrics/pre-os.c',
  ]

  plugin_commands = [
      'discover',
      'connect-all',
      'connect',
      'disconnect',
      'disconnect-all',
      'dim',
      'gen-hostnqn',
      'show-hostnqn',
  ]
endif
