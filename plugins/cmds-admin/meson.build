# SPDX-License-Identifier: GPL-2.0-or-later
#
# The controller and media management top-level commands.
# plugins/meson.build always builds this plugin.

plugin_extension = false

plugin_sources += [
    'plugins/cmds-admin/cmds-admin-plugin.c',
    'plugins/cmds-admin/cmds-admin-ctrl.c',
    'plugins/cmds-admin/cmds-admin-security.c',
]

plugin_commands = [
    'reset',
    'subsystem-reset',
    'ns-rescan',
    'virt-mgmt',
    'device-self-test',
    'sanitize',
    'sanitize-ns',
    'format',
    'lockdown',
]
