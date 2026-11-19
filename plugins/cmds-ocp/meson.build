# SPDX-License-Identifier: GPL-2.0-or-later

plugin_name = 'ocp'

plugin_needs = ['log']

plugin_sources += [
  'plugins/cmds-ocp/ocp-utils.c',
  'plugins/cmds-ocp/ocp-nvme.c',
  'plugins/cmds-ocp/ocp-clear-features.c',
  'plugins/cmds-ocp/ocp-smart-extended-log.c',
  'plugins/cmds-ocp/ocp-fw-activation-history.c',
  'plugins/cmds-ocp/ocp-telemetry-decode.c',
  'plugins/cmds-ocp/ocp-hardware-component-log.c',
  'plugins/cmds-ocp/ocp-print.c',
  'plugins/cmds-ocp/ocp-print-stdout.c',
  'plugins/cmds-ocp/ocp-print-binary.c',
]

if json_c_dep.found()
  plugin_sources += [
      'plugins/cmds-ocp/ocp-print-json.c',
  ]
endif
