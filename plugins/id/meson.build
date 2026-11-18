# SPDX-License-Identifier: GPL-2.0-or-later

plugin_sources += [
    'plugins/id/id-plugin.c',
    'plugins/id/nvme-models.c',
    'plugins/id/id-print.c',
    'plugins/id/id-print-stdout.c',
    'plugins/id/id-print-binary.c',
]

if json_c_dep.found()
  plugin_sources += [
      'plugins/id/id-print-json.c',
  ]
endif
