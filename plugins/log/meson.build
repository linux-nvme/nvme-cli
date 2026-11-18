# SPDX-License-Identifier: GPL-2.0-or-later

plugin_sources += [
    'plugins/log/log-plugin.c',
    'plugins/log/log-print.c',
    'plugins/log/log-print-stdout.c',
    'plugins/log/log-print-binary.c',
]

if json_c_dep.found()
  plugin_sources += [
      'plugins/log/log-print-json.c',
  ]
endif
