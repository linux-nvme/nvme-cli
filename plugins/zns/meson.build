# SPDX-License-Identifier: GPL-2.0-or-later

plugin_sources += [
    'plugins/zns/zns.c',
    'plugins/zns/zns-print.c',
    'plugins/zns/zns-print-stdout.c',
    'plugins/zns/zns-print-binary.c',
]

if json_c_dep.found()
  plugin_sources += [
      'plugins/zns/zns-print-json.c',
  ]
endif
