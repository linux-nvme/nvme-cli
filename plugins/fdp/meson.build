# SPDX-License-Identifier: GPL-2.0-or-later

plugin_sources += [
    'plugins/fdp/fdp.c',
    'plugins/fdp/fdp-print.c',
    'plugins/fdp/fdp-print-stdout.c',
    'plugins/fdp/fdp-print-binary.c',
]

if json_c_dep.found()
  plugin_sources += [
      'plugins/fdp/fdp-print-json.c',
  ]
endif
