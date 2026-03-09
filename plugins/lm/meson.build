# SPDX-License-Identifier: GPL-2.0-or-later

plugin_sources += [
    'plugins/lm/lm-nvme.c',
    'plugins/lm/lm-print.c',
    'plugins/lm/lm-print-stdout.c',
    'plugins/lm/lm-print-binary.c',
]

if json_c_dep.found()
    plugin_sources += [
        'plugins/lm/lm-print-json.c',
    ]
endif

