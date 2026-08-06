# SPDX-License-Identifier: GPL-2.0-or-later

util_sources = [
    'util/argconfig.c',
    'util/types.c',
    'util/utils.c',
]

if host_system == 'linux'
    util_sources += [
        'util/dashboard.c',
    ]
endif

if json_c_dep.found()
    util_sources += [
        'util/json.c',
    ]
endif
