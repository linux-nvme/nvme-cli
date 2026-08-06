# SPDX-License-Identifier: GPL-2.0-or-later

util_sources = [
    'util/argconfig.c',
    'util/types.c',
    'util/utils.c',
    'util/table.c',
]

if host_system == 'linux'
    util_sources += [
        'util/sighdl-linux.c',
        'util/dashboard.c',
    ]
elif host_system == 'windows'
    util_sources += [
        'util/sighdl-win.c',
    ]
endif

if json_c_dep.found()
    util_sources += [
        'util/json.c',
    ]
endif
