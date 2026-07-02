# SPDX-License-Identifier: GPL-2.0-or-later

util_sources = [
    'util/argconfig.c',
    'util/base64.c',
    'util/crc32.c',
    'util/suffix.c',
    'util/types.c',
    'util/utils.c',
    'util/table.c',
]

if host_system == 'windows'
    util_sources += [
        'util/sighdl-win.c',
        'util/hash-win.c',
    ]
else
    util_sources += [
        'util/sighdl-linux.c',
        'util/dashboard.c',
        'util/hash-linux.c',
    ]
endif

if json_c_dep.found()
    util_sources += [
        'util/json.c',
    ]
endif
