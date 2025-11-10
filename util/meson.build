# SPDX-License-Identifier: GPL-2.0-or-later

util_sources = [
    'util/argconfig.c',
    'util/base64.c',
    'util/crc32.c',
    'util/mem.c',
    'util/sighdl.c',
    'util/suffix.c',
    'util/types.c',
    'util/utils.c',
    'util/table.c'
]

if json_c_dep.found()
    util_sources += [
        'util/json.c',
    ]
endif
