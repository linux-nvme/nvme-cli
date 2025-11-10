# SPDX-License-Identifier: GPL-2.0-or-later

sources = [
    'ccan/hash/hash.c',
    'ccan/htable/htable.c',
    'ccan/ilog/ilog.c',
    'ccan/likely/likely.c',
    'ccan/list/list.c',
    'ccan/str/debug.c',
    'ccan/str/str.c',
    'ccan/strset/strset.c',
]

if get_option('buildtype') == 'debug'
    add_project_arguments('-DCCAN_LIST_DEBUG=1',  language : ['c'])
    add_project_arguments('-DCCAN_STR_DEBUG=1',  language : ['c'])
endif

libccan = static_library(
    'ccan',
    sources,
    install: false,
    include_directories: [incdir, ],
    dependencies: [config_dep, ],
)
