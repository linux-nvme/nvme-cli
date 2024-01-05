# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2023 Red Hat Inc.
#
# Authors: Tomas Bzatek <tbzatek@redhat.com>

# NBFT parser tests over supplied NBFT ACPI table dumps

tables_dir     = 'tables'
tables_bad_dir = 'tables_bad'
diff_dir       = 'diffs'

tables = [
    'NBFT-auto-ipv6',
    'NBFT-dhcp-ipv6',
    'NBFT-rhpoc',
    'NBFT-static-ipv4',
    'NBFT-static-ipv4-discovery',
    'NBFT-static-ipv6',
    'NBFT-Dell.PowerEdge.R760'
]

tables_bad = [
    'NBFT-bad-oldspec',
    'NBFT-random-noise',
]

nbft_dump = executable(
    'nbft-dump',
    ['nbft-dump.c'],
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir]
)


helper_data = configuration_data()
helper_data.set('NBFT_DUMP_PATH', nbft_dump.full_path())
helper_data.set('TABLES_DIR', meson.current_source_dir()/tables_dir)
helper_data.set('DIFF_DIR', meson.current_source_dir()/diff_dir)

dump_helper = configure_file(
    input: 'nbft-dump-diff.sh.in',
    output: '@BASENAME@',
    configuration: helper_data
)

gen_diffs_helper = configure_file(
    input: 'gen-nbft-diffs.sh.in',
    output: '@BASENAME@',
    configuration: helper_data
)


run_target(
    'nbft-diffs',
    depends: nbft_dump,
    command: [gen_diffs_helper]
)


diffcmd = find_program(
    'diff',
    required: false
)
if diffcmd.found()
    foreach table: tables
        test(
            table,
            dump_helper,
            args: [files(tables_dir/table),
                   files(diff_dir/table)]
        )
    endforeach
endif

foreach table: tables_bad
    test(
        table,
        nbft_dump,
        args: [files(tables_bad_dir/table)],
        should_fail: true
    )
endforeach
