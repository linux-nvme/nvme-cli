# SPDX-License-Identifier: GPL-2.0-or-later
#
# Fuzz targets for the parsers of untrusted input: the command line and
# the config files. Without -Dfuzzing=true each target runs as a test,
# with the seeds in corpus/<target> and a few seconds of mutations of
# them (FUZZ_SECONDS, FUZZ_SEED). With -Dfuzzing=true and clang, the
# targets are built for libFuzzer:
#
#   CC=clang meson setup fuzz -Dfuzzing=true -Db_sanitize=address,undefined
#   ninja -C fuzz
#   fuzz/tests/fuzz/fuzz-argconfig -dict=tests/fuzz/argconfig.dict \
#       tests/fuzz/corpus/argconfig
#
# The targets use the libFuzzer interface, which AFL++ (afl-clang-fast
# -fsanitize=fuzzer) runs as well.

fuzz_targets = {
    'argconfig': {
        'sources': ['fuzz-argconfig.c', '../../src/argconfig.c'],
        'deps': [config_dep, ccan_dep, libnvme_dep, shared_dep],
    },
    'ini': {
        'sources': ['fuzz-ini.c'],
        'deps': [config_dep, shared_dep],
    },
    'global-config': {
        'sources': [
            'fuzz-global-config.c',
            '../../src/argconfig.c',
            '../../src/global-config.c',
            '../../src/global-options.c',
        ],
        'deps': [config_dep, ccan_dep, libnvme_dep, shared_dep],
    },
}

if want_fabrics
    fuzz_targets += {
        'fabrics-conf': {
            'sources': ['fuzz-fabrics-conf.c'],
            'deps': [config_dep, ccan_dep, shared_dep, libnvme_test_dep],
        },
    }
endif

foreach name, t : fuzz_targets
    if get_option('fuzzing')
        executable(
            'fuzz-' + name,
            t['sources'],
            include_directories: include_directories('../../src'),
            dependencies: t['deps'],
            link_args: ['-fsanitize=fuzzer'],
        )
    else
        exe = executable(
            'fuzz-' + name,
            t['sources'] + ['fuzz-driver.c'],
            include_directories: include_directories('../../src'),
            dependencies: t['deps'],
        )
        test(
            'nvme-cli - fuzz-' + name,
            exe,
            args: [meson.current_source_dir() / 'corpus' / name],
            workdir: meson.current_build_dir(),
            suite: 'fuzz',
            timeout: 120,
        )
    endif
endforeach
