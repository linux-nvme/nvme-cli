# SPDX-License-Identifier: GPL-2.0-or-later
#
# Fuzz targets for the parsers of untrusted input: the command line, the
# config files and the data from the device. Without -Dfuzzing=true each
# target runs as a test, with the seeds in corpus/<target> and a few
# seconds of mutations of them (FUZZ_SECONDS, FUZZ_SEED). With
# -Dfuzzing=true and clang, the targets are built for libFuzzer:
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

# The device mock answers every command with the fuzz input. It needs
# dlsym(RTLD_NEXT), so a dynamic Linux build.
if want_nvme and have_mock_nvme
    fuzz_targets += {
        'device': {
            'sources': ['fuzz-device.c', '../cli/libmock_nvme.c'],
            'objects': nvme_exe.extract_objects(sources),
            'c_args': ['-DMOCK_FUZZ'],
            'deps': link_deps,
            'link_args': link_args_list,
        },
    }
endif

foreach name, t : fuzz_targets
    if get_option('fuzzing')
        executable(
            'fuzz-' + name,
            t['sources'],
            objects: t.get('objects', []),
            c_args: t.get('c_args', []),
            include_directories: include_directories('../../src'),
            dependencies: t['deps'],
            link_args: t.get('link_args', []) + ['-fsanitize=fuzzer'],
        )
    else
        exe = executable(
            'fuzz-' + name,
            t['sources'] + ['fuzz-driver.c'],
            objects: t.get('objects', []),
            c_args: t.get('c_args', []),
            include_directories: include_directories('../../src'),
            dependencies: t['deps'],
            link_args: t.get('link_args', []),
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
