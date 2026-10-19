#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>

set -e

ALL_FUZZ_TARGETS="argconfig ini global-config fabrics-conf device"

usage() {
    echo "Usage: build.sh [-b [release|debug]] "
    echo "                [-c [gcc|clang]]"
    echo "                [-m [meson|muon]"
    echo "                [--e2e-controller /dev/nvme0]"
    echo "                [--e2e-ns1 /dev/nvme0n1]"
    echo "                [--e2e-log-dir dir]"
    echo "                [--e2e-log-level level]"
    echo "                [--e2e-nvme-bin path]"
    echo "                [--plugin-tests plugin1,plugin2]"
    echo "                [--fuzz-seconds n] [--fuzz-jobs n]"
    echo "                [--fuzz-targets target1,target2] [--fuzz-dir dir]"
    echo "                [config]"
    echo ""
    echo "CI build script."
    echo ""
    echo " -a                   run static analysis with clang analyzer"
    echo " -b [release]|debug   build type"
    echo " -c [gcc]|clang       compiler to use"
    echo " -m [meson]|muon      use meson or muon"
    echo " -p                   enable coverage report"
    echo " -s                   run tests with ASan+UBSan (asanubsan setup)"
    echo " -t [armhf]|ppc64le|s390x|i386 cross compile target"
    echo " -x                   run tests with valgrind (valgrind setup)"
    echo ""
    echo "options for the 'tests' config (mirror the e2e-* meson options):"
    echo " --e2e-controller dev    controller device for e2e tests, e.g. /dev/nvme0"
    echo "                         (required when running the 'tests' config)"
    echo " --e2e-ns1 dev           namespace device for e2e tests, e.g. /dev/nvme0n1"
    echo "                         (required when running the 'tests' config)"
    echo " --e2e-log-dir dir       log directory for e2e tests"
    echo " --e2e-log-level level   log verbosity for e2e tests"
    echo " --e2e-nvme-bin path     nvme binary to exercise in e2e tests"
    echo " --plugin-tests list     comma-separated list of plugin test suites to"
    echo "                         run against real hardware, e.g. micron,ocp"
    echo ""
    echo "options for the 'fuzz' config:"
    echo " --fuzz-seconds n        run each target for n seconds (600)"
    echo " --fuzz-jobs n           run n libFuzzer jobs per target (all CPUs)"
    echo " --fuzz-targets list     comma-separated list of targets (all):"
    echo "                         ${ALL_FUZZ_TARGETS// /, }"
    echo " --fuzz-dir dir          directory for the results (.build-ci/fuzz):"
    echo "                         summary.txt, logs/, artifacts/ and corpus/"
    echo ""
    echo "configs with meson:"
    echo "  [default]           default settings"
    echo "  libdbus             build with libdbus"
    echo "  liburing            build with liburing"
    echo "  fallback            download all dependencies"
    echo "                      and build them as shared libraries"
    echo "  cross               use cross toolchain to build"
    echo "  distro              build libnvme and nvme-cli separately"
    echo "  docs                build all documentation"
    echo "  man_docs            build man documentation only"
    echo "  html_docs           build html documentation only"
    echo "  rst_docs            build rst documentation only"
    echo "  static              build a static binary"
    echo "  static_windows      build a static binary on MSYS2"
    echo "  minimal_static      build a static binary without fabrics support"
    echo "  nofabrics           build without fabrics support, run unit tests"
    echo "  libnvme             build only libnvme"
    echo "  libnvme_abi         build only libnvme3.so, no tests/examples"
    echo "  tests               build for nightly build"
    echo "  fuzz                build the fuzz targets for libFuzzer with clang"
    echo "                      and run them, see the options above"
    echo ""
    echo "configs with muon:"
    echo "  [default]           minimal static build"
}

BUILDTOOL=meson
MESON=meson
BUILDTYPE=release
CROSS_TARGET=armhf
CC=${CC:-"gcc"}
SCAN_BUILD=""

use_coverage=0
use_valgrind=0
use_asan=0
use_analyzer=0

E2E_CONTROLLER=""
E2E_NS1=""
E2E_LOG_DIR=""
E2E_LOG_LEVEL=""
E2E_NVME_BIN=""
PLUGIN_TESTS=""

fuzz_seconds=600
fuzz_jobs=""
fuzz_targets="${ALL_FUZZ_TARGETS}"
fuzz_dir=""

# The options which only one config takes, as "config option"
CONFIG_OPTIONS=()
config_option() {
    CONFIG_OPTIONS+=("$1 $2")
}

ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -a)
            if ! command -v clang > /dev/null 2>&1; then
                echo "Error: clang is not found; please install clang."
                exit 1
            fi

            if ! command -v scan-build >/dev/null 2>&1; then
                echo "Error: scan-build is not found; please install clang-analyzer."
                exit 1
            fi

            use_analyzer=1
            CC=clang
            SCAN_BUILD=scan-build
            shift
            ;;
        -b)
            BUILDTYPE="$2"
            shift 2
            ;;
        -c)
            CC="$2"
            shift 2
            ;;
        -m)
            BUILDTOOL="$2"
            shift 2
            ;;
        -p)
            use_coverage=1
            shift
            ;;
        -s)
            use_asan=1
            shift
            ;;
        -t)
            CROSS_TARGET="$2"
            shift 2
            ;;
        -x)
            use_valgrind=1
            shift
            ;;
        --e2e-controller)
            E2E_CONTROLLER="$2"
            config_option tests "$1"
            shift 2
            ;;
        --e2e-ns1)
            E2E_NS1="$2"
            config_option tests "$1"
            shift 2
            ;;
        --e2e-log-dir)
            E2E_LOG_DIR="$2"
            config_option tests "$1"
            shift 2
            ;;
        --e2e-log-level)
            E2E_LOG_LEVEL="$2"
            config_option tests "$1"
            shift 2
            ;;
        --e2e-nvme-bin)
            E2E_NVME_BIN="$2"
            config_option tests "$1"
            shift 2
            ;;
        --plugin-tests)
            PLUGIN_TESTS="$2"
            config_option tests "$1"
            shift 2
            ;;
        --fuzz-seconds|--fuzz-jobs)
            if ! [[ "$2" =~ ^[1-9][0-9]*$ ]]; then
                echo "error: $1 takes a positive number" >&2
                exit 1
            fi
            if [[ "$1" == --fuzz-seconds ]]; then
                fuzz_seconds="$2"
            else
                fuzz_jobs="$2"
            fi
            config_option fuzz "$1"
            shift 2
            ;;
        --fuzz-targets)
            fuzz_targets="${2//,/ }"
            for t in ${fuzz_targets}; do
                if [[ " ${ALL_FUZZ_TARGETS} " != *" ${t} "* ]]; then
                    echo "error: unknown fuzz target '${t}'" >&2
                    exit 1
                fi
            done
            config_option fuzz "$1"
            shift 2
            ;;
        --fuzz-dir)
            # relative to where build.sh runs, not to the top directory
            if [[ "$2" == /* ]]; then
                fuzz_dir="$2"
            else
                fuzz_dir="$(pwd)/$2"
            fi
            config_option fuzz "$1"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            usage
            exit 1
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done
set -- "${ARGS[@]}"

CONFIG=${1:-"default"}

for opt in "${CONFIG_OPTIONS[@]}"; do
    if [[ "${opt%% *}" != "${CONFIG}" ]]; then
        echo "error: ${opt#* } is only valid with the '${opt%% *}' config" >&2
        exit 1
    fi
done

cd "$(git rev-parse --show-toplevel)" || exit 1

BUILDDIR="$(pwd)/.build-ci"
TOOLDIR="$(pwd)/.build-tools"

fn_exists() { declare -F "$1" > /dev/null; }

config_meson_default() {
    local extra_args=()
    if [ "${use_asan:-0}" -eq 1 ]; then
        extra_args+=(-Db_sanitize=address,undefined)
        # The C++ tests need clang++ to match, and clang links the
        # sanitizer runtime only into executables.
        if [[ "${CC}" == *clang* ]]; then
            export CXX="${CXX:-${CC/clang/clang++}}"
            extra_args+=(-Db_lundef=false)
        fi
    fi
    # Build nvme-keysd in CI. "enabled" fails without libsystemd >= 257.
    if pkg-config --atleast-version=257 libsystemd 2>/dev/null; then
        extra_args+=(-Dnvme-keysd=enabled)
    fi

    CC="${CC}" ${SCAN_BUILD} "${MESON}" setup \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
		-Dioctl-tests=true						\
        "${extra_args[@]}"                      \
        "${BUILDDIR}"
}

config_meson_musl() {
	local cflags=(
		-U_GNU_SOURCE
		-idirafter /usr/include
		-idirafter /usr/include/x86_64-linux-gnu
	)
	local cflags_str="${cflags[*]}"

    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        -Dc_args="${cflags_str}"                \
        -Ddefault_library=static                \
        -Djson-c=disabled                       \
        -Dopenssl=disabled                      \
        -Dkeyutils=disabled                     \
        -Dlibarchive=disabled                   \
        -Dpython=disabled                       \
        -Dnvme-discoverd=disabled               \
        "${BUILDDIR}"
}

config_meson_libdbus() {
    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
		-Ddeprecated-cmds=enabled				\
        -Dlibdbus=enabled                       \
        --prefix="${BUILDDIR}/usr"              \
        "${BUILDDIR}"
}

config_meson_liburing() {
    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        -Dliburing=enabled                      \
        --prefix="${BUILDDIR}/usr"              \
        "${BUILDDIR}"
}

config_meson_fallback() {
    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        --wrap-mode=forcefallback               \
        --default-library=both                  \
        -Dlibdbus=enabled                       \
        -Ddbus:werror=false                     \
        -Dopenssl:werror=false                  \
        "${BUILDDIR}"
}

# The cross files work on Debian and Ubuntu, see Documentation/TESTING.md
config_meson_cross() {
    local triplet
    local opts=()

    case "${CROSS_TARGET}" in
        armhf)   triplet=arm-linux-gnueabihf ;;
        ppc64le) triplet=powerpc64le-linux-gnu ;;
        s390x)   triplet=s390x-linux-gnu ;;
        *)       triplet="" ;;
    esac
    # The tests run the binaries through binfmt_misc too, not only through
    # the exe_wrapper of the cross file: point qemu at the libraries of the
    # cross toolchain. qemu still finds what is not there, like the
    # libraries of the target architecture in the multiarch directories.
    if [ -n "${triplet}" ] && [ -d "/usr/${triplet}/lib" ] &&
       [ -z "${QEMU_LD_PREFIX:-}" ]; then
        export QEMU_LD_PREFIX="/usr/${triplet}"
    fi
    # The micron and ocp plugins decode some logs in host byte order, which
    # the JSON based mock tests of them catch on big endian: leave them out
    # until that is fixed.
    if [ "${CROSS_TARGET}" = "s390x" ]; then
        opts+=(-Djson-c=disabled)
    fi

    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        --cross-file=.github/cross/cross-${CROSS_TARGET}.txt \
        -Dpython=disabled               \
        -Dopenssl=disabled              \
        "${opts[@]}"                    \
        "${BUILDDIR}"
}

config_meson_docs() {
    CC="${CC}" "${MESON}" setup                 \
        -Ddocs=all                              \
        -Ddocs-build=true                       \
		-Ddeprecated-cmds=enabled				\
        --prefix=/tmp/usr                       \
        "${BUILDDIR}"
}

config_meson_man_docs() {
    CC="${CC}" "${MESON}" setup                 \
        -Ddocs=man                              \
        -Ddocs-build=true                       \
		-Ddeprecated-cmds=enabled				\
        --prefix=/tmp/usr                       \
        "${BUILDDIR}"
}

config_meson_html_docs() {
    CC="${CC}" "${MESON}" setup                 \
        -Ddocs=html                             \
        -Ddocs-build=true                       \
		-Ddeprecated-cmds=enabled				\
        --prefix=/tmp/usr                       \
        "${BUILDDIR}"
}

config_meson_rst_docs() {
    CC="${CC}" "${MESON}" setup                 \
        -Ddocs=rst                              \
        -Ddocs-build=true                       \
		-Ddeprecated-cmds=enabled				\
        --prefix=/tmp/usr                       \
        "${BUILDDIR}"
}

config_meson_static() {
    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype=release                     \
        --default-library=static                \
        --wrap-mode=forcefallback               \
        --prefix=/usr                           \
        -Dc_link_args="-static"                 \
        -Dkeyutils=disabled                     \
        -Dlibkmod=disabled                      \
        -Dliburing=disabled                     \
        -Dpython=disabled                       \
        -Dopenssl=disabled                      \
        -Dnvme-discoverd=disabled               \
        -Dlibarchive=disabled                   \
        -Dtests=false                           \
        -Dexamples=false                        \
        "${BUILDDIR}"
}

config_meson_static_windows() {
    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype=release                     \
        --default-library=static                \
        -Dc_link_args="-static"                 \
        -Dlibarchive=disabled                   \
        -Dpython=disabled                       \
        -Dopenssl=disabled                      \
        -Dtests=false                           \
        -Dexamples=false                        \
        "${BUILDDIR}"
}

test_meson_static_windows() {
    # Fail if nvme.exe needs a DLL that is not part of Windows.
    ldd "${BUILDDIR}/nvme.exe"
    ! ldd "${BUILDDIR}/nvme.exe" | grep -v -i '/c/windows/'
}

config_meson_minimal_static() {
	local cflags=(
		-U_GNU_SOURCE
		-idirafter /usr/include
		-idirafter /usr/include/x86_64-linux-gnu
		-Oz
		-flto
		-ffunction-sections
		-fdata-sections
		-fno-unwind-tables
		-fno-asynchronous-unwind-tables
		-fno-stack-protector
	)
	local ldflags=(
		-flto
		-Wl,--gc-sections
		-s
		-Wl,--build-id=none
		-static
	)
	local cflags_str="${cflags[*]}"
	local ldflags_str="${ldflags[*]}"

	CC=musl-gcc

    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype=release                     \
        --default-library=static                \
        --prefix=/usr                           \
        -Dplugins="sed,lm,feat,zns,fdp"         \
        -Dc_args="${cflags_str}"                \
        -Dc_link_args="${ldflags_str}"          \
        -Dfabrics=disabled                      \
        -Dlibkmod=disabled                      \
        -Dmi=disabled                           \
        -Djson-c=disabled                       \
        -Dopenssl=disabled                      \
        -Dlibarchive=disabled                   \
        -Dtests=false                           \
        -Dexamples=false                        \
        "${BUILDDIR}"
}

config_meson_nofabrics() {
    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        -Dfabrics=disabled                      \
        -Dmi=disabled                           \
        -Dpython=disabled                       \
        -Djson-c=disabled                       \
        -Dlibkmod=disabled                      \
        -Dopenssl=disabled                      \
        -Dkeyutils=disabled                     \
        -Dlibarchive=disabled                   \
        "${BUILDDIR}"
}

config_meson_tests() {
    # e2e tests are destructive and refuse to guess a target device, so
    # --e2e-controller/--e2e-ns1 must be passed on the command line (meson
    # setup errors out on its own if they're left unset). The remaining
    # options are optional and mirror the other e2e-*/plugin-tests meson
    # options.
    local extra_args=()
    [ -n "${E2E_CONTROLLER}" ] && extra_args+=(-De2e-controller="${E2E_CONTROLLER}")
    [ -n "${E2E_NS1}" ] && extra_args+=(-De2e-ns1="${E2E_NS1}")
    [ -n "${E2E_LOG_DIR}" ] && extra_args+=(-De2e-log-dir="${E2E_LOG_DIR}")
    [ -n "${E2E_LOG_LEVEL}" ] && extra_args+=(-De2e-log-level="${E2E_LOG_LEVEL}")
    [ -n "${E2E_NVME_BIN}" ] && extra_args+=(-De2e-nvme-bin="${E2E_NVME_BIN}")
    [ -n "${PLUGIN_TESTS}" ] && extra_args+=(-Dplugin-tests="${PLUGIN_TESTS}")

    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        -De2e-tests=true                        \
        "${extra_args[@]}"                      \
        "${BUILDDIR}"
}

config_meson_libnvme() {
    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        -Dnvme=disabled                         \
        -Dlibnvme=enabled                       \
        "${BUILDDIR}"
}

# Like libnvme above, but for callers that only need the compiled
# libnvme3.so itself (e.g. an ABI comparison) and not the test suite.
config_meson_libnvme_abi() {
    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        -Dnvme=disabled                         \
        -Dlibnvme=enabled                       \
        -Dtests=false                           \
        -Dexamples=false                        \
        "${BUILDDIR}"
}

test_meson_libnvme_abi() {
    :
}

# Coverage guided fuzzing with libFuzzer, see Documentation/TESTING.md.
# The results are in the --fuzz-dir, by default in the build directory:
# per target the corpus, the logs and the inputs which found a bug, and a
# summary. A --fuzz-dir outside of it grows the corpus across runs.
config_meson_fuzz() {
    if [[ "${CC}" != *clang* ]]; then
        CC=clang
    fi
    CXX="${CXX:-${CC/clang/clang++}}"

    CC="${CC}" CXX="${CXX}" "${MESON}" setup    \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        -Dfuzzing=true                          \
        -Db_sanitize=address,undefined          \
        -Db_lundef=false                        \
        "${BUILDDIR}"
}

test_meson_fuzz() {
    local root
    root="$(pwd)"
    local dir="${fuzz_dir:-${BUILDDIR}/fuzz}"
    local seconds="${fuzz_seconds}"
    local jobs="${fuzz_jobs:-$(nproc 2>/dev/null || echo 1)}"
    local failed=()
    local t f exe corpus artifacts logs args status summary stamp found
    # A device reports sizes of up to gigabytes: let ASan fail such an
    # allocation instead of libFuzzer aborting as out of memory.
    local asan="allocator_may_return_null=1:max_allocation_size_mb=1024"

    mkdir -p "${dir}"
    summary="${dir}/summary.txt"
    : > "${summary}"

    # A UBSan finding is a crash too
    export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}"

    for t in ${fuzz_targets}; do
        exe="${BUILDDIR}/tests/fuzz/fuzz-${t}"
        if [ ! -x "${exe}" ]; then
            echo "fuzz-${t}: not built, skipped"
            continue
        fi

        corpus="${dir}/corpus/${t}"
        artifacts="${dir}/artifacts/${t}"
        logs="${dir}/logs/${t}"
        rm -rf "${logs}"
        mkdir -p "${corpus}" "${artifacts}" "${logs}"
        # Add the seeds, but keep what earlier runs found
        for f in "${root}"/tests/fuzz/corpus/"${t}"/*; do
            [ -e "${corpus}/${f##*/}" ] || cp "${f}" "${corpus}/"
        done

        # Run the jobs as independent processes on the shared corpus. The
        # -fork mode is newer, but the libFuzzer of clang 22 crashes in it.
        # A job ends at its first finding, so queue more jobs than workers
        # to keep all of them busy: the timeout below ends the run.
        args=(-close_fd_mask=3 -max_total_time="${seconds}"
              -jobs="$((jobs * 100))" -workers="${jobs}"
              -artifact_prefix="${artifacts}/")
        case "${t}" in
            argconfig)
                args+=(-dict="${root}/tests/fuzz/argconfig.dict")
                ;;
            device)
                args+=(-max_len=16384 -timeout=10)
                ;;
            *)
                args+=(-dict="${root}/tests/fuzz/config.dict")
                ;;
        esac

        echo "fuzz-${t}: ${seconds}s, ${jobs} jobs, logs in ${logs}"
        # Each job writes fuzz-<job>.log to the current directory. The
        # timeout signals the whole process group, the jobs included: a
        # job whose timeout handler deadlocks would keep libFuzzer waiting
        # forever otherwise.
        stamp="${logs}/start"
        touch "${stamp}"
        status=0
        (cd "${logs}" &&
         ASAN_OPTIONS="${ASAN_OPTIONS:+${ASAN_OPTIONS}:}${asan}" \
            timeout --kill-after=60 "$((seconds + 60))" \
            "${exe}" "${args[@]}" "${corpus}" > main.log 2>&1) ||
            status=$?
        # Whether libFuzzer exits on its own or the timeout ends it (124,
        # or 137 after SIGKILL), the inputs it saved tell about the
        # findings. A slow unit is none.
        found="$(find "${artifacts}" -type f -newer "${stamp}" \
                 ! -name 'slow-unit-*' | wc -l)"
        if [ "${found}" -gt 0 ]; then
            failed+=("${t}")
            echo "fuzz-${t}: ${found} findings, exit status ${status}" |
                tee -a "${summary}"
            {
                grep -hE '^(SUMMARY|==[0-9]+==ERROR)' "${logs}"/fuzz-*.log ||
                    true
                find "${artifacts}" -type f -newer "${stamp}" \
                     ! -name 'slow-unit-*'
            } >> "${summary}"
        elif [[ ! "${status}" =~ ^(0|124|137)$ ]]; then
            failed+=("${t}")
            echo "fuzz-${t}: failed, exit status ${status}" |
                tee -a "${summary}"
        else
            echo "fuzz-${t}: no finding in ${seconds}s" | tee -a "${summary}"
        fi
    done

    if [ "${#failed[@]}" -gt 0 ]; then
        echo "fuzz targets with findings: ${failed[*]}, see ${summary}"
        return 1
    fi
}

build_meson() {
    if [ "${use_analyzer:-0}" -eq 1 ]; then
        "${SCAN_BUILD}" -o "${BUILDDIR}/scan-results" \
            -analyze-headers                          \
            --force-analyze-debug-code                \
            --status-bugs                             \
            "${MESON}" compile -C "${BUILDDIR}"
    else
        "${MESON}" compile                            \
            -C "${BUILDDIR}"
    fi
}

build_meson_docs() {
    "${MESON}" compile                          \
        -C "${BUILDDIR}"                        \
		docs
}

build_meson_man_docs() {
    "${MESON}" compile                          \
        -C "${BUILDDIR}"                        \
		docs
}

build_meson_html_docs() {
    "${MESON}" compile                          \
        -C "${BUILDDIR}"                        \
		docs
}

build_meson_rst_docs() {
    "${MESON}" compile                          \
        -C "${BUILDDIR}"                        \
		docs
}

test_meson() {
    local args=(-C "${BUILDDIR}")

    if [ "${use_valgrind:-0}" -eq 1 ]; then
        if command -v valgrind >/dev/null 2>&1; then
            args+=(--setup valgrind)
        else
            echo "Warning: valgrind requested but not found; running without it." >&2
        fi
    elif [ "${use_asan:-0}" -eq 1 ]; then
        args+=(--setup asanubsan)
    fi

    "${MESON}" test "${args[@]}"
}

test_meson_docs() {
	true
}

test_meson_man_docs() {
	true
}

test_meson_html_docs() {
	true
}

test_meson_rst_docs() {
	true
}

install_meson_docs() {
    "${MESON}" install                          \
        -C "${BUILDDIR}"
}

tools_build_samurai() {
    if [ ! -d "${TOOLDIR}"/samurai ]; then
        git clone --depth 1 https://github.com/michaelforney/samurai.git \
            "${TOOLDIR}/samurai"
    fi

    if [[ -f "${TOOLDIR}/samurai/samu" ]]; then
        return
    fi

    pushd "${TOOLDIR}/samurai" || exit 1
    CC="${CC}" make
    popd || exit 1
}

tools_build_muon() {
    if [ ! -d "${TOOLDIR}/muon" ]; then
        git clone --depth 1 https://git.sr.ht/~lattis/muon \
            "${TOOLDIR}/muon"
    fi

    if [[ -f "${TOOLDIR}/build-muon/muon" ]]; then
        return
    fi

    pushd "${TOOLDIR}/muon" || exit 1

    CC="${CC}" CFLAGS="${CFLAGS} -std=c99" ninja="${SAMU}" ./bootstrap.sh stage1

    CC="${CC}" ninja="${SAMU}" stage1/muon-bootstrap setup    \
        -Dprefix="${TOOLDIR}"                                 \
        -Dsamurai=disabled                                    \
        "${TOOLDIR}/build-muon"
    "${SAMU}" -C "${TOOLDIR}/build-muon"
    MUON="${BUILDDIR}/build-tools/.build-muon/muon"

    # "${TOOLDIR}/build-muon/muon" \
    #    -C "${TOOLDIR}/build-muon" test

    popd || exit 1
}

config_muon_default() {
    # wrap_mode=forcefallback depends on git being available

    CC="${CC}" CFLAGS="${CFLAGS}" ninja="${SAMU}"       \
        "${MUON}" setup                                 \
        -Ddefault_library=static                        \
        -Dc_link_args="-static"                         \
        -Dwrap_mode=forcefallback                       \
        -Djson-c=disabled                               \
        -Dpython=disabled                               \
        -Dopenssl=disabled                              \
        -Dkeyutils=disabled                             \
        -Djson-c=disabled                               \
        -Dnvme-discoverd=disabled                       \
        "${BUILDDIR}"
}

build_muon() {
    "${SAMU}" -C "${BUILDDIR}"
}

test_muon() {
    ninja="${SAMU}" "${MUON}" -C "${BUILDDIR}" test
    ldd "${BUILDDIR}/nvme" 2>&1 | grep 'not a dynamic executable' || exit 1
}

_install_libnvme() {
    local LBUILDDIR="${BUILDDIR}/.build-libnvme"

    CC="${CC}" "${MESON}" setup     \
        --prefix="${BUILDDIR}/usr"  \
        --buildtype="${BUILDTYPE}"  \
        -Dnvme=disabled             \
        "${LBUILDDIR}"

    "${MESON}" compile              \
        -C "${LBUILDDIR}"

    "${MESON}" install              \
        -C "${LBUILDDIR}"
}

config_meson_distro() {
    _install_libnvme

    PKG_CONFIG_PATH="${BUILDDIR}/usr/lib64/pkgconfig" \
    CC="${CC}" ${MESON} setup                         \
        --prefix="${BUILDDIR}/usr"                    \
        --werror                                      \
        --buildtype="${BUILDTYPE}"                    \
        --force-fallback-for=                         \
        -Dlibnvme=disabled                            \
        "${BUILDDIR}"
}

build_meson_distro() {
    build_meson
}

test_meson_distro() {
    test_meson
}

if [[ "${use_coverage}" -eq 1 && "${BUILDTOOL}" != "meson" ]]; then
     echo "error: coverage reporting (-p) is only supported with the meson build tool" >&2
     exit 1
fi

if [[ "${BUILDTOOL}" == "muon" ]]; then
    SAMU="$(which samu 2> /dev/null)" || true
    if [[ -z "${SAMU}" ]]; then
        tools_build_samurai
        SAMU="${TOOLDIR}/samurai/samu"
    fi

    MUON="$(which muon 2> /dev/null)" || true
    if [[ -z "${MUON}" ]]; then
        tools_build_muon
        MUON="${TOOLDIR}/build-muon/muon"
    fi
fi

echo "samu: ${SAMU}"
echo "muon: ${MUON}"

rm -rf "${BUILDDIR}"

config_"${BUILDTOOL}"_"${CONFIG}"
if [[ "${use_coverage}" -eq 1 ]]; then
    "${MESON}" setup --reconfigure "${BUILDDIR}" -Db_coverage=true
fi
fn_exists "build_${BUILDTOOL}_${CONFIG}" && "build_${BUILDTOOL}_${CONFIG}" || build_"${BUILDTOOL}"
if fn_exists "test_${BUILDTOOL}_${CONFIG}"; then
    test_fn="test_${BUILDTOOL}_${CONFIG}"
else
    test_fn="test_${BUILDTOOL}"
fi
test_status=0
"${test_fn}" || test_status=$?
# Write the report also when a test fails.
if [[ "${use_coverage}" -eq 1 ]]; then
    gcovr -r . "${BUILDDIR}" --xml-pretty -o coverage.xml
fi
if [[ "${test_status}" -ne 0 ]]; then
    exit "${test_status}"
fi
fn_exists "install_${BUILDTOOL}_${CONFIG}" && "install_${BUILDTOOL}_${CONFIG}" || true;
