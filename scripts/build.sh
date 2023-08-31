#!/bin/bash

usage() {
    echo "Usage: build.sh [-b [release|debug]] "
    echo "                [-c [gcc|clang]]"
    echo "                [-m [meson|muon]"
    echo "                [config]"
    echo ""
    echo "CI build script."
    echo ""
    echo " -b [release]|debug   build type"
    echo " -c [gcc]|clang       compiler to use"
    echo " -m [meson]|muon      use meson or muon"
    echo " -t [armhf]|ppc64le|s390x  cross compile target"
    echo ""
    echo "configs with meson:"
    echo "  [default]           default settings"
    echo "  libdbus             build with libdbus"
    echo "  fallback            download all dependencies"
    echo "                      and build them as shared libaries"
    echo "  cross               use cross toolchain to build"
    echo "  coverage            build coverage report"
    echo ""
    echo "configs with muon:"
    echo "  [default]           minimal static build"
}

BUILDTOOL=meson
MESON=meson
BUILDTYPE=release
CROSS_TARGET=armhf
CC=${CC:-"gcc"}

while getopts "b:c:m:t:" o; do
    case "${o}" in
        b)
            BUILDTYPE="${OPTARG}"
            ;;
        c)
            CC="${OPTARG}"
            ;;
        m)
            BUILDTOOL="${OPTARG}"
            ;;
        t)
            CROSS_TARGET="${OPTARG}"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))

CONFIG=${1:-"default"}

cd "$(git rev-parse --show-toplevel)" || exit 1

BUILDDIR="$(pwd)/.build-ci"

fn_exists() { declare -F "$1" > /dev/null; }

config_meson_default() {
    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        "${BUILDDIR}"
}

config_meson_libdbus() {
    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        -Dlibdbus=enabled                       \
        --prefix=/                              \
        "${BUILDDIR}"
}

config_meson_fallback() {
    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        --wrap-mode=forcefallback               \
        -Dlibdbus=enabled                       \
        -Ddbus:werror=false                     \
        -Dopenssl:werror=false                  \
        "${BUILDDIR}"
}

config_meson_cross() {
    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        --cross-file=.github/cross/ubuntu-cross-"${CROSS_TARGET}".txt \
        -Dpython=disabled                       \
        -Dopenssl=disabled                      \
        "${BUILDDIR}"
}

config_meson_coverage() {
    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        --wrap-mode=nofallback                  \
        -Dlibdbus=enabled                       \
        -Db_coverage=true                       \
        "${BUILDDIR}"
}

build_meson() {
    "${MESON}" compile                          \
        -C "${BUILDDIR}"
}

test_meson() {
    "${MESON}" test                             \
        -C "${BUILDDIR}"
}

test_meson_coverage() {
    ninja -C "${BUILDDIR}" coverage --verbose
}

tools_build_samurai() {
    mkdir -p "${BUILDDIR}"/build-tools
    git clone --depth 1 https://github.com/michaelforney/samurai.git \
        "${BUILDDIR}/build-tools/samurai"
    pushd "${BUILDDIR}/build-tools/samurai" || exit 1

    CC="${CC}" make
    SAMU="${BUILDDIR}/build-tools/samurai/samu"

    popd || exit 1
}

tools_build_muon() {
    mkdir -p "${BUILDDIR}"/build-tools
    git clone --depth 1 https://git.sr.ht/~lattis/muon \
        "${BUILDDIR}/build-tools/muon"
    pushd "${BUILDDIR}/build-tools/muon" || exit 1

    CC="${CC}" ninja="${SAMU}" ./bootstrap.sh stage1

    CC="${CC}" ninja="${SAMU}" stage1/muon setup        \
        -Dprefix="${BUILDDIR}/build-tools"              \
        -Dlibcurl=enabled                               \
        -Dlibarchive=enabled                            \
        -Dlibpkgconf=enabled                            \
        -Ddocs=disabled                                 \
        -Dsamurai=disabled                              \
        "${BUILDDIR}/build-tools/.build-muon"
    "${SAMU}" -C "${BUILDDIR}/build-tools/.build-muon"
    MUON="${BUILDDIR}/build-tools/.build-muon/muon"

    # "${MUON}" -C "${BUILDDIR}/build-tools/.build-muon" test

    popd || exit 1
}

config_muon_default() {
    CC="${CC}" CFLAGS="${CFLAGS} -static"               \
        ninja="${SAMU}" "${MUON}" setup                 \
        -Ddefault_library=static                        \
        -Djson-c=disabled                               \
        -Dopenssl=disabled                              \
        -Dkeyutils=disabled                             \
        -Dpython=disabled                               \
        -Dpython=disabled                               \
        "${BUILDDIR}"
}

build_muon() {
    "${SAMU}" -C "${BUILDDIR}"
}

test_muon() {
    ninja="${SAMU}" "${MUON}" -C "${BUILDDIR}" test
}

rm -rf "${BUILDDIR}"

if [[ "${BUILDTOOL}" == "muon" ]]; then
    if ! which samu ; then
        tools_build_samurai
    else
        SAMU="$(which samu)"
    fi

    if ! which muon ; then
        tools_build_muon
    else
        MUON="$(which muon)"
    fi
fi

config_"${BUILDTOOL}"_"${CONFIG}"
fn_exists "build_${BUILDTOOL}_${CONFIG}" && "build_${BUILDTOOL}_${CONFIG}" || build_"${BUILDTOOL}"
fn_exists "test_${BUILDTOOL}_${CONFIG}" && "test_${BUILDTOOL}_${CONFIG}" || test_"${BUILDTOOL}"
