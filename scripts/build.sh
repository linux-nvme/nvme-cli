#!/bin/bash
set -e

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
    echo "  docs                build documentation"
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
TOOLDIR="$(pwd)/.build-tools"

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

config_meson_docs() {
    CC="${CC}" "${MESON}" setup                 \
        -Ddocs=all                              \
        -Ddocs-build=true                       \
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
    "${MESON}" test                             \
        -C "${BUILDDIR}"
    ninja -C "${BUILDDIR}" coverage --verbose
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

    CC="${CC}" CFLAGS="${CFLAGS} -std=c99" ninja="${SAMU}" \
        ./bootstrap.sh stage1

    CC="${CC}" ninja="${SAMU}" stage1/muon setup        \
        -Dprefix="${TOOLDIR}"                           \
        -Ddocs=disabled                                 \
        -Dsamurai=disabled                              \
        "${TOOLDIR}/build-muon"
    "${SAMU}" -C "${TOOLDIR}/build-muon"

    # "${TOOLDIR}/build-muon/muon" \
    #    -C "${TOOLDIR}/build-muon" test

    popd || exit 1
}

config_muon_default() {
    CC="${CC}" CFLAGS="${CFLAGS}" ninja="${SAMU}"       \
        "${MUON}" setup                                 \
        -Ddefault_library=static                        \
        -Dc_link_args="-static"                         \
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
fn_exists "build_${BUILDTOOL}_${CONFIG}" && "build_${BUILDTOOL}_${CONFIG}" || build_"${BUILDTOOL}"
fn_exists "test_${BUILDTOOL}_${CONFIG}" && "test_${BUILDTOOL}_${CONFIG}" || test_"${BUILDTOOL}"
