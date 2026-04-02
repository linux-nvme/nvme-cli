#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>

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
    echo " -t [arm]|ppc64le|s390x  cross compile target"
    echo " -x                   run test with valgrind"
    echo ""
    echo "configs with meson:"
    echo "  [default]           default settings"
    echo "  libdbus             build with libdbus"
    echo "  fallback            download all dependencies"
    echo "                      and build them as shared libraries"
    echo "  cross               use cross toolchain to build"
    echo "  coverage            build coverage report"
    echo "  distro              build libnvme and nvme-cli separately"
    echo "  docs                build all documentation"
    echo "  man_docs            build man documentation only"
    echo "  html_docs           build html documentation only"
    echo "  rst_docs            build rst documentation only"
    echo "  static              build a static binary"
    echo "  minimal_static      build a static binary without fabrics support"
    echo "  libnvme             build only libnvme"
    echo "  tests               build for nightly build"
    echo ""
    echo "configs with muon:"
    echo "  [default]           minimal static build"
}

BUILDTOOL=meson
MESON=meson
BUILDTYPE=release
CROSS_TARGET=arm
CC=${CC:-"gcc"}

use_valgrind=0

while getopts "b:c:m:t:x" o; do
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
        x)
            use_valgrind=1
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
        -Dpython=disabled                       \
        "${BUILDDIR}"
}

config_meson_libdbus() {
    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        -Dlibdbus=enabled                       \
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

config_meson_cross() {
    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        --cross-file=.github/cross/ubuntu-cross-${CROSS_TARGET}.txt \
        -Dpython=disabled               \
        -Dopenssl=disabled              \
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
        --prefix=/tmp/usr                       \
        "${BUILDDIR}"
}

config_meson_man_docs() {
    CC="${CC}" "${MESON}" setup                 \
        -Ddocs=man                              \
        -Ddocs-build=true                       \
        --prefix=/tmp/usr                       \
        "${BUILDDIR}"
}

config_meson_html_docs() {
    CC="${CC}" "${MESON}" setup                 \
        -Ddocs=html                             \
        -Ddocs-build=true                       \
        --prefix=/tmp/usr                       \
        "${BUILDDIR}"
}

config_meson_rst_docs() {
    CC="${CC}" "${MESON}" setup                 \
        -Ddocs=rst                              \
        -Ddocs-build=true                       \
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
        -Dliburing=disabled                     \
        -Dpython=disabled                       \
        -Dopenssl=disabled                      \
        -Dtests=false                           \
        -Dexamples=false                        \
        "${BUILDDIR}"
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
        -Djson-c=disabled                       \
        -Dtests=false                           \
        -Dexamples=false                        \
        "${BUILDDIR}"
}

config_meson_tests() {
    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        -Dnvme-tests=true                       \
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

build_meson() {
    "${MESON}" compile                          \
        -C "${BUILDDIR}"
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
            args+=(--wrapper valgrind)
        else
            echo "Warning: valgrind requested but not found; running without it." >&2
        fi
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

test_meson_coverage() {
    "${MESON}" test                             \
        -C "${BUILDDIR}"
    ninja -C "${BUILDDIR}" coverage --verbose
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
        -Djson-c=disabled                       \
        -Dpython=disabled                       \
        -Dopenssl=disabled                      \
        -Dkeyutils=disabled                     \
        -Djson-c=disabled                               \
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
fn_exists "install_${BUILDTOOL}_${CONFIG}" && "install_${BUILDTOOL}_${CONFIG}" || true;
