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
    echo ""
    echo "configs with meson:"
    echo "  [default]           default settings"
    echo "  libdbus             build with libdbus"
    echo "  static              build without any depedencies and static"
    echo "  fallback            download all dependencies"
    echo "                      and build them as shared libaries"
    echo "  cross_armhf         build armhf with a cross compiler"
    echo "  cross_ppc64le       build ppc64le with a cross compiler"
    echo "  cross_s390x         build s390x with a cross compiler"
    echo ""
    echo "configs with muon:"
    echo "  [default]           minimal build"
}

BUILDTOOL=meson
MESON=meson
BUILDTYPE=release
CC=${CC:-"gcc"}

while getopts "b:c:m:" o; do
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

config_meson_static() {
    CC="${CC}" CFLAGS="${CFLAGS} -static"       \
        "${MESON}" setup                        \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        --default-library=static                \
        -Dlibdbus=disabled                      \
        -Dopenssl=disabled                      \
        -Dkeyutils=disabled                     \
        -Dpython=disabled                       \
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

config_meson_cross_armhf() {
    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        --cross-file=.github/cross/ubuntu-armhf.txt \
        -Dpython=disabled                       \
        "${BUILDDIR}"
}

config_meson_cross_ppc64le() {
    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        --cross-file=.github/cross/ubuntu-ppc64le.txt \
        -Dpython=disabled                       \
        "${BUILDDIR}"
}

config_meson_cross_s390x() {
    CC="${CC}" "${MESON}" setup                 \
        --werror                                \
        --buildtype="${BUILDTYPE}"              \
        --cross-file=.github/cross/ubuntu-s390x.txt \
        -Dpython=disabled                       \
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

tools_build_muon() {
    mkdir -p "${BUILDDIR}"/build-tools
    git clone --depth 1 https://git.sr.ht/~lattis/muon "${BUILDDIR}/build-tools/muon"
    pushd "${BUILDDIR}/build-tools/muon" || exit 1

    CC="${CC}" ./tools/bootstrap_ninja.sh build
    SAMU="${BUILDDIR}/build-tools/muon/build/samu"

    CC="${CC}" ninja="${SAMU}" ./bootstrap.sh build
    BOOTSTRAP_MUON="${BUILDDIR}/build-tools/muon/build/muon"

    CC="${CC}" ninja="${SAMU}" ${BOOTSTRAP_MUON} setup  \
        -Dlibcurl=disabled                              \
        -Dlibarchive=disabled                           \
        -Ddocs=disabled                                 \
        -Dsamurai=disabled                              \
        "${BUILDDIR}/build-tools/muon-bin"
    "${SAMU}" -C "${BUILDDIR}/build-tools/muon-bin"
    #"${BOOTSTRAP_MUON}" -C "${BUILDDIR}/build-tools/muon-bin" test

    MUON="${BUILDDIR}/build-tools/muon-bin/muon"

    popd || exit 1
}

config_muon_default() {
    # Need to explicitly disable python as muon currently
    # only partially supports the python module. It misses
    # the dependency() implementation
    ninja="${SAMU}" "${MUON}" setup                     \
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
    if ! which samu || ! which muon ; then
        tools_build_muon
    else
        SAMU="$(which samu)"
        MUON="$(which muon)"
    fi
fi

config_"${BUILDTOOL}"_"${CONFIG}"
build_"${BUILDTOOL}"
test_"${BUILDTOOL}"
