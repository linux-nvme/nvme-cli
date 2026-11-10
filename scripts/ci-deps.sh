#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme.
#
# Dependencies of the nightly tests that Fedora does not ship in a
# recent enough version. The ci-deps workflow builds them in a Fedora
# container and uploads them to the ci-deps release. The nightly tests
# install them from there.
#
# TODO: drop a dependency once the Fedora version of the test VM ships
# it, and install the Fedora package instead.

set -e

# mdadm 4.3 (Fedora 44) has a buffer overflow, fixed by
# https://git.kernel.org/pub/scm/utils/mdadm/mdadm.git/commit/?id=7f960c3bd050e76f8bf0a8a0c8fbdcbaa565fc78
MDADM_VERSION=4.6
# The tlshd of ktls-utils 1.4.0 (Fedora 44) loses the .nvme keyring
# when TLS handshakes run in parallel, which nvme-tcp does since 7.4.
# ktls-utils 1.5.0 fixes this (3a6658e).
KTLS_UTILS_VERSION=1.5.0

DEPS="mdadm ktls-utils"
CI_DEPS_URL=${CI_DEPS_URL:-https://github.com/linux-nvme/nvme-cli/releases/download/ci-deps}

usage() {
    echo "Usage: ci-deps.sh build OUTDIR"
    echo "       ci-deps.sh install NAME..."
    echo ""
    echo "Dependencies: ${DEPS}"
    echo ""
    echo "build    build all dependencies, write a tarball and its"
    echo "         SHA-256 sum per dependency to OUTDIR"
    echo "install  download and install the tarballs from CI_DEPS_URL"
    echo "         (${CI_DEPS_URL}). On error, install the Fedora"
    echo "         package instead."
}

version_of() {
    case "$1" in
        mdadm)          echo "${MDADM_VERSION}" ;;
        ktls-utils)     echo "${KTLS_UTILS_VERSION}" ;;
        *)              echo "unknown dependency: $1" >&2; exit 1 ;;
    esac
}

tarball_of() {
    echo "$1-$(version_of "$1")-$(uname -m).tar.gz"
}

build_mdadm() {
    local destdir="$1"

    git clone --depth 1 -b "mdadm-${MDADM_VERSION}" \
        https://git.kernel.org/pub/scm/utils/mdadm/mdadm.git
    # Fedora has merged /usr/sbin into /usr/bin. The binary is
    # built with the path of mdmon.
    make -C mdadm -j"$(nproc)" BINDIR=/usr/bin
    make -C mdadm install BINDIR=/usr/bin UDEVDIR=/usr/lib/udev \
        DESTDIR="${destdir}"
}

build_ktls_utils() {
    local destdir="$1"

    git clone --depth 1 -b "ktls-utils-${KTLS_UTILS_VERSION}" \
        https://github.com/linux-nfs/ktls-utils.git
    (
        cd ktls-utils
        ./autogen.sh
        # DANE would link libgnutls-dane, which the test VM does not
        # have. NVMe does not use it.
        ./configure --without-dane
        make -j"$(nproc)"
    )
    # Only the binary: the configuration and the unit of the Fedora
    # package stay.
    install -D -m 755 ktls-utils/src/tlshd/tlshd \
        "${destdir}/usr/bin/tlshd"
}

build_all() {
    local outdir
    local workdir
    local name

    outdir=$(realpath "$1")
    mkdir -p "${outdir}"
    workdir=$(mktemp -d)

    for name in ${DEPS}; do
        mkdir -p "${workdir}/${name}/root"
        (
            cd "${workdir}/${name}"
            "build_${name//-/_}" "${workdir}/${name}/root"
        )
        tar -C "${workdir}/${name}/root" --owner=0 --group=0 \
            --numeric-owner -czf "${outdir}/$(tarball_of "${name}")" .
        (
            cd "${outdir}"
            sha256sum "$(tarball_of "${name}")" > \
                "$(tarball_of "${name}").sha256"
        )
    done

    rm -rf "${workdir}"
}

install_one() {
    local name="$1"
    local tarball
    local tmpdir
    local file

    tarball=$(tarball_of "${name}")
    tmpdir=$(mktemp -d)

    if ! curl -fsSL -o "${tmpdir}/${tarball}" \
            "${CI_DEPS_URL}/${tarball}" ||
       ! curl -fsSL -o "${tmpdir}/${tarball}.sha256" \
            "${CI_DEPS_URL}/${tarball}.sha256" ||
       ! (cd "${tmpdir}" && sha256sum -c "${tarball}.sha256"); then
        rm -rf "${tmpdir}"
        return 1
    fi

    if ! sudo tar -C / --keep-directory-symlink --no-overwrite-dir \
            -xzf "${tmpdir}/${tarball}"; then
        rm -rf "${tmpdir}"
        return 1
    fi
    # tar creates new files, which get the label of their directory.
    if command -v restorecon > /dev/null; then
        tar -tzf "${tmpdir}/${tarball}" | grep -v '/$' |
        while read -r file; do
            sudo restorecon "${file#.}"
        done
    fi

    rm -rf "${tmpdir}"
}

install_all() {
    local name

    for name in "$@"; do
        version_of "${name}" > /dev/null
        if install_one "${name}"; then
            echo "Installed $(tarball_of "${name}") from ${CI_DEPS_URL}"
        else
            echo "WARNING: cannot install $(tarball_of "${name}")" \
                "from ${CI_DEPS_URL}, using the Fedora package"
            sudo dnf install -y "${name}"
        fi
    done
}

case "$1" in
    build)
        [ $# -eq 2 ] || { usage; exit 1; }
        build_all "$2"
        ;;
    install)
        shift
        [ $# -ge 1 ] || { usage; exit 1; }
        install_all "$@"
        ;;
    *)
        usage
        exit 1
        ;;
esac
