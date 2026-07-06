#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Utility for installing the UCRT64 MinGW build toolchain and nvme-cli
# dependencies within an MSYS2 environment on Windows.
#
# This file is part of nvme.
# Copyright (c) 2026 Micron Technology, Inc.
#
# Authors: Broc Going <bgoing@micron.com>

set -e

usage() {
    echo "Usage: win-ucrt64-setup.sh [-u]"
    echo ""
    echo "Install UCRT64 MinGW build toolchain and nvme-cli dependencies."
    echo ""
    echo " -u   refresh package database and upgrade all packages"
}

PACMAN_CMD="-S"

while getopts "u" o; do
    case "${o}" in
        u)
            PACMAN_CMD="-Syu"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))

# Install the UCRT64 MinGW build toolchain, meson build system, and nvme-cli
# dependencies. Use -u to also refresh and upgrade all packages.
pacman $PACMAN_CMD --noconfirm --needed \
    mingw-w64-ucrt-x86_64-toolchain \
    mingw-w64-ucrt-x86_64-meson \
    mingw-w64-ucrt-x86_64-ninja \
    mingw-w64-ucrt-x86_64-ccache \
    mingw-w64-ucrt-x86_64-json-c
