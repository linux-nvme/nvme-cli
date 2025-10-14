#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later

cd "$(git rev-parse --show-toplevel)" || exit 1

BUILDDIR="$(mktemp -d)"
trap 'rm -rf -- $BUILDDIR' EXIT

meson setup                        \
     -Ddocs=all                    \
     -Ddocs-build=true             \
     --force-fallback-for=libnvme  \
     "${BUILDDIR}"
meson compile -C "${BUILDDIR}"
find "${BUILDDIR}/Documentation" -maxdepth 1 \
     \( -name '*.1' -o -name '*.html' \) \
     -exec cp {} Documentation/ \;
