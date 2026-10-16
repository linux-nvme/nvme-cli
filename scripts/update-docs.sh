#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later

cd "$(git rev-parse --show-toplevel)" || exit 1

BUILDDIR="$(mktemp -d)"
trap 'rm -rf -- $BUILDDIR' EXIT

meson setup "${BUILDDIR}" || exit 1
meson compile -C "${BUILDDIR}" update-docs || exit 1
