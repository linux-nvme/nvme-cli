#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later

cd "$(git rev-parse --show-toplevel)" || exit 1

BUILDDIR="$(mktemp -d)"
trap 'rm -rf -- $BUILDDIR' EXIT

meson setup                                 \
	-Dnvme=disabled                         \
	-Dlibnvme=disabled                      \
	-Ddocs=all                              \
	-Ddocs-build=true                       \
	"${BUILDDIR}"
meson compile -C "${BUILDDIR}"

# libnvme
rm -rf libnvme/doc/man
mkdir libnvme/doc/man
find "${BUILDDIR}/libnvme/doc" -maxdepth 1 \
	-name '*.2' -exec cp {} libnvme/doc/man \;

rm -rf libnvme/doc/rst/*.rst
mkdir -p libnvme/doc/rst
find "${BUILDDIR}/libnvme/doc/rst" -maxdepth 1 \
	-name '*.rst' -exec cp {} libnvme/doc/rst \;

cp "${BUILDDIR}/libnvme/doc/conf.py" libnvme/doc
cp "${BUILDDIR}/libnvme/doc/index.rst" libnvme/doc
cp "${BUILDDIR}/libnvme/doc/config-schema.json" libnvme/doc

# nvme-cli
find "${BUILDDIR}/Documentation" -maxdepth 1 \
     \( -name '*.1' -o -name '*.html' \) \
     -exec cp {} Documentation/ \;
