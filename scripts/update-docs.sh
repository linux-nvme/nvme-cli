#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later

cd "$(git rev-parse --show-toplevel)" || exit 1

BUILDDIR="$(mktemp -d)"
CHECKDIR="$(mktemp -d)"
trap 'rm -rf -- $BUILDDIR $CHECKDIR' EXIT

# Some man pages are only listed when their option is enabled. Enable them
# here so the build and the check below both see every page.
doc_setup() {
	meson setup                             \
		-Dnvme=enabled                      \
		-Dlibnvme=enabled                   \
		-Dnvme-discoverd=enabled            \
		-Ddocs=all                          \
		"$@"
}

doc_setup -Ddocs-build=true "${BUILDDIR}"
# TODO add 'docs' target
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
     \( -name '*.[0-9]' -o -name '*.html' \) \
     -exec cp {} Documentation/ \;

# Fail if a pre-built doc file is missing.
if ! doc_setup -Ddocs-build=false "${CHECKDIR}"; then
	echo "update-docs.sh: a pre-built doc file is missing" >&2
	exit 1
fi
