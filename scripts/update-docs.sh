#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

cd "$(git rev-parse --show-toplevel)" || exit 1

# build man docs
BUILDDIR="$(mktemp -d)"
echo "${BUILDDIR}"
trap 'rm -rf -- ${BUILDDIR}' EXIT

meson setup 		\
    -Ddocs=man		\
    -Ddocs-build=true	\
    "${BUILDDIR}"
meson compile 		\
    -C "${BUILDDIR}"

rm -rf doc/man
mkdir doc/man

find "${BUILDDIR}/doc" -maxdepth 1 -name '*.2' -exec cp {} doc/man \;

# build ReST docs
rm -rf -- "${BUILDDIR}"
BUILDDIR="$(mktemp -d)"
echo "${BUILDDIR}"
trap 'rm -rf -- ${BUILDDIR}' EXIT

meson setup 		\
    -Ddocs=rst 		\
    -Ddocs-build=true	\
    "${BUILDDIR}"
meson compile 		\
    -C "${BUILDDIR}"

rm -rf doc/rst/*.rst
mkdir -p doc/rst

find "${BUILDDIR}/doc/rst" -maxdepth 1 -name '*.rst' -exec cp {} doc/rst \;

cp "${BUILDDIR}/doc/conf.py" doc
cp "${BUILDDIR}/doc/index.rst" doc
cp "${BUILDDIR}/doc/config-schema.json" doc

# build html docs
# The HTML doc is not ready yet
# rm -rf $DESTDIR/doc/html
# cp -R $BUILDDIR/doc/html $DESTDIR/doc/

