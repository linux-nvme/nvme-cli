#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

DESTDIR=$(pwd)

# build man docs
BUILDDIR="$(mktemp -d)"
echo $BUILDDIR
trap 'rm -rf -- $BUILDDIR' EXIT

meson $BUILDDIR -Ddocs=man -Ddocs-build=true
ninja -C $BUILDDIR

rm -rf $DESTDIR/doc/man
mkdir $DESTDIR/doc/man

find $BUILDDIR/doc -maxdepth 1 -name '*.2' -exec cp {} $DESTDIR/doc/man \;

# build ReST docs
rm -rf -- $BUILDDIR
BUILDDIR="$(mktemp -d)"
echo $BUILDDIR
trap 'rm -rf -- $BUILDDIR' EXIT

meson $BUILDDIR -Ddocs=rst -Ddocs-build=true
ninja -C $BUILDDIR

rm -rf $DESTDIR/doc/rst/*.rst
mkdir -p $DESTDIR/doc/rst

find $BUILDDIR/doc/rst -maxdepth 1 -name '*.rst' -exec cp {} $DESTDIR/doc/rst \;

cp $BUILDDIR/doc/conf.py $DESTDIR/doc
cp $BUILDDIR/doc/index.rst $DESTDIR/doc
cp $BUILDDIR/doc/config-schema.json $DESTDIR/doc

# build html docs
# The HTML doc is not ready yet
# rm -rf $DESTDIR/doc/html
# cp -R $BUILDDIR/doc/html $DESTDIR/doc/

