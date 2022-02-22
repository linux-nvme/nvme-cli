#!/bin/sh -x

DESTDIR=$(pwd)

BUILDDIR="$(mktemp -d)"
trap 'rm -rf -- $BUILDDIR' EXIT

meson $BUILDDIR -Ddocs=man -Ddocs-build=true
ninja -C $BUILDDIR

rm -rf $DESTDIR/doc/man
mkdir $DESTDIR/doc/man

find $BUILDDIR/doc -maxdepth 1 -name '*.2' -exec cp {} $DESTDIR/doc/man \;

# The HTML doc is not ready yet
# rm -rf $DESTDIR/doc/html
# cp -R $BUILDDIR/doc/html $DESTDIR/doc/

