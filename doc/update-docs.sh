#!/bin/sh -x

DESTDIR=$(pwd)

BUILDDIR="$(mktemp -d)"
trap 'rm -rf -- $BUILDDIR' EXIT

meson $BUILDDIR -Ddocs=all -Ddocs-build=true
ninja -C $BUILDDIR

rm -rf $DESTDIR/doc/man
rm -rf $DESTDIR/doc/html
mkdir $DESTDIR/doc/man

cp -R $BUILDDIR/doc/html $DESTDIR/doc/
find $BUILDDIR/doc -maxdepth 1 -name '*.2' -exec cp {} $DESTDIR/doc/man \;

