#!/bin/sh

BUILDDIR="$(mktemp -d)"
trap 'rm -rf -- $BUILDDIR' EXIT

meson $BUILDDIR -Ddocs=all
ninja -C $BUILDDIR
find $BUILDDIR/Documentation -maxdepth 1 \
     \( -name '*.1' -o -name '*.html' \) \
     -exec cp {} Documentation/ \;
