#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copy the generated docs into the source tree. Run by the update-docs
# meson target.

set -e

src="${MESON_SOURCE_ROOT}"
build="${MESON_BUILD_ROOT}"

# libnvme
rm -rf "${src}/libnvme/doc/man"
mkdir "${src}/libnvme/doc/man"
find "${build}/libnvme/doc" -maxdepth 1 \
	-name '*.2' -exec cp {} "${src}/libnvme/doc/man" \;

rm -f "${src}"/libnvme/doc/rst/*.rst
find "${build}/libnvme/doc/rst" -maxdepth 1 \
	-name '*.rst' -exec cp {} "${src}/libnvme/doc/rst" \;

for f in conf.py index.rst api.rst quickstart.rst installation.rst mi.rst; do
	cp "${build}/libnvme/doc/${f}" "${src}/libnvme/doc"
done

# nvme-cli
find "${build}/Documentation" -maxdepth 1 \
	\( -name '*.[0-9]' -o -name '*.html' \) \
	-exec cp {} "${src}/Documentation" \;
