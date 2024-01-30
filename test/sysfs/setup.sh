#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

TARFILE=$1
BASEDIR=$2
TESTDIR="$BASEDIR/$(basename -s .tar.xz ${TARFILE})"

mkdir -p "${TESTDIR}"
tar -x -f "${TARFILE}" -C "${TESTDIR}" || exit 1

echo "${TESTDIR}"
