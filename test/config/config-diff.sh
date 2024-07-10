#!/bin/bash -e
# SPDX-License-Identifier: LGPL-2.1-or-later

BUILD_DIR=$1
CONFIG_DUMP=$2
SYSDIR_INPUT=$3
CONFIG_JSON=$4
EXPECTED_OUTPUT=$5

ACTUAL_OUTPUT="${BUILD_DIR}"/$(basename "${EXPECTED_OUTPUT}")

TEST_NAME="$(basename -s .tar.xz $SYSDIR_INPUT)"
TEST_DIR="$BUILD_DIR/$TEST_NAME"

rm -rf "${TEST_DIR}"
mkdir "${TEST_DIR}"
tar -x -f "${SYSDIR_INPUT}" -C "${TEST_DIR}"

LIBNVME_SYSFS_PATH="$TEST_DIR" \
LIBNVME_HOSTNQN=nqn.2014-08.org.nvmexpress:uuid:ce4fee3e-c02c-11ee-8442-830d068a36c6 \
LIBNVME_HOSTID=ce4fee3e-c02c-11ee-8442-830d068a36c6 \
"${CONFIG_DUMP}" "${CONFIG_JSON}" > "${ACTUAL_OUTPUT}" || echo "test failed"

diff -u "${EXPECTED_OUTPUT}" "${ACTUAL_OUTPUT}"
