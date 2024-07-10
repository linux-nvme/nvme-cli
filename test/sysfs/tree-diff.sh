#!/bin/bash -e
# SPDX-License-Identifier: LGPL-2.1-or-later

BUILD_DIR=$1
TREE_DUMP=$2
SYSFS_INPUT=$3
EXPECTED_OUTPUT=$4

TEST_NAME="$(basename -s .tar.xz ${SYSFS_INPUT})"
TEST_DIR="${BUILD_DIR}/${TEST_NAME}"
ACTUAL_OUTPUT="${TEST_DIR}.out"

rm -rf "${TEST_DIR}"
mkdir "${TEST_DIR}"
tar -x -f "${SYSFS_INPUT}" -C "${TEST_DIR}"

LIBNVME_SYSFS_PATH="${TEST_DIR}" \
LIBNVME_HOSTNQN=nqn.2014-08.org.nvmexpress:uuid:ce4fee3e-c02c-11ee-8442-830d068a36c6 \
LIBNVME_HOSTID=ce4fee3e-c02c-11ee-8442-830d068a36c6 \
"${TREE_DUMP}" > "${ACTUAL_OUTPUT}" || echo "test failed"

diff -u "${EXPECTED_OUTPUT}" "${ACTUAL_OUTPUT}"
