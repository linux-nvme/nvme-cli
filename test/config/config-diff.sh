#!/bin/bash -e
# SPDX-License-Identifier: LGPL-2.1-or-later

positional_args=()
sysfs_tar=""
config_json=""

while [[ $# -gt 0 ]]; do
    case $1 in
	--sysfs-tar)
	    sysfs_tar=$2
	    shift 1
	    ;;
	--config-json)
	    config_json=$2
	    shift 1
	    ;;
    *)
        positional_args+=("$1")
        shift
        ;;
    esac
done

set -- "${positional_args[@]}"

test_binary="$1"
build_dir="$2"
expected_output="$3"

sysfs_path=""
if [[ -n "${sysfs_tar}" ]]; then
   test_name="$(basename -s .tar.xz ${sysfs_tar})"
   sysfs_path="${build_dir}/${test_name}"

   rm -rf "${sysfs_path}"
   mkdir "${sysfs_path}"
   tar -x -f "${sysfs_tar}" -C "${sysfs_path}"
fi

output="${build_dir}"/$(basename "${expected_output}")

LIBNVME_SYSFS_PATH="${sysfs_path}" \
LIBNVME_HOSTNQN=nqn.2014-08.org.nvmexpress:uuid:ce4fee3e-c02c-11ee-8442-830d068a36c6 \
LIBNVME_HOSTID=ce4fee3e-c02c-11ee-8442-830d068a36c6 \
"${test_binary}" "${config_json}" > "${output}" || echo "test failed"

diff -u "${expected_output}" "${output}"
