#!/bin/bash -e
# SPDX-License-Identifier: LGPL-2.1-or-later

positional_args=()
sysfs_tar=""
config_json=""

while [[ $# -gt 0 ]]; do
	case "$1" in
	--sysfs-tar)
		sysfs_tar=$2
		shift 2
		;;
	--config-json)
		config_json=$2
		shift 2
		;;
	*)
		positional_args+=("$1")
		shift
		;;
	esac
done

set -- "${positional_args[@]}"

if [[ $# -lt 3 ]]; then
	echo "usage: $0 [--sysfs-tar file] [--config-json file] <test-binary> <build-dir> <expected-output>"
	exit 1
fi

test_binary="$1"
build_dir="$2"
expected_output="$3"

sysfs_path=""
if [[ -n "${sysfs_tar}" ]]; then
	test_name="$(basename -s .tar.xz "${sysfs_tar}")"
	sysfs_path="${build_dir}/${test_name}"

	rm -rf "${sysfs_path}"
	mkdir -p "${sysfs_path}"
	tar -x -f "${sysfs_tar}" -C "${sysfs_path}"
fi

output="${build_dir}/$(basename "${expected_output}")"

DEFAULT_HOSTUUID="ce4fee3e-c02c-11ee-8442-830d068a36c6"
AUX_HOSTUUID="2cd2c43b-a90a-45c1-a8cd-86b33ab273b5"

hosts=(
	"$DEFAULT_HOSTUUID"
	"$AUX_HOSTUUID"
	"$DEFAULT_HOSTUUID"
)

set_options=""
for i in "${!hosts[@]}"; do
	nqn="nqn.2014-08.org.nvmexpress:uuid:${hosts[$i]}"

	if [ -n "$set_options" ]; then
		set_options+=","
	fi

	set_options+="hostnqn_$((i + 1))=${nqn},hostid_$((i + 1))=${hosts[$i]}"
done

cmd=(
	"$test_binary"
	--set-options "$set_options"
)

if [[ -n "${sysfs_path}" ]]; then
	cmd+=(--set-options "test-sysfs-dir=${sysfs_path}")
fi

if [[ -n "${config_json}" ]]; then
	cmd+=("${config_json}")
fi

echo "Running command:"
printf '%q ' "${cmd[@]}"
printf '> %q\n' "$output"

if "${cmd[@]}" > "$output"; then
	:
else
	rc=$?
	echo "test failed (exit code $rc)"
	exit "$rc"
fi

diff -u "${expected_output}" "${output}"
