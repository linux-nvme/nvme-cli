#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
#
# Manual, root-required integration test for nvme-keysd. Runs the unit as
# built, with its hardening, loads a PSK from an encrypted systemd
# credential, and connects to an nvmet-tcp target over TLS on loopback
# with the key that nvme-keysd put in the .nvme keyring.
#
# Not part of `meson test`: needs root, systemd-creds, tlshd (ktls-utils)
# and real kernel modules (nvmet, nvmet-tcp, nvme-tcp, tls). Invoke
# directly, after building with -Dnvme-keysd=enabled:
#
#   sudo [TLSHD=/path/to/tlshd] "$0" [-y]
#
# It asks for confirmation first. -y skips the question.
#
# tlshd.service is used if it is installed. Otherwise the test runs a
# tlshd binary as a transient unit: TLSHD, or tlshd in PATH.
#
# On loopback, the host and the target share the .nvme keyring, so one key
# serves both ends of the connection.

set -u

if [ "$(id -u)" -ne 0 ]; then
	echo "This script must be run as root." >&2
	exit 1
fi

ASSUME_YES=false
if [ "${1:-}" = "-y" ]; then
	ASSUME_YES=true
	shift
fi

for tool in systemctl systemd-run systemd-creds modprobe; do
	if ! command -v "${tool}" >/dev/null 2>&1; then
		echo "Missing required tool: ${tool}" >&2
		exit 1
	fi
done

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# Override to run against another build, e.g. a sanitizer-enabled one.
BUILD_DIR="${BUILD_DIR:-${REPO_ROOT}/.build}"
KEYSD_BIN="${BUILD_DIR}/keysd/nvme-keysd"
KEYSD_UNIT_FILE="${BUILD_DIR}/keysd/nvme-keysd.service"
LIBNVME_SO="${BUILD_DIR}/libnvme/src/libnvme3.so.1"
NVME_BIN="${BUILD_DIR}/nvme"

if [ ! -x "${KEYSD_BIN}" ]; then
	cat >&2 <<EOF
${KEYSD_BIN} not found. Build first:
  meson setup ${BUILD_DIR} -Dnvme-keysd=enabled
  meson compile -C ${BUILD_DIR}
EOF
	exit 1
fi

TLSHD_UNIT=tlshd.service
TLSHD_WAS_ACTIVE=false
if ! err=$(systemctl cat "${TLSHD_UNIT}" 2>&1 >/dev/null); then
	echo "${TLSHD_UNIT}: ${err}"
	TLSHD="${TLSHD:-$(command -v tlshd)}"
	if [ ! -x "${TLSHD}" ]; then
		echo "No tlshd binary: set TLSHD to a tlshd binary" >&2
		exit 1
	fi
	echo "Using ${TLSHD}"
	TLSHD_UNIT=keysd-wringer-tlshd.service
fi

# The build is copied here, because the unit's ProtectHome= hides a build
# under /home. The layout keeps the binary's RUNPATH ($ORIGIN/../libnvme/src).
WORK_DIR=/run/keysd-wringer
FABRICS_CONF="${WORK_DIR}/nvme-fabrics.conf"
CRED_DIR="${WORK_DIR}/creds"
CRED_NAME=keysd-wringer-vol1
CRED_FILE="${CRED_DIR}/${CRED_NAME}"
UNIT=keysd-wringer.service
UNIT_FILE="/run/systemd/system/${UNIT}"

HOSTID=c3d4e5f6-0000-4000-8000-000000000003
HOSTNQN="nqn.2014-08.org.nvmexpress:uuid:${HOSTID}"
SUBSYS_NQN=nqn.2026-09.org.nvmexpress.keysd-wringer:vol1
TRADDR=127.0.0.1
TRSVCID=4430
PORT_ID=30

# Test-only PSKs, never used anywhere else.
KEY_A='NVMeTLSkey-1:01:FJeRbUOvWkhSbfjCKeQYjPqtZpGO+OthuIsXjWIItWlnUfzl:'
KEY_B='NVMeTLSkey-1:01:yyMDXyYiAi6eDt01wprARTn+XEhk9DQgFweyGFLfvJfSuD3o:'

confirm() {
	cat <<EOF
This test changes the state of this machine:
  - It installs and runs ${UNIT} from ${BUILD_DIR}.
  - It adds and revokes TLS PSKs for ${HOSTNQN}
    in the .nvme keyring.
  - It creates an nvmet-tcp subsystem and a TLS port on ${TRADDR}:${TRSVCID}.
  - It starts ${TLSHD_UNIT}.
Run it on a test machine only.
EOF

	if [ "${ASSUME_YES}" = true ]; then
		return
	fi
	if [ ! -t 0 ]; then
		echo "stdin is not a terminal: use -y to continue" >&2
		exit 1
	fi

	local answer
	read -r -p "Continue? [y/N] " answer
	if [ "${answer}" != y ] && [ "${answer}" != Y ]; then
		exit 1
	fi
}

confirm

BACKING_FILE=$(mktemp /tmp/keysd-wringer-ns.XXXXXX)
SCRATCH=$(mktemp /tmp/keysd-wringer-out.XXXXXX)

CYAN="\033[1;36m"
RED="\033[1;31m"
NORMAL="\033[0m"
PASS=0
FAIL=0
PHASE=0

log() {
	printf "%b%s%b\n" "${CYAN}" "$1" "${NORMAL}"
}

pass() {
	printf "  PASS: %s\n" "$1"
	PASS=$((PASS + 1))
}

fail() {
	printf "%b  FAIL: %s%b\n" "${RED}" "$1" "${NORMAL}"
	FAIL=$((FAIL + 1))
}

check() {
	local desc="$1"

	shift
	if "$@"; then
		pass "${desc}"
	else
		fail "${desc}"
	fi
}

# Start the next phase, numbered in order. Under GitHub Actions, each phase
# is a collapsible group in the log.
phase() {
	PHASE=$((PHASE + 1))
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		[ "${PHASE}" -gt 1 ] && echo "::endgroup::"
		echo "::group::Phase ${PHASE}: $1"
	fi
	log ">>>>> Phase ${PHASE}: $1 <<<<<"
}

# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

# The identity that nvme connect derives for PSK $1.
identity_of() {
	"${NVME_BIN}" keys check-tls-psk --hostnqn="${HOSTNQN}" \
		--subsysnqn="${SUBSYS_NQN}" --keydata="$1" --identity=1 \
		2>/dev/null | tail -n 1
}

# The serial, in hex, of the valid psk key with identity $1. A revoked (R)
# or dead (D) key is not valid.
key_serial() {
	awk -v id="$1" '$8 == "psk" {
		desc = $0
		sub(/^([^ ]+ +){8}/, "", desc)
		sub(/: [0-9]+$/, "", desc)
		if (desc == id && $2 !~ /[RD]/)
			print $1
	}' /proc/keys
}

key_present() {
	[ -n "$(key_serial "$1")" ]
}

key_absent() {
	! key_present "$1"
}

# Encrypt PSK $2 into credential file $1 under name $3.
write_cred() {
	printf '%s' "$2" | systemd-creds encrypt --name="$3" - "$1"
}

revoke_test_keys() {
	local id

	for id in "${ID_A:-}" "${ID_B:-}"; do
		[ -n "${id}" ] || continue
		"${NVME_BIN}" keys revoke --identity="${id}" >/dev/null 2>&1
	done
}

# ---------------------------------------------------------------------------
# tlshd and the nvmet-tcp target
# ---------------------------------------------------------------------------

tlshd_start() {
	if [ "${TLSHD_UNIT}" = tlshd.service ]; then
		if systemctl is-active --quiet tlshd.service; then
			TLSHD_WAS_ACTIVE=true
		fi
		systemctl start tlshd.service
		return
	fi

	cat > "${WORK_DIR}/tlshd.conf" <<EOF
[authenticate]
keyrings = .nvme
EOF
	systemd-run --unit="${TLSHD_UNIT}" --collect \
		"${TLSHD}" -s -c "${WORK_DIR}/tlshd.conf" >/dev/null
}

tlshd_stop() {
	if [ "${TLSHD_UNIT}" = tlshd.service ]; then
		[ "${TLSHD_WAS_ACTIVE}" = true ] || systemctl stop tlshd.service
		return
	fi
	systemctl stop "${TLSHD_UNIT}" 2>/dev/null
}

nvmet_setup() {
	local subsys_dir="/sys/kernel/config/nvmet/subsystems/${SUBSYS_NQN}"
	local port_dir="/sys/kernel/config/nvmet/ports/${PORT_ID}"

	log "nvmet: TLS port ${TRSVCID} on ${TRADDR} serves ${SUBSYS_NQN}"
	modprobe -a nvmet nvmet-tcp nvme-tcp tls
	truncate -s 64M "${BACKING_FILE}"
	mkdir -p "${subsys_dir}"
	echo 1 > "${subsys_dir}/attr_allow_any_host"
	mkdir -p "${subsys_dir}/namespaces/1"
	echo -n "${BACKING_FILE}" > "${subsys_dir}/namespaces/1/device_path"
	echo 1 > "${subsys_dir}/namespaces/1/enable"

	mkdir -p "${port_dir}"
	echo ipv4 > "${port_dir}/addr_adrfam"
	echo tcp > "${port_dir}/addr_trtype"
	echo "${TRADDR}" > "${port_dir}/addr_traddr"
	echo "${TRSVCID}" > "${port_dir}/addr_trsvcid"
	echo tls1.3 > "${port_dir}/addr_tsas"
	ln -sf "${subsys_dir}" "${port_dir}/subsystems/${SUBSYS_NQN}"
}

nvmet_teardown() {
	local subsys_dir="/sys/kernel/config/nvmet/subsystems/${SUBSYS_NQN}"

	rm -f /sys/kernel/config/nvmet/ports/"${PORT_ID}"/subsystems/*
	rmdir "/sys/kernel/config/nvmet/ports/${PORT_ID}" 2>/dev/null
	if [ -e "${subsys_dir}/namespaces/1/enable" ]; then
		echo 0 > "${subsys_dir}/namespaces/1/enable"
	fi
	rmdir "${subsys_dir}/namespaces/1" 2>/dev/null
	rmdir "${subsys_dir}" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Host connection
# ---------------------------------------------------------------------------

# The nvmeX device connected to the test subsystem, if any.
test_ctrl() {
	local d

	for d in /sys/class/nvme/nvme*; do
		[ -e "${d}/subsysnqn" ] || continue
		if [ "$(cat "${d}/subsysnqn")" = "${SUBSYS_NQN}" ]; then
			basename "${d}"
			return
		fi
	done
}

# Connect through the fabrics configuration, as nvme connect-all does.
connect_from_config() {
	"${NVME_BIN}" connect -J "${FABRICS_CONF}" >"${SCRATCH}" 2>&1
	sleep 1
	[ -n "$(test_ctrl)" ]
}

disconnect() {
	"${NVME_BIN}" disconnect -n "${SUBSYS_NQN}" >/dev/null 2>&1
}

# The key serial, in hex, that the live controller's TLS session uses.
ctrl_key_serial() {
	local dev

	dev=$(test_ctrl)
	[ -n "${dev}" ] || return
	cat "/sys/class/nvme/${dev}/tls_key" 2>/dev/null
}

ctrl_uses_key() {
	local want have

	want=$(key_serial "$1")
	have=$(ctrl_key_serial)
	[ -n "${want}" ] && [ "$((16#${have:-0}))" -eq "$((16#${want}))" ]
}

ctrl_live() {
	local dev

	dev=$(test_ctrl)
	[ -n "${dev}" ] && [ "$(cat "/sys/class/nvme/${dev}/state")" = live ]
}

# ---------------------------------------------------------------------------
# nvme-keysd
# ---------------------------------------------------------------------------

keysd_install() {
	log "Install ${UNIT}"
	mkdir -p "${WORK_DIR}/keysd" "${WORK_DIR}/libnvme/src"
	mkdir -m 0700 -p "${CRED_DIR}"
	cp "${KEYSD_BIN}" "${WORK_DIR}/keysd/"
	cp "${LIBNVME_SO}" "${WORK_DIR}/libnvme/src/"

	write_fabrics_conf systemd-creds

	# The unit as built, with the binary and its arguments replaced. The
	# credentials are in ${CRED_DIR}, so the unit must not create
	# /etc/nvme/creds.
	local exec_start="${WORK_DIR}/keysd/nvme-keysd"

	exec_start+=" --fabrics-config ${FABRICS_CONF}"
	exec_start+=" --creds-dir ${CRED_DIR} --debug"
	local coverage=()

	# A coverage build writes its .gcda files into ${BUILD_DIR}, which
	# the unit's hardening makes inaccessible. ${BUILD_DIR} belongs to
	# the user who built it, so root also needs CAP_DAC_OVERRIDE.
	if compgen -G "${BUILD_DIR}/keysd/nvme-keysd.p/*.gcno" >/dev/null; then
		coverage=(-e "s|^ProtectHome=.*|ProtectHome=read-only|"
			  -e "s|^CapabilityBoundingSet=.*|CapabilityBoundingSet=CAP_DAC_OVERRIDE|"
			  -e "/^ExecStart=/a ReadWritePaths=${BUILD_DIR}")
	fi
	sed -e "s|^ExecStart=.*|ExecStart=${exec_start}|" \
	    -e "s|^ExecCondition=.*|ExecCondition=${exec_start} --should-start|" \
	    -e "/^ConfigurationDirectory/d" \
	    "${coverage[@]}" \
		"${KEYSD_UNIT_FILE}" > "${UNIT_FILE}"
	systemctl daemon-reload
}

# $1: the key source of the subsystem entry, or "inline".
write_fabrics_conf() {
	cat > "${FABRICS_CONF}" <<EOF
[Host]
hostnqn    = ${HOSTNQN}
hostid     = ${HOSTID}
key-source = $1

[Subsystem]
nqn        = ${SUBSYS_NQN}
controller = transport=tcp;traddr=${TRADDR};trsvcid=${TRSVCID}
tls        = true
tls-key    = ${CRED_NAME}
EOF
}

keysd_uninstall() {
	systemctl stop "${UNIT}" 2>/dev/null
	systemctl reset-failed "${UNIT}" 2>/dev/null
	rm -f "${UNIT_FILE}"
	systemctl daemon-reload
}

keysd_restart() {
	systemctl reset-failed "${UNIT}" 2>/dev/null
	systemctl restart "${UNIT}" >"${SCRATCH}" 2>&1
}

# nvme-keysd ran since $1, and exited with status 0.
keysd_ran() {
	unit_journal_has "$1" "Finished ${UNIT}"
}

journal_has() {
	journalctl -t nvme-keysd --since "$1" 2>/dev/null | grep -q -- "$2"
}

# systemd unloads an inactive unit, and "systemctl show" then returns
# default values. The unit's journal keeps what happened.
unit_journal_has() {
	journalctl -u "${UNIT}" --since "$1" 2>/dev/null | grep -q -- "$2"
}

journal_count() {
	journalctl -t nvme-keysd --since "$1" 2>/dev/null | grep -c -- "$2"
}

# ---------------------------------------------------------------------------
# Cleanup: always runs, even on Ctrl-C or an assertion failing partway.
# ---------------------------------------------------------------------------

cleanup() {
	log "Cleanup"
	disconnect
	keysd_uninstall
	revoke_test_keys
	nvmet_teardown
	tlshd_stop
	rm -rf "${WORK_DIR}"
	rm -f "${BACKING_FILE}" "${SCRATCH}"
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

mkdir -p "${WORK_DIR}"
ID_A=$(identity_of "${KEY_A}")
ID_B=$(identity_of "${KEY_B}")
if [ -z "${ID_A}" ] || [ -z "${ID_B}" ]; then
	echo "cannot derive the test identities with ${NVME_BIN}" >&2
	exit 1
fi

# A prior run killed before cleanup() could have left these behind.
disconnect
revoke_test_keys

nvmet_setup
tlshd_start
keysd_install

phase "the unit does not start without a key source"
write_fabrics_conf inline
PHASE_START=$(date '+%Y-%m-%d %H:%M:%S')
keysd_restart
check "the unit is not active" test "$(systemctl is-active "${UNIT}")" = inactive
check "the unit is not failed" \
	test "$(systemctl is-failed "${UNIT}")" != failed
check "ExecCondition= skipped the unit" \
	unit_journal_has "${PHASE_START}" "Skipped due to 'exec-condition'"
check "the check was logged" journal_has "${PHASE_START}" "nothing to do"
write_fabrics_conf systemd-creds

phase "a missing credential is reported"
PHASE_START=$(date '+%Y-%m-%d %H:%M:%S')
keysd_restart
check "nvme-keysd runs without its credential" keysd_ran "${PHASE_START}"
check "the missing credential was logged" \
	journal_has "${PHASE_START}" "cannot decrypt credential '${CRED_NAME}'"

phase "a credential is imported at startup"
write_cred "${CRED_FILE}" "${KEY_A}" "${CRED_NAME}"
PHASE_START=$(date '+%Y-%m-%d %H:%M:%S')
keysd_restart
check "nvme-keysd ran" keysd_ran "${PHASE_START}"
check "key A is in .nvme with the expected identity" key_present "${ID_A}"
check "the import was logged" journal_has "${PHASE_START}" "imported '${ID_A}'"
check "the exit was logged" journal_has "${PHASE_START}" "keys imported, exiting"

phase "a TLS connection finds the key without --tls-key"
check "nvme connect -J connects" connect_from_config
check "the controller is live" ctrl_live
check "the connection uses key A" ctrl_uses_key "${ID_A}"

phase "a restart with nothing changed changes nothing"
SERIAL_A=$(key_serial "${ID_A}")
PHASE_START=$(date '+%Y-%m-%d %H:%M:%S')
keysd_restart
check "nvme-keysd ran" keysd_ran "${PHASE_START}"
check "key A keeps its serial" test "$(key_serial "${ID_A}")" = "${SERIAL_A}"
check "'already present' was logged" \
	journal_has "${PHASE_START}" "'${ID_A}' already present"

phase "a new credential and a restart replace the key"
write_cred "${CRED_FILE}" "${KEY_B}" "${CRED_NAME}"
PHASE_START=$(date '+%Y-%m-%d %H:%M:%S')
keysd_restart
check "nvme-keysd ran" keysd_ran "${PHASE_START}"
check "key B is in .nvme" key_present "${ID_B}"
check "key A is revoked" key_absent "${ID_A}"
check "the revocation was logged" \
	journal_has "${PHASE_START}" "revoked '${ID_A}'"
check "the existing connection stays live" ctrl_live
disconnect
check "a new connection succeeds" connect_from_config
check "the new connection uses key B" ctrl_uses_key "${ID_B}"
disconnect

phase "the keys outlive nvme-keysd"
check "the unit is not active" test "$(systemctl is-active "${UNIT}")" = inactive
# The key garbage collector runs asynchronously.
sleep 2
check "key B is still in .nvme" key_present "${ID_B}"
check "a new connection succeeds" connect_from_config
check "the new connection uses key B" ctrl_uses_key "${ID_B}"
disconnect

phase "a credential with the wrong name is rejected"
write_cred "${CRED_FILE}" "${KEY_A}" wrong-name
PHASE_START=$(date '+%Y-%m-%d %H:%M:%S')
keysd_restart
check "nvme-keysd ran" keysd_ran "${PHASE_START}"
check "the name mismatch was logged" \
	journal_has "${PHASE_START}" "io.systemd.Credentials.NameMismatch"
check "key B is still in .nvme" key_present "${ID_B}"
check "key A is not imported" key_absent "${ID_A}"

phase "every path of a subsystem imports the key once"
write_cred "${CRED_FILE}" "${KEY_B}" "${CRED_NAME}"
sed -i "/^controller/a controller = transport=tcp;traddr=${TRADDR};trsvcid=$((TRSVCID + 1))" \
	"${FABRICS_CONF}"
PHASE_START=$(date '+%Y-%m-%d %H:%M:%S')
keysd_restart
check "nvme-keysd ran" keysd_ran "${PHASE_START}"
check "'already present' was logged once" \
	test "$(journal_count "${PHASE_START}" "'${ID_B}' already present")" -eq 1

# A drop-in without [Host] uses the system host NQN. Every entry fails
# before a key is inserted, so the keyring of the real host is untouched.
phase "entries that cannot be imported are skipped"
DROPIN_DIR="${FABRICS_CONF}.d"
DROPIN="${DROPIN_DIR}/errors.conf"
NQN_BASE=nqn.2026-09.org.nvmexpress.keysd-wringer
mkdir -p "${DROPIN_DIR}"
write_cred "${CRED_DIR}/keysd-wringer-notpsk" "not-a-psk" keysd-wringer-notpsk
write_cred "${CRED_DIR}/keysd-wringer-big" "$(printf '%0200d' 0)" \
	keysd-wringer-big
write_cred "${CRED_DIR}/keysd-wringer-keyring" "${KEY_A}" \
	keysd-wringer-keyring
{
	entry() {
		printf '[Subsystem]\nnqn        = %s:%s\n' "${NQN_BASE}" "$1"
		printf 'controller = transport=tcp;traddr=%s;trsvcid=%s\n' \
			"${TRADDR}" "${TRSVCID}"
		shift
		printf '%s\n' "$@" ""
	}
	entry inline "key-source = inline" "tls-key = ${KEY_A}"
	entry kmip "key-source = kmip" "tls-key = ${CRED_NAME}"
	entry notlskey "key-source = systemd-creds"
	entry badname "key-source = systemd-creds" "tls-key = ../x"
	entry notpsk "key-source = systemd-creds" \
		"tls-key = keysd-wringer-notpsk"
	entry big "key-source = systemd-creds" "tls-key = keysd-wringer-big"
	entry keyring "key-source = systemd-creds" \
		"tls-key = keysd-wringer-keyring" \
		"keyring = keysd-wringer-nosuch"
} > "${DROPIN}"
PHASE_START=$(date '+%Y-%m-%d %H:%M:%S')
keysd_restart
check "nvme-keysd ran" keysd_ran "${PHASE_START}"
check "the inline entry is ignored" \
	test "$(journal_count "${PHASE_START}" "${NQN_BASE}:inline")" -eq 0
check "an unsupported key-source was logged" \
	journal_has "${PHASE_START}" "key-source 'kmip' is not supported"
check "a missing tls-key was logged" \
	journal_has "${PHASE_START}" "${NQN_BASE}:notlskey: key-source is systemd-creds but tls-key is not set"
check "an invalid credential name was logged" \
	journal_has "${PHASE_START}" "invalid credential name '../x'"
check "a credential that is not a PSK was logged" \
	journal_has "${PHASE_START}" "credential 'keysd-wringer-notpsk' is not a valid PSK"
check "a credential that is too large was logged" \
	journal_has "${PHASE_START}" "cannot decrypt credential 'keysd-wringer-big': File too large"
check "a missing keyring was logged" \
	journal_has "${PHASE_START}" "keyring 'keysd-wringer-nosuch' not available"
check "key B is still in .nvme" key_present "${ID_B}"
check "the main file is still imported" \
	journal_has "${PHASE_START}" "'${ID_B}' already present"

phase "a fabrics configuration that does not parse is reported"
printf '[Subsystem]\nnqn = not-an-nqn\n' > "${DROPIN}"
PHASE_START=$(date '+%Y-%m-%d %H:%M:%S')
keysd_restart
check "the unit is skipped" \
	unit_journal_has "${PHASE_START}" "Skipped due to 'exec-condition'"
check "the read failure was logged" \
	journal_has "${PHASE_START}" "cannot read the fabrics configuration"
check "key B is still in .nvme" key_present "${ID_B}"

if [ -n "${GITHUB_ACTIONS:-}" ] && [ "${PHASE}" -gt 0 ]; then
	echo "::endgroup::"
fi
printf "\n"
log "Results: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
