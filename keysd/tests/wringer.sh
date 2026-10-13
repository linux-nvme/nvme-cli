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
#   sudo [TLSHD=/path/to/tlshd] [PYKMIP_PYTHON=/path/to/python] "$0" [-y]
#
# It asks for confirmation first. -y skips the question.
#
# tlshd.service is used if it is installed. Otherwise the test runs a
# tlshd binary as a transient unit: TLSHD, or tlshd in PATH.
#
# When nvme-keysd-kmip is built (-Dkmip), the KMIP phases run against a
# PyKMIP server on loopback. PYKMIP_PYTHON is a Python interpreter that
# can import PyKMIP (default: python3).
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
NQN_BASE=nqn.2026-09.org.nvmexpress.keysd-wringer

# KMIP
KMIP_BIN="${BUILD_DIR}/keysd/nvme-keysd-kmip"
KMIP_SOCKET_FILE="${BUILD_DIR}/keysd/nvme-keysd-kmip.socket"
KMIP_SERVICE_FILE="${BUILD_DIR}/keysd/nvme-keysd-kmip@.service"
KMIP_UNIT=keysd-wringer-kmip
KMIP_SOCKET="${WORK_DIR}/kmip.sock"
KMIP_DIR="${WORK_DIR}/kmip"
KMIP_GCOV_DIR="${WORK_DIR}/gcov"
KEYSD_CONF="${WORK_DIR}/nvme-keysd.conf"
PYKMIP_PYTHON="${PYKMIP_PYTHON:-python3}"
PYKMIP_KMS="${REPO_ROOT}/keysd/tests/pykmip-kms.py"
KMS_UNIT=keysd-wringer-pykmip.service
KMS_PORT=5697
VARLINK_IF=io.nvme.keysd.Kmip

# Test-only raw keys for the Symmetric Key phases.
HEX_32=$(printf '%02x' $(seq 0 31))
HEX_48=$(printf '%02x' $(seq 32 79))

KMIP=false
if [ -x "${KMIP_BIN}" ]; then
	KMIP=true
	for tool in openssl setpriv ss varlinkctl; do
		if ! command -v "${tool}" >/dev/null 2>&1; then
			echo "Missing required tool for KMIP: ${tool}" >&2
			exit 1
		fi
	done
	if ! "${PYKMIP_PYTHON}" -c 'import kmip' 2>/dev/null; then
		cat >&2 <<EOF
${KMIP_BIN} is built: its phases need PyKMIP. For example:
  python3 -m venv /opt/pykmip
  /opt/pykmip/bin/pip install pykmip
and run with PYKMIP_PYTHON=/opt/pykmip/bin/python.
EOF
		exit 1
	fi
fi

confirm() {
	cat <<EOF
This test changes the state of this machine:
  - It installs and runs ${UNIT} from ${BUILD_DIR}.
  - It adds and revokes TLS PSKs for ${HOSTNQN}
    in the .nvme keyring.
  - It creates an nvmet-tcp subsystem and a TLS port on ${TRADDR}:${TRSVCID}.
  - It starts ${TLSHD_UNIT}.
EOF
	if [ "${KMIP}" = true ]; then
		cat <<EOF
  - It runs ${KMIP_UNIT}.socket and a PyKMIP server on ${TRADDR}:${KMS_PORT}.
EOF
	fi
	cat <<EOF
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

# The time, in microseconds: a phase must not see the messages of the
# previous one.
now() {
	date '+%Y-%m-%d %H:%M:%S.%6N'
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

# The identity that nvme connect derives for PSK $1, and subsystem $2
# (default: the test subsystem).
identity_of() {
	"${NVME_BIN}" keys check-tls-psk --hostnqn="${HOSTNQN}" \
		--subsysnqn="${2:-${SUBSYS_NQN}}" --keydata="$1" --identity=1 \
		2>/dev/null | tail -n 1
}

# The PSK interchange string of the raw key $1 (hex), for hash $2
# (1: SHA-256, 2: SHA-384).
psk_of() {
	"${NVME_BIN}" keys gen-tls-psk --secret="$1" --hmac="$2" \
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

revoke_key() {
	"${NVME_BIN}" keys revoke --identity="$1" >/dev/null 2>&1
}

revoke_test_keys() {
	local id

	for id in "${ID_A:-}" "${ID_B:-}" "${ID_B2:-}" "${ID_S32:-}" \
		  "${ID_S48:-}"; do
		[ -n "${id}" ] || continue
		revoke_key "${id}"
	done
}

# Run "$@" until it succeeds, for at most $1 seconds.
wait_until() {
	local i

	for i in $(seq $(($1 * 2))); do
		"${@:2}" && return 0
		sleep 0.5
	done

	"${@:2}"
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
	: > "${KEYSD_CONF}"

	# The unit as built, with the binary and its arguments replaced. The
	# credentials are in ${CRED_DIR}, so the unit must not create
	# /etc/nvme/creds.
	local exec_start="${WORK_DIR}/keysd/nvme-keysd"

	exec_start+=" --fabrics-config ${FABRICS_CONF}"
	exec_start+=" --creds-dir ${CRED_DIR} --config ${KEYSD_CONF}"
	exec_start+=" --kmip-test-addr ${KMIP_SOCKET} --debug"
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
	    -e "s|nvme-keysd-kmip.socket|${KMIP_UNIT}.socket|" \
	    "${coverage[@]}" \
		"${KEYSD_UNIT_FILE}" > "${UNIT_FILE}"
	systemctl daemon-reload
}

# $1: the key source of the subsystem entry, or "inline". $2: its tls-key
# (default: ${CRED_NAME}).
write_fabrics_conf() {
	cat > "${FABRICS_CONF}" <<EOF
[Host]
hostnqn    = ${HOSTNQN}
hostid     = ${HOSTID}
tls-key-source = $1

[Subsystem]
nqn        = ${SUBSYS_NQN}
controller = transport=tcp;traddr=${TRADDR};trsvcid=${TRSVCID}
tls        = true
tls-key    = ${2:-${CRED_NAME}}
EOF
}

# A [Subsystem] entry for ${NQN_BASE}:$1, with the lines "${@:2}".
subsys_entry() {
	printf '[Subsystem]\nnqn        = %s:%s\n' "${NQN_BASE}" "$1"
	printf 'controller = transport=tcp;traddr=%s;trsvcid=%s\n' \
		"${TRADDR}" "${TRSVCID}"
	shift
	printf '%s\n' "$@" ""
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

# nvme-keysd ran since $1, and exited with status 0. With Type=notify,
# systemctl returns at READY=1, before the exit: wait for it.
keysd_ran() {
	wait_until 10 journal_match -u "${UNIT}" "$1" "Deactivated successfully"
}

# The journal has, for the selector $1 $2, a message since $3 that
# contains $4.
journal_match() {
	journalctl "$1" "$2" --since "$3" 2>/dev/null | grep -q -- "$4"
}

# journald stores a message some time after it is sent: the *_has checks
# wait for it.
journal_has() {
	wait_until 5 journal_match -t nvme-keysd "$1" "$2"
}

# systemd unloads an inactive unit, and "systemctl show" then returns
# default values. The unit's journal keeps what happened.
unit_journal_has() {
	wait_until 5 journal_match -u "${UNIT}" "$1" "$2"
}

journal_count() {
	journalctl -t nvme-keysd --since "$1" 2>/dev/null | grep -c -- "$2"
}

keysd_active() {
	test "$(systemctl is-active "${UNIT}")" = active
}

# The STATUS= that nvme-keysd last sent to systemd is $1.
keysd_status_is() {
	test "$(systemctl show -p StatusText --value "${UNIT}")" = "$1"
}

keysd_main_pid() {
	systemctl show -p MainPID --value "${UNIT}"
}

# nvme-keysd runs, with a main PID other than $1.
keysd_restarted_after() {
	local pid

	pid=$(keysd_main_pid)
	[ "${pid}" != 0 ] && [ "${pid}" != "$1" ]
}

# ---------------------------------------------------------------------------
# KMIP: nvme-keysd-kmip and the PyKMIP server
# ---------------------------------------------------------------------------

kmip_install() {
	local unit_dir=/run/systemd/system

	log "Install ${KMIP_UNIT}.socket"
	cp "${KMIP_BIN}" "${WORK_DIR}/keysd/"
	mkdir -m 0700 -p "${CRED_DIR}/kmip"

	local exec_start="${WORK_DIR}/keysd/nvme-keysd-kmip"

	exec_start+=" --config ${KEYSD_CONF} --debug"
	local coverage=()

	# The helper's dynamic user cannot write into ${BUILD_DIR}. Its
	# coverage counters go to ${KMIP_GCOV_DIR}, and cleanup copies them
	# back. All instances share one user, so they can update the same
	# counter files.
	if compgen -G "${BUILD_DIR}/keysd/nvme-keysd-kmip.p/*.gcno" >/dev/null; then
		mkdir -m 1777 -p "${KMIP_GCOV_DIR}"
		coverage=(-e "/^ExecStart=/a Environment=GCOV_PREFIX=${KMIP_GCOV_DIR}"
			  -e "/^ExecStart=/a ReadWritePaths=${KMIP_GCOV_DIR}"
			  -e "/^ExecStart=/a User=${KMIP_UNIT}"
			  -e "s|^UMask=.*|UMask=0022|")
	fi
	sed -e "s|^ExecStart=.*|ExecStart=${exec_start}|" \
	    -e "s|^LoadCredentialEncrypted=kmip:.*|LoadCredentialEncrypted=kmip:${CRED_DIR}/kmip|" \
	    "${coverage[@]}" \
		"${KMIP_SERVICE_FILE}" > "${unit_dir}/${KMIP_UNIT}@.service"
	sed -e "s|^ListenStream=.*|ListenStream=${KMIP_SOCKET}|" \
		"${KMIP_SOCKET_FILE}" > "${unit_dir}/${KMIP_UNIT}.socket"
	systemctl daemon-reload
	systemctl start "${KMIP_UNIT}.socket"
}

kmip_uninstall() {
	local src="${KMIP_GCOV_DIR}${BUILD_DIR}/keysd/nvme-keysd-kmip.p"

	systemctl stop "${KMIP_UNIT}.socket" "${KMIP_UNIT}@*.service" \
		2>/dev/null
	rm -f "/run/systemd/system/${KMIP_UNIT}.socket" \
	      "/run/systemd/system/${KMIP_UNIT}@.service"
	systemctl daemon-reload
	if compgen -G "${src}/*.gcda" >/dev/null; then
		cp "${src}"/*.gcda "${BUILD_DIR}/keysd/nvme-keysd-kmip.p/"
	fi
}

# Certificate $1 (.pem and .key), signed by CA $2, with the X.509 v3
# extensions $3.
kmip_cert() {
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-keyout "$1.key" -out "$1.csr" -subj "/CN=keysd-wringer-$1" \
		2>/dev/null &&
	openssl x509 -req -in "$1.csr" -CA "$2.pem" -CAkey "$2.key" \
		-CAcreateserial -out "$1.pem" -days 1 \
		-extfile <(printf '%s\n' "$3") 2>/dev/null
}

kmip_ca() {
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-keyout "$1.key" -out "$1.pem" -days 1 \
		-subj "/CN=keysd-wringer-$1" 2>/dev/null
}

# A CA, a server and a client certificate for the KMS, and a second CA
# that signed nothing. The certificates must be readable by the helper.
kms_setup() {
	log "PyKMIP: KMS on ${TRADDR}:${KMS_PORT}"
	mkdir -p "${KMIP_DIR}/policies"
	(
		cd "${KMIP_DIR}" || exit 1
		kmip_ca ca && kmip_ca other-ca &&
		kmip_cert server ca "subjectAltName=IP:${TRADDR}" &&
		kmip_cert client ca "extendedKeyUsage=clientAuth"
	) || { echo "cannot create the KMIP certificates" >&2; exit 1; }
	chmod 0644 "${KMIP_DIR}"/*.pem
	systemd-creds encrypt --name=kmip_client "${KMIP_DIR}/client.key" \
		"${CRED_DIR}/kmip/client"

	cat > "${KMIP_DIR}/server.conf" <<EOF
[server]
hostname=${TRADDR}
port=${KMS_PORT}
certificate_path=${KMIP_DIR}/server.pem
key_path=${KMIP_DIR}/server.key
ca_path=${KMIP_DIR}/ca.pem
auth_suite=TLS1.2
policy_path=${KMIP_DIR}/policies
enable_tls_client_auth=True
database_path=${KMIP_DIR}/pykmip.db
EOF
	kms_start || { echo "PyKMIP does not start" >&2; exit 1; }
}

kms_listening() {
	ss -Hltn "sport = :${KMS_PORT}" | grep -q .
}

kms_start() {
	systemd-run --unit="${KMS_UNIT}" --collect -p WorkingDirectory=/ \
		"${PYKMIP_PYTHON}" -I "${PYKMIP_KMS}" serve \
		"${KMIP_DIR}/server.conf" "${KMIP_DIR}/server.log" >/dev/null
	wait_until 20 kms_listening
}

kms_stop() {
	systemctl stop "${KMS_UNIT}" 2>/dev/null
}

# Manage the keys on the KMS. PyKMIP's own messages go to client.log.
kms() {
	"${PYKMIP_PYTHON}" -I "${PYKMIP_KMS}" --dir "${KMIP_DIR}" \
		--port "${KMS_PORT}" "$@" 2>>"${KMIP_DIR}/client.log"
}

# $1: the CA file. The other arguments: the servers.
write_keysd_conf() {
	local ca=$1 server

	shift
	{
		echo "[kmip:wringer]"
		for server in "$@"; do
			echo "server      = ${server}"
		done
		cat <<EOF
port        = ${KMS_PORT}
ca          = ${ca}
client-cert = ${KMIP_DIR}/client.pem
client-key  = client
EOF
	} > "${KEYSD_CONF}"
}

helper_journal_has() {
	wait_until 5 journal_match -t nvme-keysd-kmip "$1" "$2"
}

helper_journal_count() {
	journalctl -t nvme-keysd-kmip --since "$1" 2>/dev/null |
		grep -c -- "$2"
}

# The helper logged since $1, and never as root.
helper_not_root() {
	local uids

	uids=$(journalctl -t nvme-keysd-kmip --since "$1" -o export \
		2>/dev/null | sed -n 's/^_UID=//p' | sort -u)
	[ -n "${uids}" ] && ! grep -qx 0 <<< "${uids}"
}

# nvme-keysd logged that key $1 failed with Varlink error $2, and the retry
# delay $3.
kmip_failed() {
	journal_match -t nvme-keysd "${PHASE_START}" \
		"KMS 'wringer', key '$1': ${VARLINK_IF}.$2, retry in $3 s"
}

# Call the helper directly, as user $1, with the parameters $2.
helper_call() {
	setpriv --reuid="$1" --regid="$1" --clear-groups \
		varlinkctl call "unix:${KMIP_SOCKET}" "${VARLINK_IF}.GetKey" "$2" \
		>"${SCRATCH}" 2>&1
}

# The socket is root's only: "nobody" cannot connect.
helper_refuses_nobody() {
	! helper_call 65534 '{"kms":"wringer","name":"x"}' &&
		grep -q "Permission denied" "${SCRATCH}"
}

# ---------------------------------------------------------------------------
# Cleanup: always runs, even on Ctrl-C or an assertion failing partway.
# ---------------------------------------------------------------------------

cleanup() {
	log "Cleanup"
	disconnect
	keysd_uninstall
	kmip_uninstall
	kms_stop
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
ID_B2=$(identity_of "${KEY_B}" "${NQN_BASE}:second")
PSK_S32=$(psk_of "${HEX_32}" 1)
PSK_S48=$(psk_of "${HEX_48}" 2)
ID_S32=$(identity_of "${PSK_S32}")
ID_S48=$(identity_of "${PSK_S48}")
if [ -z "${ID_A}" ] || [ -z "${ID_B}" ] || [ -z "${ID_B2}" ] ||
   [ -z "${ID_S32}" ] || [ -z "${ID_S48}" ]; then
	echo "cannot derive the test identities with ${NVME_BIN}" >&2
	exit 1
fi

# A prior run killed before cleanup() could have left these behind.
disconnect
revoke_test_keys

nvmet_setup
tlshd_start
keysd_install
if [ "${KMIP}" = true ]; then
	kmip_install
	kms_setup
fi

phase "the unit does not start without a key source"
write_fabrics_conf inline
PHASE_START=$(now)
keysd_restart
check "the unit is not active" test "$(systemctl is-active "${UNIT}")" = inactive
check "the unit is not failed" \
	test "$(systemctl is-failed "${UNIT}")" != failed
check "ExecCondition= skipped the unit" \
	unit_journal_has "${PHASE_START}" "Skipped due to 'exec-condition'"
check "the check was logged" journal_has "${PHASE_START}" "nothing to do"
write_fabrics_conf systemd-creds

phase "a missing credential is reported"
PHASE_START=$(now)
keysd_restart
check "nvme-keysd runs without its credential" keysd_ran "${PHASE_START}"
check "the missing credential was logged" \
	journal_has "${PHASE_START}" "cannot decrypt credential '${CRED_NAME}'"

phase "a credential is imported at startup"
write_cred "${CRED_FILE}" "${KEY_A}" "${CRED_NAME}"
PHASE_START=$(now)
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
PHASE_START=$(now)
keysd_restart
check "nvme-keysd ran" keysd_ran "${PHASE_START}"
check "key A keeps its serial" test "$(key_serial "${ID_A}")" = "${SERIAL_A}"
check "'already present' was logged" \
	journal_has "${PHASE_START}" "'${ID_A}' already present"

phase "a new credential and a restart replace the key"
write_cred "${CRED_FILE}" "${KEY_B}" "${CRED_NAME}"
PHASE_START=$(now)
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
PHASE_START=$(now)
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
PHASE_START=$(now)
keysd_restart
check "nvme-keysd ran" keysd_ran "${PHASE_START}"
check "'already present' was logged once" \
	test "$(journal_count "${PHASE_START}" "'${ID_B}' already present")" -eq 1

# A drop-in without [Host] uses the system host NQN. Every entry fails
# before a key is inserted, so the keyring of the real host is untouched.
phase "entries that cannot be imported are skipped"
DROPIN_DIR="${FABRICS_CONF}.d"
DROPIN="${DROPIN_DIR}/errors.conf"
mkdir -p "${DROPIN_DIR}"
write_cred "${CRED_DIR}/keysd-wringer-notpsk" "not-a-psk" keysd-wringer-notpsk
write_cred "${CRED_DIR}/keysd-wringer-big" "$(printf '%0200d' 0)" \
	keysd-wringer-big
write_cred "${CRED_DIR}/keysd-wringer-keyring" "${KEY_A}" \
	keysd-wringer-keyring
{
	subsys_entry inline "tls-key-source = inline" "tls-key = ${KEY_A}"
	subsys_entry nosuch "tls-key-source = nosuch" "tls-key = ${CRED_NAME}"
	subsys_entry kmip "tls-key-source = kmip" "tls-key = ${CRED_NAME}"
	subsys_entry notlskey "tls-key-source = systemd-creds"
	subsys_entry badname "tls-key-source = systemd-creds" "tls-key = ../x"
	subsys_entry notpsk "tls-key-source = systemd-creds" \
		"tls-key = keysd-wringer-notpsk"
	subsys_entry big "tls-key-source = systemd-creds" "tls-key = keysd-wringer-big"
	subsys_entry keyring "tls-key-source = systemd-creds" \
		"tls-key = keysd-wringer-keyring" \
		"keyring = keysd-wringer-nosuch"
} > "${DROPIN}"
PHASE_START=$(now)
keysd_restart
check "nvme-keysd ran" keysd_ran "${PHASE_START}"
check "the inline entry is ignored" \
	test "$(journal_count "${PHASE_START}" "${NQN_BASE}:inline")" -eq 0
check "an unsupported tls-key-source was logged" \
	journal_has "${PHASE_START}" "${NQN_BASE}:nosuch: tls-key-source 'nosuch' is not supported"
check "kmip without a KMS was logged" \
	journal_has "${PHASE_START}" "${NQN_BASE}:kmip: tls-key-source is kmip but no KMS is configured"
check "a missing tls-key was logged" \
	journal_has "${PHASE_START}" "${NQN_BASE}:notlskey: tls-key-source is systemd-creds but tls-key is not set"
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
PHASE_START=$(now)
keysd_restart
check "the unit is skipped" \
	unit_journal_has "${PHASE_START}" "Skipped due to 'exec-condition'"
check "the read failure was logged" \
	journal_has "${PHASE_START}" "cannot read the fabrics configuration"
check "key B is still in .nvme" key_present "${ID_B}"

finish() {
	if [ -n "${GITHUB_ACTIONS:-}" ] && [ "${PHASE}" -gt 0 ]; then
		echo "::endgroup::"
	fi
	printf "\n"
	log "Results: ${PASS} passed, ${FAIL} failed"
	[ "${FAIL}" -eq 0 ]
	exit
}

rm -rf "${DROPIN_DIR}"
if [ "${KMIP}" != true ]; then
	log "nvme-keysd-kmip is not built: no KMIP phases"
	finish
fi

# ---------------------------------------------------------------------------
# KMIP phases
# ---------------------------------------------------------------------------

NAME_A=keysd-wringer-a
NAME_B2=keysd-wringer-b2
NAME_S32=keysd-wringer-s32
NAME_S48=keysd-wringer-s48
NAME_DUP=keysd-wringer-dup

phase "a KMIP key that is not Active is not used"
revoke_test_keys
UID_A=$(kms register-secret "${NAME_A}" "${KEY_A}")
check "key A is on the KMS" test -n "${UID_A}"
write_keysd_conf "${KMIP_DIR}/ca.pem" "${TRADDR}"
write_fabrics_conf kmip:wringer "${NAME_A}"
PHASE_START=$(now)
keysd_restart
check "nvme-keysd keeps running" keysd_active
check "NoSuchKey was logged" wait_until 5 kmip_failed "${NAME_A}" NoSuchKey 5
check "the status counts the missing key" \
	keysd_status_is "1 KMIP key(s) not imported yet"
check "key A is not in .nvme" key_absent "${ID_A}"
check "the retry delay doubles" \
	wait_until 10 kmip_failed "${NAME_A}" NoSuchKey 10

phase "an activated key is imported at the next try"
kms activate "${UID_A}"
check "key A is in .nvme" wait_until 15 key_present "${ID_A}"
check "the import was logged" journal_has "${PHASE_START}" \
	"imported '${ID_A}' from KMS 'wringer', key '${NAME_A}'"
check "the helper logged the server" helper_journal_has "${PHASE_START}" \
	"KMS 'wringer': key '${NAME_A}' sent, from ${TRADDR}"
check "the status says all keys are imported" \
	keysd_status_is "All KMIP keys imported"
check "nvme-keysd keeps running" keysd_active

phase "a TLS connection uses the KMIP key"
check "nvme connect -J connects" connect_from_config
check "the controller is live" ctrl_live
check "the connection uses key A" ctrl_uses_key "${ID_A}"
disconnect

phase "the helper runs without privileges"
check "the helper never ran as root" helper_not_root "${PHASE_START}"
check "root can call the helper" \
	helper_call 0 "{\"kms\":\"wringer\",\"name\":\"${NAME_A}\"}"
check "another user cannot call the helper" helper_refuses_nobody

phase "the helper refuses requests it cannot serve"
helper_call 0 '{"kms":"nosuch","name":"x"}'
check "an unknown KMS gets NoSuchKms" grep -q "${VARLINK_IF}.NoSuchKms" "${SCRATCH}"
helper_call 0 '{"kms":"wringer","name":""}'
# varlinkctl prints InvalidParameter as "Invalid argument" and the parameter.
check "an empty name is an invalid parameter" \
	grep -q '"parameter":"name"' "${SCRATCH}"
helper_call 0 '{"kms":"wringer","name":"keysd-wringer-nosuch"}'
check "an unknown key gets NoSuchKey" grep -q "${VARLINK_IF}.NoSuchKey" "${SCRATCH}"

phase "a Symmetric Key of 32 bytes is a SHA-256 PSK"
kms register-symmetric --activate "${NAME_S32}" "${HEX_32}" >/dev/null
write_fabrics_conf kmip:wringer "${NAME_S32}"
PHASE_START=$(now)
keysd_restart
check "the key is in .nvme" wait_until 10 key_present "${ID_S32}"
check "the PSK uses SHA-256" test "${PSK_S32#NVMeTLSkey-1:01:}" != "${PSK_S32}"
check "key A is revoked" key_absent "${ID_A}"

phase "a Symmetric Key of 48 bytes is a SHA-384 PSK"
kms register-symmetric --activate "${NAME_S48}" "${HEX_48}" >/dev/null
write_fabrics_conf kmip:wringer "${NAME_S48}"
PHASE_START=$(now)
keysd_restart
check "the key is in .nvme" wait_until 10 key_present "${ID_S48}"
check "the PSK uses SHA-384" test "${PSK_S48#NVMeTLSkey-1:02:}" != "${PSK_S48}"
check "a new connection succeeds" connect_from_config
check "the new connection uses the key" ctrl_uses_key "${ID_S48}"
disconnect

phase "objects that are not PSKs are refused"
kms register-secret --activate keysd-wringer-notpsk not-a-psk >/dev/null
kms register-symmetric --activate keysd-wringer-short \
	"${HEX_32:0:32}" >/dev/null
kms register-certificate --activate keysd-wringer-cert \
	"${KMIP_DIR}/client.pem" >/dev/null
{
	subsys_entry notpsk "tls-key = keysd-wringer-notpsk"
	subsys_entry short "tls-key = keysd-wringer-short"
	subsys_entry cert "tls-key = keysd-wringer-cert"
} >> "${FABRICS_CONF}"
PHASE_START=$(now)
keysd_restart
check "Secret Data that is not a PSK gets InvalidKey" \
	wait_until 10 kmip_failed keysd-wringer-notpsk InvalidKey 5
check "a Symmetric Key of 16 bytes gets InvalidKey" \
	wait_until 10 kmip_failed keysd-wringer-short InvalidKey 5
check "a certificate gets InvalidKey" \
	wait_until 10 kmip_failed keysd-wringer-cert InvalidKey 5
check "the status counts the three keys" \
	keysd_status_is "3 KMIP key(s) not imported yet"
check "the valid key is still in .nvme" key_present "${ID_S48}"

phase "two Active keys with one name are refused"
UID_DUP=$(kms register-secret --activate "${NAME_DUP}" "${KEY_A}")
kms register-secret --activate "${NAME_DUP}" "${KEY_B}" >/dev/null
write_fabrics_conf kmip:wringer "${NAME_DUP}"
PHASE_START=$(now)
keysd_restart
check "KeyNotUnique was logged" \
	wait_until 5 kmip_failed "${NAME_DUP}" KeyNotUnique 5
check "key A is not in .nvme" key_absent "${ID_A}"
check "key B is not in .nvme" key_absent "${ID_B}"
kms revoke "${UID_DUP}"
check "the remaining key is imported" wait_until 15 key_present "${ID_B}"

phase "a KMS that is down at startup is asked again"
kms_stop
revoke_key "${ID_B}"
PHASE_START=$(now)
keysd_restart
check "KmsFailed was logged" \
	wait_until 5 kmip_failed "${NAME_DUP}" KmsFailed 5
check "the helper logged the refused connection" \
	helper_journal_has "${PHASE_START}" \
	"KMIP ${TRADDR}: connect: Connection refused"
check "PyKMIP starts" kms_start
check "the key is imported when the KMS is back" \
	wait_until 20 key_present "${ID_B}"

phase "the servers of a KMS are tried in order"
# Nothing listens on 127.0.0.2. The second key must start with the server
# that answered for the first one.
kms register-secret --activate "${NAME_B2}" "${KEY_B}" >/dev/null
write_keysd_conf "${KMIP_DIR}/ca.pem" 127.0.0.2 "${TRADDR}"
write_fabrics_conf kmip:wringer "${NAME_A}"
subsys_entry second "tls-key = ${NAME_B2}" >> "${FABRICS_CONF}"
PHASE_START=$(now)
keysd_restart
check "key A is in .nvme" wait_until 10 key_present "${ID_A}"
check "the second key is in .nvme" wait_until 10 key_present "${ID_B2}"
check "both keys came from ${TRADDR}" test "$(helper_journal_count \
	"${PHASE_START}" "sent, from ${TRADDR}")" -eq 2
check "127.0.0.2 was tried once" test "$(helper_journal_count \
	"${PHASE_START}" "KMIP 127.0.0.2: connect")" -eq 1
revoke_key "${ID_B2}"
write_fabrics_conf kmip:wringer "${NAME_A}"

phase "a server certificate from another CA is refused"
write_keysd_conf "${KMIP_DIR}/other-ca.pem" "${TRADDR}"
revoke_key "${ID_A}"
PHASE_START=$(now)
keysd_restart
check "KmsFailed was logged" \
	wait_until 10 kmip_failed "${NAME_A}" KmsFailed 5
check "the helper logged the certificate" \
	helper_journal_has "${PHASE_START}" "KMIP ${TRADDR}: server certificate:"
check "key A is not in .nvme" key_absent "${ID_A}"

phase "a KMS that requires a client certificate refuses a client without one"
write_keysd_conf "${KMIP_DIR}/ca.pem" "${TRADDR}"
sed -i '/^client-/d' "${KEYSD_CONF}"
PHASE_START=$(now)
keysd_restart
check "KmsFailed was logged" \
	wait_until 10 kmip_failed "${NAME_A}" KmsFailed 5
check "the helper logged the failed handshake" \
	helper_journal_has "${PHASE_START}" "KMIP ${TRADDR}: TLS handshake:"
check "key A is not in .nvme" key_absent "${ID_A}"

phase "a missing client key is reported"
write_keysd_conf "${KMIP_DIR}/ca.pem" "${TRADDR}"
sed -i 's/^client-key .*/client-key  = nosuch/' "${KEYSD_CONF}"
PHASE_START=$(now)
keysd_restart
check "KmsFailed was logged" \
	wait_until 10 kmip_failed "${NAME_A}" KmsFailed 5
check "the helper logged the client key" \
	helper_journal_has "${PHASE_START}" \
	"KMIP ${TRADDR}: client key: No such file or directory"

phase "tls-key-source names a KMS when there are several"
write_keysd_conf "${KMIP_DIR}/ca.pem" "${TRADDR}"
printf '\n[kmip:other]\nserver = %s\n' "${TRADDR}" >> "${KEYSD_CONF}"
write_fabrics_conf kmip "${NAME_A}"
subsys_entry nosuchkms "tls-key-source = kmip:nosuch" "tls-key = ${NAME_A}" \
	>> "${FABRICS_CONF}"
PHASE_START=$(now)
keysd_restart
check "nvme-keysd ran" keysd_ran "${PHASE_START}"
check "a plain kmip source was logged" journal_has "${PHASE_START}" \
	"${SUBSYS_NQN}: several KMSes: use tls-key-source = kmip:<name>"
check "an unknown KMS was logged" journal_has "${PHASE_START}" \
	"${NQN_BASE}:nosuchkms: KMS 'nosuch' is not configured"

phase "nvme-keysd is restarted after a crash"
write_keysd_conf "${KMIP_DIR}/ca.pem" "${TRADDR}"
write_fabrics_conf kmip:wringer "${NAME_A}"
PHASE_START=$(now)
keysd_restart
check "key A is in .nvme" wait_until 10 key_present "${ID_A}"
OLD_PID=$(keysd_main_pid)
systemctl kill -s KILL --kill-whom=main "${UNIT}"
check "systemd started nvme-keysd again" \
	wait_until 10 keysd_restarted_after "${OLD_PID}"
check "nvme-keysd keeps running" keysd_active
check "key A is still in .nvme" key_present "${ID_A}"

phase "nvme-keysd stops on SIGTERM"
PHASE_START=$(now)
systemctl stop "${UNIT}"
check "the unit is not active" test "$(systemctl is-active "${UNIT}")" = inactive
check "the unit is not failed" \
	test "$(systemctl is-failed "${UNIT}")" != failed
check "key A is still in .nvme" key_present "${ID_A}"

finish
