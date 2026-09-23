#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
#
# Manual, root-required integration test for nvme-discoverd. Sets up a real
# nvmet-tcp target on loopback, points nvme-discoverd at it through
# nvme-fabrics.conf, and drives it through daemon restarts and out-of-band
# disconnects.
#
# Not part of `meson test`: needs root and real kernel modules (nvmet,
# nvmet-tcp, nvme-tcp). Invoke directly, after building with
# -Dnvme-discoverd=enabled:
#
#   sudo "$0"
#
# Run it on a test host only. Cleanup stops every nvme-discoverd-*.service
# unit on the machine, which disconnects the controllers they manage.

set -u

if [ "$(id -u)" -ne 0 ]; then
	echo "This script must be run as root." >&2
	exit 1
fi

for tool in nvme systemd-run modprobe; do
	if ! command -v "${tool}" >/dev/null 2>&1; then
		echo "Missing required tool: ${tool}" >&2
		exit 1
	fi
done

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# Override to run against another build, e.g. a sanitizer-enabled one.
BUILD_DIR="${BUILD_DIR:-${REPO_ROOT}/.build}"
DISCOVERD_BIN="${BUILD_DIR}/discoverd/nvme-discoverd"
NVME_BIN="${BUILD_DIR}/nvme"

if [ ! -x "${DISCOVERD_BIN}" ]; then
	cat >&2 <<EOF
${DISCOVERD_BIN} not found. Build first:
  meson setup ${BUILD_DIR} -Dnvme-discoverd=enabled
  meson compile -C ${BUILD_DIR}
EOF
	exit 1
fi

# The config directory this build reads, e.g. /usr/local/etc/nvme for the
# default /usr/local prefix. The isolated copy is bind-mounted over it.
SYSCONFDIR=$(sed -n 's/^#define SYSCONFDIR "\(.*\)"$/\1/p' \
	"${BUILD_DIR}/nvme-config.h")
if [ -z "${SYSCONFDIR}" ]; then
	echo "SYSCONFDIR not found in ${BUILD_DIR}/nvme-config.h" >&2
	exit 1
fi
NVME_CONF_DIR="${SYSCONFDIR}/nvme"
NVME_CONF_DIR_CREATED=false

DISCOVERD_UNIT=discoverd-wringer.service
TRADDR=127.0.0.1

# Reached through the Discovery Log Page of the DC on DISC_PORT.
TARGET_NQN=nqn.2026-09.org.nvmexpress.discoverd-wringer:target1
DISC_PORT=8009
DISC_PORT_ID=1

# Connected by hand, never listed in a Discovery Log Page: nvmet's DLP only
# lists the subsystems on its own port. Stands in for another orchestrator.
FOREIGN_NQN=nqn.2026-09.org.nvmexpress.discoverd-wringer:foreign
FOREIGN_PORT=4420
FOREIGN_PORT_ID=2

# Listed directly in nvme-fabrics.conf, with no [Host] section, from
# phase 6 on. Its port serves no other subsystem, so no DLP lists it.
CONF_NQN=nqn.2026-09.org.nvmexpress.discoverd-wringer:configured
CONF_PORT=4421
CONF_PORT_ID=3

ETC_NVME_DIR=$(mktemp -d /tmp/discoverd-wringer-etc-nvme.XXXXXX)
BACKING_DIR=$(mktemp -d /tmp/discoverd-wringer-ns.XXXXXX)
SCRATCH=$(mktemp /tmp/discoverd-wringer-out.XXXXXX)

CYAN="\033[1;36m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
NORMAL="\033[0m"
PASS=0
FAIL=0
SKIP=0

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

skip() {
	printf "%b  SKIP: %s%b\n" "${YELLOW}" "$1" "${NORMAL}"
	SKIP=$((SKIP + 1))
}

# ---------------------------------------------------------------------------
# nvmet-tcp target: one subsystem per port, each with one namespace.
# ---------------------------------------------------------------------------

nvmet_add_subsystem() {
	local nqn="$1"
	local subsys_dir="/sys/kernel/config/nvmet/subsystems/${nqn}"
	local backing="${BACKING_DIR}/$(basename "${nqn}")"

	log "nvmet: create subsystem ${nqn}"
	truncate -s 64M "${backing}"
	mkdir -p "${subsys_dir}"
	echo 1 > "${subsys_dir}/attr_allow_any_host"
	mkdir -p "${subsys_dir}/namespaces/1"
	echo -n "${backing}" > "${subsys_dir}/namespaces/1/device_path"
	echo 1 > "${subsys_dir}/namespaces/1/enable"
}

nvmet_add_port() {
	local id="$1" trsvcid="$2" nqn="$3"
	local port_dir="/sys/kernel/config/nvmet/ports/${id}"

	log "nvmet: port ${trsvcid} on ${TRADDR} serves ${nqn}"
	mkdir -p "${port_dir}"
	echo "${TRADDR}" > "${port_dir}/addr_traddr"
	echo tcp > "${port_dir}/addr_trtype"
	echo "${trsvcid}" > "${port_dir}/addr_trsvcid"
	echo ipv4 > "${port_dir}/addr_adrfam"
	ln -sf "/sys/kernel/config/nvmet/subsystems/${nqn}" \
	       "${port_dir}/subsystems/${nqn}"
}

nvmet_setup() {
	modprobe -a nvmet nvmet-tcp nvme-tcp
	nvmet_add_subsystem "${TARGET_NQN}"
	nvmet_add_subsystem "${FOREIGN_NQN}"
	nvmet_add_subsystem "${CONF_NQN}"
	nvmet_add_port "${DISC_PORT_ID}" "${DISC_PORT}" "${TARGET_NQN}"
	nvmet_add_port "${FOREIGN_PORT_ID}" "${FOREIGN_PORT}" "${FOREIGN_NQN}"
	nvmet_add_port "${CONF_PORT_ID}" "${CONF_PORT}" "${CONF_NQN}"
}

nvmet_teardown() {
	local id nqn

	log "nvmet: tear down"
	for id in "${DISC_PORT_ID}" "${FOREIGN_PORT_ID}" "${CONF_PORT_ID}"; do
		rm -f /sys/kernel/config/nvmet/ports/"${id}"/subsystems/*
		rmdir "/sys/kernel/config/nvmet/ports/${id}" 2>/dev/null
	done
	for nqn in "${TARGET_NQN}" "${FOREIGN_NQN}" "${CONF_NQN}"; do
		local subsys_dir="/sys/kernel/config/nvmet/subsystems/${nqn}"

		if [ -e "${subsys_dir}/namespaces/1/enable" ]; then
			echo 0 > "${subsys_dir}/namespaces/1/enable"
		fi
		rmdir "${subsys_dir}/namespaces/1" 2>/dev/null
		rmdir "${subsys_dir}" 2>/dev/null
	done
}

# ---------------------------------------------------------------------------
# Isolated config directory, bind-mounted over NVME_CONF_DIR for the daemon
# unit only.
# A stale exclusions.conf or fabrics config on the test machine must never
# change what this run connects.
#
# The isolation ends at the daemon. The per-controller units nvme-discoverd
# creates via StartTransientUnit are top-level units outside the daemon's
# mount namespace, so their `nvme connect` reads the machine's real
# NVME_CONF_DIR. The hostnqn and hostid still match, because nvme-discoverd
# passes both on the connect command line.
# ---------------------------------------------------------------------------

etc_nvme_populate() {
	local hostid=b2c3d4e5-0000-4000-8000-000000000002

	log "Populate ${ETC_NVME_DIR}"
	echo "nqn.2014-08.org.nvmexpress:uuid:${hostid}" \
		> "${ETC_NVME_DIR}/hostnqn"
	echo "${hostid}" > "${ETC_NVME_DIR}/hostid"
	: > "${ETC_NVME_DIR}/exclusions.conf"
	mkdir -p "${ETC_NVME_DIR}/exclusions.conf.d"
	cat > "${ETC_NVME_DIR}/nvme-fabrics.conf" <<EOF
[Discovery Controller]
controller = transport=tcp;traddr=${TRADDR};trsvcid=${DISC_PORT}
EOF
	chmod -R a+rX "${ETC_NVME_DIR}"

	# BindPaths= needs the mount point to exist.
	if [ ! -d "${NVME_CONF_DIR}" ]; then
		mkdir -p "${NVME_CONF_DIR}"
		NVME_CONF_DIR_CREATED=true
	fi
}

# ---------------------------------------------------------------------------
# nvme-discoverd lifecycle, as a transient unit so it can be stopped and
# restarted between phases.
# ---------------------------------------------------------------------------

discoverd_start() {
	log "Start nvme-discoverd"
	systemctl reset-failed "${DISCOVERD_UNIT}" >/dev/null 2>&1
	systemd-run --unit="${DISCOVERD_UNIT}" --collect \
		--property="BindPaths=${ETC_NVME_DIR}:${NVME_CONF_DIR}" \
		--property=Type=notify-reload \
		--property="SyslogIdentifier=nvme-discoverd" \
		"${DISCOVERD_BIN}" --nvme-path "${NVME_BIN}" --debug \
		>"${SCRATCH}" 2>&1 || cat "${SCRATCH}"
	sleep 2
	if ! systemctl is-active "${DISCOVERD_UNIT}" >/dev/null 2>&1; then
		echo "nvme-discoverd failed to start" >&2
		echo "check: journalctl -t nvme-discoverd" >&2
		exit 1
	fi
}

# Stop only the daemon. Its per-controller transient units stay loaded, as
# they do across any real daemon restart.
discoverd_stop_daemon_only() {
	if systemctl is-active "${DISCOVERD_UNIT}" >/dev/null 2>&1; then
		log "Stop nvme-discoverd (daemon only)"
		systemctl stop "${DISCOVERD_UNIT}" >/dev/null 2>&1
	fi
	systemctl reset-failed "${DISCOVERD_UNIT}" >/dev/null 2>&1
}

# Stop the daemon and every unit it created. Stopping a unit runs its
# ExecStop=, which disconnects, and lets systemd free the unit name.
# `nvme disconnect` alone would leave the unit loaded, because it bypasses
# ExecStop=.
discoverd_stop() {
	discoverd_stop_daemon_only
	systemctl stop 'nvme-discoverd-*.service' >/dev/null 2>&1 || true
	systemctl reset-failed 'nvme-discoverd-*.service' \
		>/dev/null 2>&1 || true
	"${NVME_BIN}" disconnect -n "${TARGET_NQN}" >/dev/null 2>&1 || true
	"${NVME_BIN}" disconnect -n "${CONF_NQN}" >/dev/null 2>&1 || true
}

# Is any nvme-discoverd transient unit loaded?
units_loaded() {
	[ -n "$(systemctl list-units 'nvme-discoverd-*' --all \
		--no-pager --no-legend 2>/dev/null)" ]
}

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

# Kernel device name (e.g. "nvme3") connected to subsystem $1, or non-zero
# if there is none. Reads sysfs, the same way nvme-discoverd does.
connected_dev() {
	local nqn="$1" d

	for d in /sys/class/nvme/nvme*; do
		[ -r "${d}/subsysnqn" ] || continue
		if [ "$(cat "${d}/subsysnqn" 2>/dev/null)" = "${nqn}" ]; then
			basename "${d}"
			return 0
		fi
	done
	return 1
}

is_connected() {
	connected_dev "$1" >/dev/null
}

# Poll for up to $2 seconds (default 15) for subsystem $1 to be connected.
wait_for_connected() {
	local nqn="$1" timeout="${2:-15}" waited=0

	while [ "${waited}" -lt "${timeout}" ]; do
		is_connected "${nqn}" && return 0
		sleep 1
		waited=$((waited + 1))
	done
	return 1
}

# Poll for up to $2 seconds (default 15) for subsystem $1 to disconnect.
wait_for_disconnected() {
	local nqn="$1" timeout="${2:-15}" waited=0

	while [ "${waited}" -lt "${timeout}" ]; do
		is_connected "${nqn}" || return 0
		sleep 1
		waited=$((waited + 1))
	done
	return 1
}

assert_connected() {
	local desc="$1" nqn="$2" timeout="${3:-15}"

	if wait_for_connected "${nqn}" "${timeout}"; then
		pass "${desc}"
	else
		fail "${desc}"
	fi
}

# Watch for $4 seconds (default 20) that subsystem $2 never leaves device
# $3. A changed or missing device name means the connection was torn down
# and recreated, whatever the logs say.
assert_dev_stable() {
	local desc="$1" nqn="$2" want="$3" timeout="${4:-20}" waited=0 got

	while [ "${waited}" -lt "${timeout}" ]; do
		got=$(connected_dev "${nqn}") || got="<gone>"
		if [ "${got}" != "${want}" ]; then
			fail "${desc} (was ${want}, now ${got})"
			return
		fi
		sleep 1
		waited=$((waited + 1))
	done
	pass "${desc}"
}

# Subsystem NQN of device $1, or empty if the device does not exist.
dev_nqn() {
	cat "/sys/class/nvme/$1/subsysnqn" 2>/dev/null
}

# Watch for $4 seconds (default 10) that device $3 stays connected to
# subsystem $2.
assert_dev_holds() {
	local desc="$1" nqn="$2" dev="$3" timeout="${4:-10}" waited=0 got

	while [ "${waited}" -lt "${timeout}" ]; do
		got=$(dev_nqn "${dev}")
		if [ "${got}" != "${nqn}" ]; then
			fail "${desc} (${dev} now holds '${got:-nothing}')"
			return
		fi
		sleep 1
		waited=$((waited + 1))
	done
	pass "${desc}"
}

# Connect subsystem $1 by hand, over and over, until a connection gets
# device name $2. The kernel hands out the lowest free nvmeN, so every
# lower free name has to be filled first. The extra connections stay up;
# cleanup() disconnects them. Returns non-zero if $2 was never reached.
connect_onto_dev() {
	local nqn="$1" want="$2" tries=0 before after d

	while [ "${tries}" -lt 16 ]; do
		before=$(ls /sys/class/nvme)
		"${NVME_BIN}" connect -t tcp -a "${TRADDR}" \
			-s "${FOREIGN_PORT}" -n "${nqn}" --duplicate-connect \
			>/dev/null 2>&1 || return 1
		after=$(ls /sys/class/nvme)
		for d in ${after}; do
			if ! grep -qx "${d}" <<<"${before}"; then
				log "${nqn} connected as ${d}"
				[ "${d}" = "${want}" ] && return 0
			fi
		done
		tries=$((tries + 1))
	done
	return 1
}

journal_has() {
	journalctl -t nvme-discoverd --since "$1" 2>/dev/null | grep -q -- "$2"
}

assert_journal_has() {
	local desc="$1" since="$2" pattern="$3"

	if journal_has "${since}" "${pattern}"; then
		pass "${desc}"
	else
		fail "${desc}"
	fi
}

assert_journal_lacks() {
	local desc="$1" since="$2" pattern="$3"

	if journal_has "${since}" "${pattern}"; then
		fail "${desc}"
	else
		pass "${desc}"
	fi
}

# Disconnect subsystem $1 behind nvme-discoverd's back, bypassing the unit's
# ExecStop=, as a target reboot or a cable pull would.
disconnect_out_of_band() {
	local nqn="$1" dev

	dev=$(connected_dev "${nqn}") || return 0
	log "Disconnect ${dev} (${nqn}) out of band"
	"${NVME_BIN}" disconnect -d "${dev}" >/dev/null 2>&1
	wait_for_disconnected "${nqn}" 10
}

# ---------------------------------------------------------------------------
# Cleanup: always runs, even on Ctrl-C or an assertion failing partway.
# ---------------------------------------------------------------------------

cleanup() {
	log "Cleanup"
	discoverd_stop
	"${NVME_BIN}" disconnect -n "${FOREIGN_NQN}" >/dev/null 2>&1 || true
	nvmet_teardown
	rm -rf "${ETC_NVME_DIR}" "${BACKING_DIR}"
	rm -f "${SCRATCH}"
	if [ "${NVME_CONF_DIR_CREATED}" = true ]; then
		rmdir "${NVME_CONF_DIR}" 2>/dev/null
	fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

# A prior run killed before reaching cleanup() could have left these
# connected on the real host.
"${NVME_BIN}" disconnect -n "${TARGET_NQN}" >/dev/null 2>&1 || true
"${NVME_BIN}" disconnect -n "${FOREIGN_NQN}" >/dev/null 2>&1 || true
"${NVME_BIN}" disconnect -n "${CONF_NQN}" >/dev/null 2>&1 || true

etc_nvme_populate
nvmet_setup

log ">>>>> Phase 1: connect through a configured DC <<<<<"
discoverd_start
assert_connected "connects the subsystem listed in the DC's DLP" \
	"${TARGET_NQN}" 30

log ">>>>> Phase 2: restart over a live connection <<<<<"
log "the connection must survive untouched"
#
# Every ordinary daemon restart looks like this: the controller is still
# connected and its unit still loaded. nvme-discoverd must adopt the unit.
# Starting it again would fail with -EEXIST, and the recovery for that
# stops the unit, whose ExecStop= disconnects.
PHASE2_DEV=$(connected_dev "${TARGET_NQN}")
log "phase 2: connected as ${PHASE2_DEV}"

discoverd_stop_daemon_only
if units_loaded; then
	pass "phase 2 setup: unit still loaded with the daemon down"
else
	fail "phase 2 setup: expected the unit to outlive the daemon"
fi

PHASE2_START=$(date +%H:%M:%S)
discoverd_start
assert_dev_stable "restart adopts the live connection" \
	"${TARGET_NQN}" "${PHASE2_DEV}"
assert_journal_has "the adoption path was taken" \
	"${PHASE2_START}" "adopted, already connected"
assert_journal_lacks "no stale-unit collision on a live connection" \
	"${PHASE2_START}" "held by a stale unit"

log ">>>>> Phase 3: an adopted controller that drops is reconnected <<<<<"
#
# Continues from phase 2: the controller is tracked because it was
# adopted, not because this daemon connected it.
PHASE3_START=$(date +%H:%M:%S)
disconnect_out_of_band "${TARGET_NQN}"
assert_connected "reconnects the adopted controller" "${TARGET_NQN}" 30
assert_journal_has "treated the drop as a desired controller" \
	"${PHASE3_START}" "removed but still desired, reconnecting"

log ">>>>> Phase 4: restart over a stale unit <<<<<"
#
# The mirror of phase 2: the unit is still loaded, but its controller
# dropped while the daemon was down. nvme-discoverd must replace the unit.
discoverd_stop_daemon_only
disconnect_out_of_band "${TARGET_NQN}"
if units_loaded; then
	pass "phase 4 setup: stale unit left loaded"
else
	fail "phase 4 setup: expected a stale unit, found none"
fi

PHASE4_START=$(date +%H:%M:%S)
discoverd_start
assert_connected "replaces the stale unit and reconnects" \
	"${TARGET_NQN}" 30
assert_journal_has "the stale-unit collision was hit" \
	"${PHASE4_START}" "held by a stale unit"

log ">>>>> Phase 5: a stale unit's device name was reused <<<<<"
#
# The kernel hands out the lowest free nvmeN. While the daemon is down, the
# controller drops and another orchestrator's connection takes its name.
# The stale unit still records that name. nvme-discoverd must neither adopt
# that connection nor let the stale unit's ExecStop= disconnect it.
discoverd_stop_daemon_only
PHASE5_DEV=$(connected_dev "${TARGET_NQN}")
disconnect_out_of_band "${TARGET_NQN}"

if ! connect_onto_dev "${FOREIGN_NQN}" "${PHASE5_DEV}"; then
	skip "phase 5: could not get ${FOREIGN_NQN} onto ${PHASE5_DEV}"
else
	PHASE5_START=$(date +%H:%M:%S)
	discoverd_start
	assert_connected "reconnects its own controller" "${TARGET_NQN}" 30
	assert_dev_holds "leaves the other connection on the reused name" \
		"${FOREIGN_NQN}" "${PHASE5_DEV}"
	assert_journal_lacks "does not adopt the other connection" \
		"${PHASE5_START}" "${PHASE5_DEV} - adopted"
fi

log ">>>>> Phase 6: restart over a configured IOC without [Host] <<<<<"
#
# A connection listed in nvme-fabrics.conf with no [Host] section connects
# as the default host. Its candidate must carry that identity, or a
# restart cannot match the unit's connection and replaces it instead of
# adopting it.
discoverd_stop_daemon_only
cat >> "${ETC_NVME_DIR}/nvme-fabrics.conf" <<EOF

[Subsystem]
nqn        = ${CONF_NQN}
controller = transport=tcp;traddr=${TRADDR};trsvcid=${CONF_PORT}
EOF
discoverd_start
assert_connected "connects the configured IOC" "${CONF_NQN}" 30
PHASE6_DEV=$(connected_dev "${CONF_NQN}")
log "phase 6: connected as ${PHASE6_DEV}"

discoverd_stop_daemon_only
PHASE6_START=$(date +%H:%M:%S)
discoverd_start
assert_dev_stable "restart adopts the configured IOC" \
	"${CONF_NQN}" "${PHASE6_DEV}"
assert_journal_has "the adoption path was taken" \
	"${PHASE6_START}" "${PHASE6_DEV} - adopted"

printf "\n"
log "Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
[ "${FAIL}" -eq 0 ]
