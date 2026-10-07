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
# nvmet-tcp, nvme-tcp, dummy). Invoke directly, after building with
# -Dnvme-discoverd=enabled:
#
#   sudo "$0" [-y] [<iface>]
#
# It asks for confirmation first. -y skips the question.
#
# With <iface>, the mDNS (TP8009) phases run too. They advertise DCs with
# avahi-publish (package avahi-utils) and need an nvme-discoverd built with
# mDNS support. <iface> must be up, multicast-capable, not loopback, and
# have an IPv4 address. The test sends real mDNS traffic on it, so use a
# test link, not a production one. The test enables mDNS in
# systemd-resolved and restarts it, and restores the setting at the end.
#
# Run it on a test host only. Cleanup stops every nvme-discoverd-*.service
# unit on the machine, which disconnects the controllers they manage.

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

IFACE="${1:-}"
if [ -n "${IFACE}" ] && ! ip link show "${IFACE}" >/dev/null 2>&1; then
	echo "No such interface: ${IFACE}" >&2
	exit 1
fi

confirm() {
	cat <<EOF
This test changes the state of this machine:
  - It stops every nvme-discoverd-*.service unit, which disconnects the
    controllers they manage.
  - It creates nvmet-tcp subsystems and ports on ${TRADDR} and on "::".
  - It creates the dummy interface ${LL_IFACE}.
EOF
	if [ -n "${IFACE}" ]; then
		cat <<EOF
  - It sends mDNS traffic on ${IFACE}, and nvmet listens on its address.
  - It enables mDNS in systemd-resolved and restarts it several times.
EOF
	fi
	echo "Run it on a test machine only."

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

TOOLS="systemd-run modprobe"
[ -n "${IFACE}" ] && TOOLS="${TOOLS} avahi-publish resolvectl"
for tool in ${TOOLS}; do
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

for bin in "${DISCOVERD_BIN}" "${NVME_BIN}"; do
	[ -x "${bin}" ] && continue
	cat >&2 <<EOF
${bin} not found. Build first:
  meson setup ${BUILD_DIR} -Dnvme-discoverd=enabled
  meson compile -C ${BUILD_DIR}
EOF
	exit 1
done

# The config directory this build reads, e.g. /usr/local/etc/nvme for the
# default /usr/local prefix. The isolated copy is bind-mounted over it.
SYSCONFDIR=$(sed -n 's/^#define SYSCONFDIR "\(.*\)"$/\1/p' \
	"${BUILD_DIR}/nvme-config.h")
if [ -z "${SYSCONFDIR}" ]; then
	echo "SYSCONFDIR not found in ${BUILD_DIR}/nvme-config.h" >&2
	exit 1
fi
NVME_CONF_DIR="${SYSCONFDIR}/nvme"

# nvme-discoverd's state files, e.g. /run/nvme/discoverd/controllers.
RUNDIR=$(sed -n 's/^#define RUNDIR "\(.*\)"$/\1/p' "${BUILD_DIR}/nvme-config.h")
STATE_CTRLS_DIR="${RUNDIR}/nvme/discoverd/controllers"
STATE_UNITS_DIR="${RUNDIR}/nvme/discoverd/units"
REGISTRY_DIR="${RUNDIR}/nvme/registry"
DESIRED_FILE="${RUNDIR}/nvme/discoverd/desired"
NVME_CONF_DIR_CREATED=false

DISCOVERD_UNIT=discoverd-wringer.service
TRADDR=127.0.0.1

# Reached through the Discovery Log Page of the DC on DISC_PORT.
TARGET_NQN=nqn.2026-09.org.nvmexpress.discoverd-wringer:target1
DISC_PORT=8009
DISC_PORT_ID=1

# Connected by hand, never listed in a Discovery Log Page: nvmet's DLP only
# lists the subsystems on its own port. Stands in for another orchestrator,
# registered in the ownership registry as FOREIGN_OWNER.
FOREIGN_OWNER=wringer
FOREIGN_NQN=nqn.2026-09.org.nvmexpress.discoverd-wringer:foreign
FOREIGN_PORT=4420
FOREIGN_PORT_ID=2

# Listed directly in nvme-fabrics.conf, with no [Host] section, from the
# "configured IOC without [Host]" phase on. Its port serves no other
# subsystem, so no DLP lists it.
CONF_NQN=nqn.2026-09.org.nvmexpress.discoverd-wringer:configured
CONF_PORT=4421
CONF_PORT_ID=3

# IPv6 phases. Each port listens on "::". For such a port, nvmet reports
# the address the host connected to as the traddr of its DLP entries,
# without an IPv6 scope. The link-local phase uses a dummy interface.
V6_NQN=nqn.2026-09.org.nvmexpress.discoverd-wringer:ipv6
V6_PORT=8012
V6_PORT_ID=5
LL_NQN=nqn.2026-09.org.nvmexpress.discoverd-wringer:link-local
LL_PORT=8013
LL_PORT_ID=6
LL_IFACE=wringer0
LL_IFACE_CREATED=false

# Release phases. A DC kept connected with persistent=force, so that the
# kernel reports its log page changes.
REL_NQN=nqn.2026-09.org.nvmexpress.discoverd-wringer:release
REL2_NQN=nqn.2026-09.org.nvmexpress.discoverd-wringer:release2
REL_PORT=8014
REL_PORT_ID=7

# Not-live phase. A DC kept connected with persistent=force. Its port is
# removed, so the DC is held in the CONNECTING state.
NL_NQN=nqn.2026-09.org.nvmexpress.discoverd-wringer:not-live
NL_PORT=8015
NL_PORT_ID=8

# IPv4-mapped phase. The port listens on "::", so the DLP reports the IOC
# as ::ffff:127.0.0.1 to a host that connects over IPv4.
MAP_NQN=nqn.2026-10.org.nvmexpress.discoverd-wringer:mapped
MAP_PORT=8016
MAP_PORT_ID=9
REF_NQN=nqn.2026-10.org.nvmexpress.discoverd-wringer:referral
REF_PORT=8017
REF_PORT_ID=10

# mDNS phases only. Advertised through mDNS, on ${IFACE}'s address. The
# port is opened and closed per phase, so a phase can advertise a DC whose
# port is not open yet.
MDNS_NQN=nqn.2026-09.org.nvmexpress.discoverd-wringer:mdns
MDNS_PORT=8010
MDNS_PORT_ID=4
MDNS_TRADDR=
MDNS_DC_REQUESTED=
PUBLISHER_UNIT=discoverd-wringer-mdns-publisher.service
RESOLVED_DROPIN=/run/systemd/resolved.conf.d/99-discoverd-wringer.conf
RESOLVED_MDNS_WAS=

confirm

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

skip() {
	printf "%b  SKIP: %s%b\n" "${YELLOW}" "$1" "${NORMAL}"
	SKIP=$((SKIP + 1))
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

# Wait $1 seconds and say why ($2). On a terminal, the remaining time
# counts down in place. Elsewhere, a log would keep every update as a line
# of its own, so the wait is announced once.
countdown() {
	local secs="$1"

	log "$2 (${secs} s)"
	if [ ! -t 1 ]; then
		sleep "${secs}"
		return
	fi
	while [ "${secs}" -gt 0 ]; do
		printf "\r    %3d s remaining " "${secs}"
		sleep 1
		secs=$((secs - 1))
	done
	printf "\r%*s\r" 24 ""
}

results() {
	if [ -n "${GITHUB_ACTIONS:-}" ] && [ "${PHASE}" -gt 0 ]; then
		echo "::endgroup::"
	fi
	printf "\n"
	log "Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
	[ "${FAIL}" -eq 0 ]
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

# $4 and $5 default to ${TRADDR} and ipv4.
nvmet_add_port() {
	local id="$1" trsvcid="$2" nqn="$3"
	local traddr="${4:-${TRADDR}}" adrfam="${5:-ipv4}"
	local port_dir="/sys/kernel/config/nvmet/ports/${id}"

	log "nvmet: port ${trsvcid} on ${traddr} serves ${nqn}"
	mkdir -p "${port_dir}"
	echo "${traddr}" > "${port_dir}/addr_traddr"
	echo tcp > "${port_dir}/addr_trtype"
	echo "${trsvcid}" > "${port_dir}/addr_trsvcid"
	echo "${adrfam}" > "${port_dir}/addr_adrfam"
	ln -sf "/sys/kernel/config/nvmet/subsystems/${nqn}" \
	       "${port_dir}/subsystems/${nqn}"
}

# Port $1 lists a referral to the discovery port $2, whose port ID is $3.
nvmet_add_referral() {
	local id="$1" trsvcid="$2" portid="$3"
	local ref_dir="/sys/kernel/config/nvmet/ports/${id}/referrals/${trsvcid}"

	log "nvmet: port ID ${id} refers to ${TRADDR}:${trsvcid}"
	mkdir -p "${ref_dir}"
	echo "${TRADDR}" > "${ref_dir}/addr_traddr"
	echo tcp > "${ref_dir}/addr_trtype"
	echo "${trsvcid}" > "${ref_dir}/addr_trsvcid"
	echo ipv4 > "${ref_dir}/addr_adrfam"
	echo "${portid}" > "${ref_dir}/addr_portid"
	echo 1 > "${ref_dir}/enable"
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
	rmdir /sys/kernel/config/nvmet/ports/*/referrals/* 2>/dev/null
	for id in "${DISC_PORT_ID}" "${FOREIGN_PORT_ID}" "${CONF_PORT_ID}" \
		  "${V6_PORT_ID}" "${LL_PORT_ID}" "${REL_PORT_ID}" \
		  "${MDNS_PORT_ID}" "${NL_PORT_ID}" "${MAP_PORT_ID}" \
		  "${REF_PORT_ID}"; do
		rm -f /sys/kernel/config/nvmet/ports/"${id}"/subsystems/*
		rmdir "/sys/kernel/config/nvmet/ports/${id}" 2>/dev/null
	done
	for nqn in "${TARGET_NQN}" "${FOREIGN_NQN}" "${CONF_NQN}" \
		   "${V6_NQN}" "${LL_NQN}" "${REL_NQN}" "${REL2_NQN}" \
		   "${MDNS_NQN}" "${NL_NQN}" "${MAP_NQN}" "${REF_NQN}"; do
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
	"${NVME_BIN}" disconnect -n "${MDNS_NQN}" >/dev/null 2>&1 || true
	"${NVME_BIN}" disconnect -n "${V6_NQN}" >/dev/null 2>&1 || true
	"${NVME_BIN}" disconnect -n "${LL_NQN}" >/dev/null 2>&1 || true
	"${NVME_BIN}" disconnect -n "${REL_NQN}" >/dev/null 2>&1 || true
	"${NVME_BIN}" disconnect -n "${REL2_NQN}" >/dev/null 2>&1 || true
	"${NVME_BIN}" disconnect -n "${NL_NQN}" >/dev/null 2>&1 || true
	"${NVME_BIN}" disconnect -n "${MAP_NQN}" >/dev/null 2>&1 || true
	"${NVME_BIN}" disconnect -n "${REF_NQN}" >/dev/null 2>&1 || true
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

# Number of controllers connected to subsystem $1.
count_connected() {
	local nqn="$1" d n=0

	for d in /sys/class/nvme/nvme*; do
		[ "$(cat "${d}/subsysnqn" 2>/dev/null)" = "${nqn}" ] &&
			n=$((n + 1))
	done
	echo "${n}"
}

# No device may be recorded by more than one unit. Two units on one device
# means that stopping one of them disconnects the other's connection.
assert_one_unit_per_device() {
	local desc="$1" dups

	dups=$(cat "${STATE_UNITS_DIR}"/*.devid 2>/dev/null | grep . |
	       sort | uniq -d | tr '\n' ' ')
	if [ -z "${dups}" ]; then
		pass "${desc}"
	else
		fail "${desc} (shared: ${dups})"
	fi
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

# Device name of the DC connected on port $1, or non-zero if there is none.
dc_dev() {
	local port="$1" d

	for d in /sys/class/nvme/nvme*; do
		[ "$(cat "${d}/subsysnqn" 2>/dev/null)" = \
		  nqn.2014-08.org.nvmexpress.discovery ] || continue
		if grep -qE "trsvcid=${port}(,|$)" "${d}/address" \
			2>/dev/null; then
			basename "${d}"
			return 0
		fi
	done
	return 1
}

# Poll for up to $3 seconds for device $1 to reach controller state $2.
wait_for_state() {
	local dev="$1" want="$2" timeout="$3" waited=0

	while [ "${waited}" -lt "${timeout}" ]; do
		[ "$(cat "/sys/class/nvme/${dev}/state" 2>/dev/null)" = \
		  "${want}" ] && return 0
		sleep 1
		waited=$((waited + 1))
	done
	return 1
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
			--owner "${FOREIGN_OWNER}" >/dev/null 2>&1 || return 1
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

# Poll for up to $4 seconds (default 0) for the journal line. On a
# terminal, a wait of 30 s or more shows the time left, as countdown()
# does.
assert_journal_has() {
	local desc="$1" since="$2" pattern="$3" timeout="${4:-0}" waited=0
	local show=false

	[ -t 1 ] && [ "${timeout}" -ge 30 ] && show=true
	until journal_has "${since}" "${pattern}"; do
		if [ "${waited}" -ge "${timeout}" ]; then
			[ "${show}" = true ] && printf "\r%*s\r" 24 ""
			fail "${desc}"
			return
		fi
		[ "${show}" = true ] &&
			printf "\r    %3d s remaining " $((timeout - waited))
		sleep 1
		waited=$((waited + 1))
	done
	[ "${show}" = true ] && printf "\r%*s\r" 24 ""
	pass "${desc}"
}

# The unit that owns device $1, as nvme-discoverd recorded it.
dev_unit() {
	cat "${STATE_CTRLS_DIR}/$1/unit" 2>/dev/null
}

# Check that nvme-discoverd released subsystem $2 on device $3, owned by
# unit $4: the connection stays up, the unit stops, and the registry
# owner is cleared. The release runs from the event loop, so wait for it.
assert_released() {
	local desc="$1" nqn="$2" dev="$3" unit="$4" waited=0

	while [ "${waited}" -lt 10 ]; do
		if ! systemctl is-active --quiet "${unit}" &&
		   [ "$(cat "${REGISTRY_DIR}/${dev}/owner" 2>/dev/null)" != \
		     discoverd ]; then
			break
		fi
		sleep 1
		waited=$((waited + 1))
	done

	if systemctl is-active --quiet "${unit}"; then
		fail "${desc}: its unit is stopped"
	else
		pass "${desc}: its unit is stopped"
	fi
	if [ "$(cat "${REGISTRY_DIR}/${dev}/owner" 2>/dev/null)" = \
	     discoverd ]; then
		fail "${desc}: its registry owner is cleared"
	else
		pass "${desc}: its registry owner is cleared"
	fi
	assert_dev_holds "${desc}: it stays connected" "${nqn}" "${dev}" 5
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
# mDNS phases only.
#
# systemd-resolved needs mDNS enabled both globally (MulticastDNS= in
# resolved.conf, "no" on many distributions) and on the link. The global
# setting needs a drop-in and a restart. A restart drops the runtime link
# setting, so set the link after every restart.
# ---------------------------------------------------------------------------

resolved_mdns_link_enable() {
	resolvectl mdns "${IFACE}" yes
}

resolved_mdns_enable() {
	log "systemd-resolved: enable mDNS globally and on ${IFACE}"
	RESOLVED_MDNS_WAS=$(resolvectl mdns "${IFACE}" 2>/dev/null \
		| awk -F': ' '{print $2}')
	mkdir -p "$(dirname "${RESOLVED_DROPIN}")"
	printf '[Resolve]\nMulticastDNS=yes\n' > "${RESOLVED_DROPIN}"
	systemctl restart systemd-resolved
	sleep 1
	resolved_mdns_link_enable
}

resolved_mdns_restore() {
	[ -e "${RESOLVED_DROPIN}" ] || return 0
	log "systemd-resolved: restore mDNS settings"
	rm -f "${RESOLVED_DROPIN}"
	systemctl restart systemd-resolved
	sleep 1
	if [ -n "${RESOLVED_MDNS_WAS}" ]; then
		resolvectl mdns "${IFACE}" "${RESOLVED_MDNS_WAS}" \
			>/dev/null 2>&1
	fi
}

mdns_setup() {
	MDNS_TRADDR=$(ip -4 -o addr show "${IFACE}" | awk '{print $4}' \
		| cut -d/ -f1 | head -n1)
	if [ -z "${MDNS_TRADDR}" ]; then
		echo "${IFACE} has no IPv4 address" >&2
		exit 1
	fi
	# The connect request logged for the mDNS DC, whatever its transport.
	MDNS_DC_REQUESTED="${MDNS_TRADDR}, ${MDNS_PORT}, .*requested DC unit"
	nvmet_add_subsystem "${MDNS_NQN}"
	resolved_mdns_enable
}

# Open the mDNS DC's port, if not open yet.
mdns_port_open() {
	local port_dir="/sys/kernel/config/nvmet/ports/${MDNS_PORT_ID}"

	[ -e "${port_dir}/subsystems/${MDNS_NQN}" ] && return 0
	log "nvmet: port ${MDNS_PORT} on ${MDNS_TRADDR} serves ${MDNS_NQN}"
	mkdir -p "${port_dir}"
	echo "${MDNS_TRADDR}" > "${port_dir}/addr_traddr"
	echo tcp > "${port_dir}/addr_trtype"
	echo "${MDNS_PORT}" > "${port_dir}/addr_trsvcid"
	echo ipv4 > "${port_dir}/addr_adrfam"
	ln -sf "/sys/kernel/config/nvmet/subsystems/${MDNS_NQN}" \
	       "${port_dir}/subsystems/${MDNS_NQN}"
}

# Close the mDNS DC's port: a TCP connect to it is refused.
mdns_port_close() {
	local port_dir="/sys/kernel/config/nvmet/ports/${MDNS_PORT_ID}"

	log "nvmet: close port ${MDNS_PORT}"
	rm -f "${port_dir}/subsystems/${MDNS_NQN}"
	rmdir "${port_dir}" 2>/dev/null
}

# Advertise the mDNS DC. Arguments are TXT record strings, e.g. "p=tcp".
publish_start() {
	log "avahi-publish: _nvme-disc._tcp ${MDNS_PORT} $*"
	systemctl reset-failed "${PUBLISHER_UNIT}" >/dev/null 2>&1
	systemd-run --unit="${PUBLISHER_UNIT}" --collect \
		avahi-publish -s WRINGER _nvme-disc._tcp "${MDNS_PORT}" "$@" \
		>"${SCRATCH}" 2>&1 || cat "${SCRATCH}"
	sleep 1
}

publish_stop() {
	if systemctl is-active "${PUBLISHER_UNIT}" >/dev/null 2>&1; then
		log "avahi-publish: stop"
		systemctl stop "${PUBLISHER_UNIT}" >/dev/null 2>&1
	fi
	systemctl reset-failed "${PUBLISHER_UNIT}" >/dev/null 2>&1
}

zeroconf_enable() {
	printf '[Discovery]\nzeroconf = true\n' \
		> "${ETC_NVME_DIR}/nvme-discoverd.conf"
	chmod a+r "${ETC_NVME_DIR}/nvme-discoverd.conf"
}

# Start each mDNS phase from the same state: no advertisement, no
# connection to the mDNS subsystem, nvme-discoverd running.
mdns_phase_reset() {
	publish_stop
	discoverd_stop
	mdns_port_close
	# A restart restores the mDNS DCs saved by the last run. Each phase
	# starts from none.
	rm -f "${DESIRED_FILE}"
	discoverd_start
}

assert_not_connected() {
	local desc="$1" nqn="$2"

	if is_connected "${nqn}"; then
		fail "${desc}"
	else
		pass "${desc}"
	fi
}

# Disconnect every connection made by hand as ${FOREIGN_OWNER}. stdin is
# /dev/null because disconnect-all --owner asks for confirmation on a
# terminal.
#
# libnvme's scan merges controllers with identical connection parameters
# into one node, so one disconnect-all removes only one of the duplicate
# connections that connect_onto_dev() makes. Repeat until none is left.
disconnect_foreign() {
	local i

	for i in 1 2 3 4 5 6 7 8; do
		is_connected "${FOREIGN_NQN}" || return 0
		"${NVME_BIN}" disconnect-all --owner "${FOREIGN_OWNER}" \
			</dev/null >/dev/null 2>&1 || true
	done
}

# ---------------------------------------------------------------------------
# Cleanup: always runs, even on Ctrl-C or an assertion failing partway.
# ---------------------------------------------------------------------------

cleanup() {
	log "Cleanup"
	if [ -n "${IFACE}" ]; then
		publish_stop
	fi
	discoverd_stop
	disconnect_foreign
	nvmet_teardown
	if [ "${LL_IFACE_CREATED}" = true ]; then
		ip link del "${LL_IFACE}" 2>/dev/null
	fi
	if [ -n "${IFACE}" ]; then
		resolved_mdns_restore
	fi
	rm -rf "${ETC_NVME_DIR}" "${BACKING_DIR}"
	rm -f "${SCRATCH}" "${DESIRED_FILE}"
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
disconnect_foreign
"${NVME_BIN}" disconnect -n "${CONF_NQN}" >/dev/null 2>&1 || true
"${NVME_BIN}" disconnect -n "${MDNS_NQN}" >/dev/null 2>&1 || true
"${NVME_BIN}" disconnect -n "${V6_NQN}" >/dev/null 2>&1 || true
"${NVME_BIN}" disconnect -n "${LL_NQN}" >/dev/null 2>&1 || true
"${NVME_BIN}" disconnect -n "${REL_NQN}" >/dev/null 2>&1 || true
"${NVME_BIN}" disconnect -n "${REL2_NQN}" >/dev/null 2>&1 || true
"${NVME_BIN}" disconnect -n "${NL_NQN}" >/dev/null 2>&1 || true
"${NVME_BIN}" disconnect -n "${MAP_NQN}" >/dev/null 2>&1 || true
"${NVME_BIN}" disconnect -n "${REF_NQN}" >/dev/null 2>&1 || true
# ... and left its desired controllers saved.
rm -f "${DESIRED_FILE}"

etc_nvme_populate
nvmet_setup

phase "connect through a configured DC"
discoverd_start
assert_connected "connects the subsystem listed in the DC's DLP" \
	"${TARGET_NQN}" 30

phase "restart over a live connection"
log "the connection must survive untouched"
#
# Every ordinary daemon restart looks like this: the controller is still
# connected and its unit still loaded. nvme-discoverd must adopt the unit.
# Starting it again would fail with -EEXIST, and the recovery for that
# stops the unit, whose ExecStop= disconnects.
P_DEV=$(connected_dev "${TARGET_NQN}")
log "connected as ${P_DEV}"

discoverd_stop_daemon_only
if units_loaded; then
	pass "setup: unit still loaded with the daemon down"
else
	fail "setup: expected the unit to outlive the daemon"
fi

P_START=$(date +%H:%M:%S)
discoverd_start
assert_dev_stable "restart adopts the live connection" \
	"${TARGET_NQN}" "${P_DEV}"
assert_journal_has "the adoption path was taken" \
	"${P_START}" "adopted, already connected"
assert_journal_lacks "no stale-unit collision on a live connection" \
	"${P_START}" "held by a stale unit"
assert_one_unit_per_device "every device has one unit"

phase "an adopted controller that drops is reconnected"
#
# Continues from the previous phase: the controller is tracked because it
# was adopted, not because this daemon connected it.
P_START=$(date +%H:%M:%S)
disconnect_out_of_band "${TARGET_NQN}"
assert_connected "reconnects the adopted controller" "${TARGET_NQN}" 30
assert_journal_has "treated the drop as a desired controller" \
	"${P_START}" "removed but still desired, reconnecting"

phase "restart over a stale unit"
#
# The mirror of "restart over a live connection": the unit is still
# loaded, but its controller dropped while the daemon was down.
# nvme-discoverd must replace the unit.
discoverd_stop_daemon_only
disconnect_out_of_band "${TARGET_NQN}"
if units_loaded; then
	pass "setup: stale unit left loaded"
else
	fail "setup: expected a stale unit, found none"
fi

P_START=$(date +%H:%M:%S)
discoverd_start
assert_connected "replaces the stale unit and reconnects" \
	"${TARGET_NQN}" 30
assert_journal_has "the stale-unit collision was hit" \
	"${P_START}" "held by a stale unit"
assert_journal_has "startup removes the state of the gone device" \
	"${P_START}" "device gone, removing stale state"

phase "a stale unit's device name was reused"
#
# The kernel hands out the lowest free nvmeN. While the daemon is down, the
# controller drops and another orchestrator's connection takes its name.
# The stale unit still records that name. nvme-discoverd must neither adopt
# that connection nor let the stale unit's ExecStop= disconnect it.
discoverd_stop_daemon_only
P_DEV=$(connected_dev "${TARGET_NQN}")
disconnect_out_of_band "${TARGET_NQN}"

if ! connect_onto_dev "${FOREIGN_NQN}" "${P_DEV}"; then
	skip "could not get ${FOREIGN_NQN} onto ${P_DEV}"
else
	P_START=$(date +%H:%M:%S)
	discoverd_start
	assert_connected "reconnects its own controller" "${TARGET_NQN}" 30
	assert_dev_holds "leaves the other connection on the reused name" \
		"${FOREIGN_NQN}" "${P_DEV}"
	assert_journal_lacks "does not adopt the other connection" \
		"${P_START}" "${P_DEV} - adopted"
	assert_journal_has "startup removes the reused name's state" \
		"${P_START}" "${P_DEV}: device name reused"
fi

phase "restart over a configured IOC without [Host]"
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
P_DEV=$(connected_dev "${CONF_NQN}")
log "connected as ${P_DEV}"

discoverd_stop_daemon_only
P_START=$(date +%H:%M:%S)
discoverd_start
assert_dev_stable "restart adopts the configured IOC" \
	"${CONF_NQN}" "${P_DEV}"
assert_journal_has "the adoption path was taken" \
	"${P_START}" "${P_DEV} - adopted"

phase "stopping a stale unit spares a reused device name"
#
# As in "a stale unit's device name was reused", but the stale unit is
# stopped while the daemon is down. Its ExecStop= finds its state for the
# device name. Only the inode recorded at connect time shows that the name
# now belongs to another connection.
discoverd_stop_daemon_only
P_DEV=$(connected_dev "${TARGET_NQN}")
P_UNIT=$(cat "${STATE_CTRLS_DIR}/${P_DEV}/unit" 2>/dev/null)
disconnect_out_of_band "${TARGET_NQN}"

if [ -z "${P_UNIT}" ]; then
	fail "setup: no unit recorded for ${P_DEV}"
elif ! connect_onto_dev "${FOREIGN_NQN}" "${P_DEV}"; then
	skip "could not get ${FOREIGN_NQN} onto ${P_DEV}"
else
	log "Stop ${P_UNIT}"
	systemctl stop "${P_UNIT}" >/dev/null 2>&1
	assert_dev_holds "the stale unit's ExecStop= spares the reused name" \
		"${FOREIGN_NQN}" "${P_DEV}"
fi
discoverd_start
assert_connected "reconnects its own controller" "${TARGET_NQN}" 30

phase "a DC reached over IPv6"
nvmet_add_subsystem "${V6_NQN}"
nvmet_add_port "${V6_PORT_ID}" "${V6_PORT}" "${V6_NQN}" "::" ipv6
discoverd_stop_daemon_only
cat >> "${ETC_NVME_DIR}/nvme-fabrics.conf" <<EOF

[Discovery Controller]
controller = transport=tcp;traddr=::1;trsvcid=${V6_PORT}
EOF
discoverd_start
assert_connected "connects the subsystem listed in the DC's DLP" \
	"${V6_NQN}" 30

phase "an IPv4-mapped DLP entry is the configured IPv4 IOC"
#
# A port on "::" reports the IOC as ::ffff:127.0.0.1 to a host connected
# over IPv4. The same IOC is also configured as 127.0.0.1. Both spellings
# are one address, so they must give one unit and one connection.
nvmet_add_subsystem "${MAP_NQN}"
nvmet_add_port "${MAP_PORT_ID}" "${MAP_PORT}" "${MAP_NQN}" "::" ipv6
discoverd_stop_daemon_only
cat >> "${ETC_NVME_DIR}/nvme-fabrics.conf" <<EOF

[Discovery Controller]
controller = transport=tcp;traddr=${TRADDR};trsvcid=${MAP_PORT}

[Subsystem]
nqn        = ${MAP_NQN}
controller = transport=tcp;traddr=${TRADDR};trsvcid=${MAP_PORT}
EOF
P_START=$(date +%H:%M:%S)
discoverd_start
assert_connected "connects the subsystem" "${MAP_NQN}" 30
countdown 5 "let both sources of the IOC settle"
if [ "$(count_connected "${MAP_NQN}")" = 1 ]; then
	pass "one connection for both spellings"
else
	fail "one connection for both spellings"
fi
assert_journal_lacks "the mapped spelling is not used" \
	"${P_START}" "::ffff:${TRADDR}"
assert_one_unit_per_device "every device has one unit"

phase "a DC reached over a scoped IPv6 link-local address"
#
# A DLP entry carries no IPv6 scope. The DC reports the IOC as a bare
# fe80:: address. Without a scope, the kernel cannot use a link-local
# address, so nvme-discoverd must add the DC's scope.
LL_TRADDR=
if modprobe dummy 2>/dev/null &&
   ip link add "${LL_IFACE}" type dummy 2>/dev/null; then
	LL_IFACE_CREATED=true
	ip link set "${LL_IFACE}" up
	sleep 2
	LL_TRADDR=$(ip -6 -o addr show dev "${LL_IFACE}" scope link |
		    awk '{ sub("/.*", "", $4); print $4; exit }')
fi

if [ -z "${LL_TRADDR}" ]; then
	skip "no link-local address on a dummy interface"
else
	nvmet_add_subsystem "${LL_NQN}"
	nvmet_add_port "${LL_PORT_ID}" "${LL_PORT}" "${LL_NQN}" "::" ipv6
	discoverd_stop_daemon_only
	cat >> "${ETC_NVME_DIR}/nvme-fabrics.conf" <<EOF

[Discovery Controller]
controller = transport=tcp;traddr=${LL_TRADDR}%${LL_IFACE};trsvcid=${LL_PORT}
EOF
	discoverd_start
	assert_connected "connects the link-local subsystem" "${LL_NQN}" 30
	LL_DEV=$(connected_dev "${LL_NQN}")
	if grep -q "traddr=${LL_TRADDR}%${LL_IFACE}" \
		"/sys/class/nvme/${LL_DEV}/address" 2>/dev/null; then
		pass "the connection carries the DC's scope"
	else
		fail "the connection carries the DC's scope"
	fi
fi

phase "a reload releases a removed configured IOC"
#
# "Restart over a configured IOC without [Host]" configured this IOC.
# Without it in the configuration, it is not desired anymore.
# nvme-discoverd releases it and leaves it connected.
P_DEV=$(connected_dev "${CONF_NQN}")
P_UNIT=$(dev_unit "${P_DEV}")
sed -i "/^\[Subsystem\]\$/,/trsvcid=${CONF_PORT}\$/d" \
	"${ETC_NVME_DIR}/nvme-fabrics.conf"
P_START=$(date +%H:%M:%S)
systemctl reload "${DISCOVERD_UNIT}"
assert_released "the configured IOC" "${CONF_NQN}" "${P_DEV}" \
	"${P_UNIT}"
assert_journal_has "the release was logged" \
	"${P_START}" "${P_DEV} - no longer desired, released"

phase "a changed log page releases the entry it dropped"
#
# persistent=force keeps the DC connected, so the kernel reports log page
# changes. Unlinking a subsystem from a port would also delete its
# controllers, so the entry is removed from the log page by disallowing
# the host instead. nvmet sends that change only to allowed hosts, so a
# second subsystem, linked to the same port, triggers the fetch.
nvmet_add_subsystem "${REL_NQN}"
nvmet_add_port "${REL_PORT_ID}" "${REL_PORT}" "${REL_NQN}"
discoverd_stop_daemon_only
cat >> "${ETC_NVME_DIR}/nvme-fabrics.conf" <<EOF

[Discovery Controller]
persistent = force
controller = transport=tcp;traddr=${TRADDR};trsvcid=${REL_PORT}
EOF
discoverd_start
assert_connected "connects the subsystem listed in the DC's DLP" \
	"${REL_NQN}" 30
P_DEV=$(connected_dev "${REL_NQN}")
P_UNIT=$(dev_unit "${P_DEV}")
log "nvmet: ${REL_NQN} no longer allows any host"
echo 0 > "/sys/kernel/config/nvmet/subsystems/${REL_NQN}/attr_allow_any_host"
nvmet_add_subsystem "${REL2_NQN}"
P_START=$(date +%H:%M:%S)
log "nvmet: port ${REL_PORT} also serves ${REL2_NQN}"
ln -s "/sys/kernel/config/nvmet/subsystems/${REL2_NQN}" \
	"/sys/kernel/config/nvmet/ports/${REL_PORT_ID}/subsystems/${REL2_NQN}"
assert_connected "connects the subsystem added to the DLP" "${REL2_NQN}" 30
assert_released "the dropped entry" "${REL_NQN}" "${P_DEV}" \
	"${P_UNIT}"
assert_journal_has "the release was logged" \
	"${P_START}" "${P_DEV} - no longer desired, released"

phase "a restart releases what was removed while down"
#
# The IPv6 DC is removed from the configuration while nvme-discoverd is
# down. The IOC it listed is in the saved desired set, and its DC is gone,
# so the restart releases it at once.
P_DEV=$(connected_dev "${V6_NQN}")
P_UNIT=$(dev_unit "${P_DEV}")
discoverd_stop_daemon_only
sed -i "/traddr=::1;trsvcid=${V6_PORT}\$/d" \
	"${ETC_NVME_DIR}/nvme-fabrics.conf"
P_START=$(date +%H:%M:%S)
discoverd_start
assert_released "the IOC of the removed DC" "${V6_NQN}" \
	"${P_DEV}" "${P_UNIT}"
assert_journal_has "the release was logged" "${P_START}" \
	"${P_DEV} - no longer desired since the last run, released"

phase "a reload releases a newly excluded IOC"
P_DEV=$(connected_dev "${TARGET_NQN}")
P_UNIT=$(dev_unit "${P_DEV}")
printf '[exclusions]\nexclusion = nqn=%s\n' "${TARGET_NQN}" \
	> "${ETC_NVME_DIR}/exclusions.conf"
P_START=$(date +%H:%M:%S)
systemctl reload "${DISCOVERD_UNIT}"
assert_released "the excluded IOC" "${TARGET_NQN}" "${P_DEV}" \
	"${P_UNIT}"
assert_journal_has "the release was logged" \
	"${P_START}" "${P_DEV} - excluded, released"
: > "${ETC_NVME_DIR}/exclusions.conf"

phase "a restart adopts a DC that is not live"
#
# The kernel refuses to open a controller that is not LIVE (EWOULDBLOCK).
# An adopted DC has its DLP fetched at once, so a restart while a DC
# reconnects fetches from a device that cannot be opened. The fetch must
# fail without crashing the daemon.
nvmet_add_subsystem "${NL_NQN}"
nvmet_add_port "${NL_PORT_ID}" "${NL_PORT}" "${NL_NQN}"
discoverd_stop_daemon_only
cat >> "${ETC_NVME_DIR}/nvme-fabrics.conf" <<EOF

[Discovery Controller]
persistent = force
controller = transport=tcp;traddr=${TRADDR};trsvcid=${NL_PORT}
EOF
discoverd_start
assert_connected "connects the subsystem listed in the DC's DLP" \
	"${NL_NQN}" 30
P_DEV=$(dc_dev "${NL_PORT}")
log "DC connected as ${P_DEV:-<none>}"
if [ "$(cat "/sys/class/nvme/${P_DEV}/kato" 2>/dev/null)" = 30 ]; then
	pass "the DC connected with a 30 s keep-alive timeout"
else
	fail "the DC connected with a 30 s keep-alive timeout"
fi

discoverd_stop_daemon_only
log "nvmet: remove port ${NL_PORT}"
rm -f "/sys/kernel/config/nvmet/ports/${NL_PORT_ID}/subsystems/${NL_NQN}"
rmdir "/sys/kernel/config/nvmet/ports/${NL_PORT_ID}"
if [ -n "${P_DEV}" ] && wait_for_state "${P_DEV}" connecting 30; then
	pass "setup: the DC is connecting"
else
	fail "setup: the DC is connecting"
fi

P_START=$(date +%H:%M:%S)
discoverd_start
assert_journal_has "the DC was adopted" \
	"${P_START}" "${P_DEV} - adopted" 10
assert_journal_has "the DLP fetch failed" \
	"${P_START}" "${P_DEV} - get_discovery_log failed" 10
assert_journal_lacks "no EPCSD decision after a failed fetch" \
	"${P_START}" "${TRADDR}, ${NL_PORT}, .*EPCSD="
if systemctl is-active --quiet "${DISCOVERD_UNIT}"; then
	pass "nvme-discoverd is still running"
else
	fail "nvme-discoverd is still running"
fi

nvmet_add_port "${NL_PORT_ID}" "${NL_PORT}" "${NL_NQN}"
if wait_for_state "${P_DEV}" live 30; then
	pass "the DC is live again once its port returns"
else
	fail "the DC is live again once its port returns"
fi
assert_connected "the IOC is connected" "${NL_NQN}" 30
assert_one_unit_per_device "every device has one unit"

phase "a referral is followed"
#
# The configured DC's log page refers to a second DC. nvme-discoverd
# connects that DC and the subsystem it lists.
nvmet_add_subsystem "${REF_NQN}"
nvmet_add_port "${REF_PORT_ID}" "${REF_PORT}" "${REF_NQN}"
nvmet_add_referral "${DISC_PORT_ID}" "${REF_PORT}" "${REF_PORT_ID}"
discoverd_stop_daemon_only
discoverd_start
assert_connected "connects the subsystem the referred DC lists" \
	"${REF_NQN}" 30

phase "an unreachable referred DC is given up"
#
# dc-giveup-timeout applies to a DC with no source of its own, such as a
# referred DC. The poll interval is for the next phase.
discoverd_stop_daemon_only
printf '[Discovery]\nepcsd-poll-interval-minutes = 1\ndc-giveup-timeout = 3s\n' \
	> "${ETC_NVME_DIR}/nvme-discoverd.conf"
chmod a+r "${ETC_NVME_DIR}/nvme-discoverd.conf"
log "nvmet: remove port ${REF_PORT}"
rm -f "/sys/kernel/config/nvmet/ports/${REF_PORT_ID}/subsystems/${REF_NQN}"
rmdir "/sys/kernel/config/nvmet/ports/${REF_PORT_ID}"
P_START=$(date +%H:%M:%S)
discoverd_start
assert_journal_has "the referred DC was given up" "${P_START}" \
	"${TRADDR}, ${REF_PORT}, .* - giving up after repeated failures" 30

phase "a parked DC is polled"
#
# nvmet reports EPCSD=0, so the configured DC is disconnected after each
# fetch. nvme-discoverd connects it again after
# epcsd-poll-interval-minutes to check whether that changed.
log "Wait up to 90 s for the poll"
assert_journal_has "the parked DC was polled" "${P_START}" \
	"${TRADDR}, ${DISC_PORT}, .* - EPCSD poll: reconnecting to re-check" 90

log "Remove the referral and restore nvme-discoverd.conf"
rmdir "/sys/kernel/config/nvmet/ports/${DISC_PORT_ID}/referrals/${REF_PORT}"
rm -f "${ETC_NVME_DIR}/nvme-discoverd.conf"
discoverd_stop_daemon_only
discoverd_start

phase "a damaged desired file is read"
#
# nvme-discoverd skips the lines of its saved desired set that it cannot
# parse. A "discovered" line restores a DC found by mDNS or FC. The file
# ends without a newline.
discoverd_stop_daemon_only
P_CANON=$(awk -F'\t' -v port="${DISC_PORT}" \
	'$1 == "config" && index($2, port) { print $2; exit }' \
	"${DESIRED_FILE}")
if [ -n "${P_CANON}" ]; then
	pass "setup: the configured DC is in the desired file"
else
	fail "setup: the configured DC is in the desired file"
fi
printf 'garbage\ndlp\tnot-a-tid\t-\ndiscovered\t%s\t-' "${P_CANON}" \
	>> "${DESIRED_FILE}"
discoverd_start
if systemctl is-active --quiet "${DISCOVERD_UNIT}"; then
	pass "nvme-discoverd is running"
else
	fail "nvme-discoverd is running"
fi
assert_one_unit_per_device "every device has one unit"

phase "an excluded controller that drops is not reconnected"
#
# The exclusion is added without a reload, so nvme-discoverd still tracks
# the IOC. When the IOC drops, the exclusion list is checked again.
printf '[exclusions]\nexclusion = nqn=%s\n' "${NL_NQN}" \
	> "${ETC_NVME_DIR}/exclusions.conf"
P_START=$(date +%H:%M:%S)
disconnect_out_of_band "${NL_NQN}"
assert_journal_has "the drop was checked against the exclusions" \
	"${P_START}" "${NL_NQN}.* - excluded, skipping" 10
countdown 3 "give a reconnect time to start"
assert_not_connected "the excluded IOC is not reconnected" "${NL_NQN}"
: > "${ETC_NVME_DIR}/exclusions.conf"

if [ -z "${IFACE}" ]; then
	log "No <iface> given: mDNS phases not run"
	results
	exit
fi

mdns_setup

phase "SIGHUP enables mDNS; an advertised DC is connected"
mdns_port_open
zeroconf_enable
P_START=$(date +%H:%M:%S)
if timeout 20 systemctl reload "${DISCOVERD_UNIT}"; then
	pass "systemctl reload completes"
else
	fail "systemctl reload completes"
fi
sleep 2
assert_journal_has "the reload started mDNS on ${IFACE}" \
	"${P_START}" "mdns: browsing ${IFACE} for _nvme-disc._tcp"
publish_start "p=tcp"
assert_connected "connects the subsystem behind the advertised DC" \
	"${MDNS_NQN}" 30

phase "a withdrawn advertisement disconnects nothing"
P_DEV=$(connected_dev "${MDNS_NQN}")
publish_stop
assert_dev_stable "stays connected after the advertisement is withdrawn" \
	"${MDNS_NQN}" "${P_DEV}" 5

phase "a DC advertised before its port is open"
#
# A real DC was seen to advertise before its TCP listener was up. A plain
# TCP connect is retried silently until the port opens. No NVMe connect is
# attempted before then.
mdns_phase_reset
P_START=$(date +%H:%M:%S)
publish_start "p=tcp"
sleep 3
assert_not_connected "does not connect while the port is closed" \
	"${MDNS_NQN}"
assert_journal_lacks "no NVMe connect attempted while the port is closed" \
	"${P_START}" "${MDNS_DC_REQUESTED}"
mdns_port_open
assert_connected "connects once the port opens" "${MDNS_NQN}" 30

phase "an unusable TXT record"
mdns_phase_reset
mdns_port_open
P_START=$(date +%H:%M:%S)
publish_start "p=bogus"
sleep 3
assert_not_connected "unknown p= value: not connected" "${MDNS_NQN}"
assert_journal_has "unknown p= value: logged" \
	"${P_START}" "missing/invalid transport in TXT record"
publish_stop
publish_start
sleep 3
assert_not_connected "no TXT record: not connected" "${MDNS_NQN}"

phase "an advertised discovery NQN is used"
#
# The TXT record's nqn= key names the DC's discovery NQN. nvme-discoverd
# connects with it when the kernel accepts the "discovery" option.
mdns_phase_reset
mdns_port_open
publish_start "p=tcp" "nqn=nqn.2014-08.org.nvmexpress.discovery"
assert_connected "connects the subsystem behind the advertised DC" \
	"${MDNS_NQN}" 30

phase "an rdma DC is not checked first"
#
# No RDMA hardware is needed: the test only checks that the connect is
# requested at once, without a TCP check.
mdns_phase_reset
P_START=$(date +%H:%M:%S)
publish_start "p=roce"
sleep 3
assert_journal_has "rdma: connect requested at once" \
	"${P_START}" "${MDNS_DC_REQUESTED}"

phase "mDNS still works after 45 seconds"
#
# sd-varlink's default call timeout is 45 s, and it also applies to the
# BrowseServices call. The browse must outlive it.
mdns_phase_reset
mdns_port_open
countdown 50 "wait past the 45 s call timeout"
publish_start "p=tcp"
assert_connected "connects a DC advertised 50 s after startup" \
	"${MDNS_NQN}" 30

phase "mDNS recovers from a systemd-resolved restart"
mdns_phase_reset
mdns_port_open
P_START=$(date +%H:%M:%S)
systemctl restart systemd-resolved
sleep 1
resolved_mdns_link_enable
sleep 5
assert_journal_has "the browse failed when systemd-resolved restarted" \
	"${P_START}" "browsing _nvme-disc._tcp failed"
assert_journal_has "the browse restarted" \
	"${P_START}" "mdns: browsing ${IFACE} for _nvme-disc._tcp again"
publish_start "p=tcp"
assert_connected "connects a DC advertised after the restart" \
	"${MDNS_NQN}" 30

results
