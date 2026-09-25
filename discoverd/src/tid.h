/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>

#include <nvme/generated/accessors-fabrics.h>
#include <nvme/tid.h>

#include <shared/array-util.h>
#include <shared/cleanup-util.h>
#include <shared/string-util.h>

/*
 * __cleanup_tid - free a struct libnvmf_tid * when it goes out of scope.
 * Declare fresh inside a loop body to free the previous iteration's TID
 * automatically, on every exit path including continue, instead of a
 * manual tid_free() before each one.
 */
static inline DEFINE_CLEANUP_FUNC(cleanup_tid, struct libnvmf_tid *,
				  libnvmf_tid_free)
#define __cleanup_tid __cleanup(cleanup_tid)

/*
 * tid_new() - allocate a TID from individual field strings.
 *
 * Thin wrapper around libnvmf_tid_from_fields() that fills in trsvcid when
 * the caller does not have one: if trsvcid is NULL or empty, it is set via
 * libnvmf_get_default_trsvcid(transport, is_dc) - the caller must say
 * whether this TID is a DC or an IOC, since the well-known port differs by
 * role for at least NVMe/TCP (8009 vs 4420).
 *
 * Returns NULL if traddr/host_traddr is not numeric on an IP transport, or
 * on allocation failure (same as libnvmf_tid_from_fields()).
 */
struct libnvmf_tid *tid_new(const char *transport, const char *traddr,
			    const char *trsvcid, const char *subsysnqn,
			    const char *host_traddr, const char *host_iface,
			    const char *hostnqn, const char *hostid,
			    bool is_dc);

/*
 * tid_set_default_host_if_unset() - give a hostless TID the default host.
 *
 * If @tid names no host, give it @hostnqn and @hostid, the default
 * identity. A TID that names a host is left as it is: the default hostid
 * belongs to the default hostnqn, not to another host. A hostid the TID
 * already has is kept. The TID copies both strings.
 *
 * Returns 0, or a negative errno from libnvmf_tid_set_identity().
 */
int tid_set_default_host_if_unset(struct libnvmf_tid *tid,
				  const char *hostnqn, const char *hostid);

/* tid_free() - release a TID (delegates to libnvmf_tid_free). */
static inline void tid_free(struct libnvmf_tid *t)
{
	libnvmf_tid_free(t);
}

/* Growable TID array, backed by struct shr_ptrarray. */
SHR_PTRARRAY_DEFINE(tid_list, struct libnvmf_tid);

/* Free every TID in @l, then the array itself, leaving @l empty. */
static inline void tid_list_free_items(struct tid_list *l)
{
	size_t i;

	for (i = 0; i < l->len; i++)
		tid_free(l->items[i]);
	tid_list_free(l);
}

/*
 * tid_same() - do two TIDs refer to the same host-subsystem relationship?
 *
 * Byte-comparison of libnvmf_tid_get_canonical(). Correct here because every
 * TID discoverd compares is discoverd-built (sanitized/canonicalized by the
 * same constructors), so canonical-string equality is byte-reproducible for
 * this single producer. Valid only between candidate TIDs (NBFT, config, a
 * Discovery Log Page, or mDNS). A TID read from sysfs carries the fields
 * the kernel chose, so it never compares equal to the candidate that
 * produced the connection - use tid_matches_existing() for that.
 */
static inline bool tid_same(const struct libnvmf_tid *a,
			    const struct libnvmf_tid *b)
{
	return shr_streq0(libnvmf_tid_get_canonical(a),
			 libnvmf_tid_get_canonical(b));
}

struct ifaddrs;

/*
 * tid_matches_existing() - can an existing connection serve a candidate?
 * @candidate:      candidate TID (from NBFT, config, a DLPE, or mDNS)
 * @existing:       TID read from sysfs for a currently-connected controller
 * @existing_is_dc: is @existing a Discovery Controller?
 * @iface_list:     interface list from getifaddrs(), or NULL
 *
 * Unlike tid_same(), this is asymmetric: @candidate states what the connection
 * must provide, @existing reports what the kernel actually did. Host-side
 * fields are checked only when @candidate asks for them, and the kernel's
 * source address is mapped back to an interface rather than compared
 * literally, because a connection made with host_iface alone reports a
 * source address the candidate never named. A candidate requesting the
 * well-known discovery NQN accepts any DC, since a DC may answer with a
 * unique NQN. The host ID is compared only when both TIDs have one.
 *
 * Return: true if @existing satisfies @candidate.
 */
/*
 * tid_link_local_scope() - scope of a TID's link-local traddr
 * @t: TID
 *
 * Return: the scope after '%' if @t's traddr is a scoped IPv6 link-local
 * address, else NULL. Borrowed from @t.
 */
const char *tid_link_local_scope(const struct libnvmf_tid *t);

/*
 * tid_scope_link_local() - add a scope to a link-local traddr
 * @traddr: transport address
 * @scope:  interface name or index, or NULL
 *
 * A link-local IPv6 address names no link by itself. Discovery Log Page
 * entries and mDNS results carry no scope, and RDMA has no host_iface to
 * select the link.
 *
 * Return: "@traddr%@scope" if @traddr is an unscoped IPv6 link-local
 * address and @scope is not NULL, else a copy of @traddr. NULL if out of
 * memory. Free with free().
 */
char *tid_scope_link_local(const char *traddr, const char *scope);

bool tid_matches_existing(const struct libnvmf_tid *candidate,
			  const struct libnvmf_tid *existing,
			  bool existing_is_dc,
			  const struct ifaddrs *iface_list);

/*
 * tid_target_same() - do two TIDs point at the same target?
 *
 * Compares transport, traddr and trsvcid only - the target-side addressing -
 * not subsysnqn, hostnqn, or the host-side host_traddr/host_iface. Use this
 * to tell whether a DLPE's connection point is the same one a DC's own TID
 * already points at, e.g. to accept a Current Discovery Subsystem entry only
 * for the interface actually in use. tid_same() is the stricter, full
 * comparison; reach for that instead when subsysnqn/host identity matters
 * too.
 */
static inline bool tid_target_same(const struct libnvmf_tid *a,
				   const struct libnvmf_tid *b)
{
	return shr_streq0(libnvmf_tid_get_transport(a),
			 libnvmf_tid_get_transport(b)) &&
	       shr_streq0(libnvmf_tid_get_traddr(a),
			 libnvmf_tid_get_traddr(b)) &&
	       shr_streq0(libnvmf_tid_get_trsvcid(a),
			 libnvmf_tid_get_trsvcid(b));
}

/*
 * tid_unit_name() - systemd unit name for a TID.
 * Returns "nvme-discoverd-<12 hex chars>.service", the FNV-1a-64 hash of
 * libnvmf_tid_get_canonical() truncated to 48 bits. Caller must free the
 * returned string.
 */
char *tid_unit_name(const struct libnvmf_tid *t);
