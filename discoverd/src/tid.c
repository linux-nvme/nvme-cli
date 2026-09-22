// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <ifaddrs.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <nvme/fabrics.h>
#include <nvme/nvme-types-fabrics.h>

#include <shared/net-util.h>

#include "tid.h"

struct libnvmf_tid *tid_new(const char *transport, const char *traddr,
			    const char *trsvcid, const char *subsysnqn,
			    const char *host_traddr, const char *host_iface,
			    const char *hostnqn, bool is_dc)
{
	struct libnvmf_tid *t;

	if (!trsvcid || trsvcid[0] == '\0')
		trsvcid = libnvmf_get_default_trsvcid(transport, is_dc);

	libnvmf_tid_from_fields(transport, traddr, trsvcid, subsysnqn,
				host_traddr, host_iface, hostnqn, NULL, &t);
	return t;
}

/*
 * Compare transport addresses. Defensive: every TID reaching here was
 * built by libnvmf_tid_from_fields(), which canonicalizes traddr and
 * host_traddr, so a literal comparison would do. Compare IP addresses
 * numerically anyway, so a TID that arrives from somewhere that did not
 * canonicalize still matches its other spelling.
 */
static bool tid_addr_eq(bool ip, const char *a, const char *b)
{
	if (ip)
		return shr_ipaddrs_eq(a, b);

	return shr_streq0(a, b);
}

/*
 * Match the host-side fields of a TCP connection. The kernel reports the
 * source address it selected; map it back to an interface instead of
 * comparing interface names, because a connection made with host_iface
 * alone carries a source address the candidate never named. Kernels older
 * than 6.1 report no source address, so fall back to the interface the
 * connection recorded and, for a candidate host_traddr, to that
 * interface's primary address. That fallback cannot distinguish a
 * connection that overrode the primary address.
 */
static bool tcp_host_side_matches(const char *candidate_host_traddr,
				  const char *candidate_host_iface,
				  const struct libnvmf_tid *existing,
				  const struct ifaddrs *iface_list)
{
	const char *src = libnvmf_tid_get_host_traddr(existing);
	const char *existing_iface = libnvmf_tid_get_host_iface(existing);

	if (!src) {
		if (candidate_host_iface && existing_iface &&
		    !shr_streq0(candidate_host_iface, existing_iface))
			return false;
		if (candidate_host_traddr && existing_iface &&
		    !shr_iface_primary_addr_matches(iface_list, existing_iface,
						    candidate_host_traddr))
			return false;

		return true;
	}

	if (candidate_host_traddr &&
	    !shr_ipaddrs_eq(candidate_host_traddr, src))
		return false;

	if (candidate_host_iface &&
	    !shr_streq0(candidate_host_iface,
			shr_iface_matching_addr(iface_list, src)))
		return false;

	return true;
}

bool tid_matches_existing(const struct libnvmf_tid *candidate,
		      const struct libnvmf_tid *existing, bool existing_is_dc,
		      const struct ifaddrs *iface_list)
{
	const char *transport = libnvmf_tid_get_transport(candidate);
	const char *subsysnqn = libnvmf_tid_get_subsysnqn(candidate);
	const char *host_traddr = libnvmf_tid_get_host_traddr(candidate);
	const char *host_iface = libnvmf_tid_get_host_iface(candidate);
	bool ip = shr_streq0(transport, "tcp") || shr_streq0(transport, "rdma");

	if (!shr_streq0(transport, libnvmf_tid_get_transport(existing)))
		return false;

	if (!shr_streq0(libnvmf_tid_get_trsvcid(candidate),
			libnvmf_tid_get_trsvcid(existing)))
		return false;

	if (!tid_addr_eq(ip, libnvmf_tid_get_traddr(candidate),
			 libnvmf_tid_get_traddr(existing)))
		return false;

	if (!shr_streq0(libnvmf_tid_get_hostnqn(candidate),
			libnvmf_tid_get_hostnqn(existing)))
		return false;

	if (shr_streq0(subsysnqn, NVME_DISC_SUBSYS_NAME)) {
		if (!existing_is_dc)
			return false;
	} else if (!shr_streq0(subsysnqn,
			       libnvmf_tid_get_subsysnqn(existing))) {
		return false;
	}

	if (shr_streq0(transport, "tcp")) {
		if ((host_traddr || host_iface) &&
		    !tcp_host_side_matches(host_traddr, host_iface, existing,
					   iface_list))
			return false;
	} else {
		const char *existing_traddr =
			libnvmf_tid_get_host_traddr(existing);
		const char *existing_iface =
			libnvmf_tid_get_host_iface(existing);

		if (host_traddr && existing_traddr &&
		    !tid_addr_eq(ip, host_traddr, existing_traddr))
			return false;

		if (host_iface && existing_iface &&
		    !shr_streq0(host_iface, existing_iface))
			return false;
	}

	return true;
}

/*
 * FNV-1a 64-bit over a byte range. libnvme has its own internal copy
 * (libnvmf_fnv1a_64() in util-fabrics.c) but it is not part of the public
 * API, so discoverd carries this short, dependency-free copy of the same
 * well-known algorithm rather than reaching into libnvme's private headers.
 */
static uint64_t fnv1a_64(const void *buf, size_t len)
{
	const unsigned char *p = buf;
	uint64_t hash = 14695981039346656037ULL;
	size_t i;

	for (i = 0; i < len; i++) {
		hash ^= p[i];
		hash *= 1099511628211ULL;
	}
	return hash;
}

char *tid_unit_name(const struct libnvmf_tid *t)
{
	const char *canon = libnvmf_tid_get_canonical(t);
	uint64_t hash;
	char *name;

	if (!canon)
		return NULL;

	/* Truncate to 48 bits (12 hex chars) — see tid.h. */
	hash = fnv1a_64(canon, strlen(canon)) & 0xffffffffffffULL;

	if (asprintf(&name, "nvme-discoverd-%012" PRIx64 ".service", hash) < 0)
		return NULL;
	return name;
}
