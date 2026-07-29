// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <nvme/fabrics.h>

#include "tid.h"

struct libnvmf_tid *tid_new(const char *transport, const char *traddr,
			    const char *trsvcid, const char *subsysnqn,
			    const char *host_traddr, const char *host_iface,
			    const char *hostnqn, bool is_dc)
{
	if (!trsvcid || trsvcid[0] == '\0')
		trsvcid = libnvmf_get_default_trsvcid(transport, is_dc);

	return libnvmf_tid_from_fields(transport, traddr, trsvcid, subsysnqn,
				       host_traddr, host_iface, hostnqn, NULL);
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
