/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>

#include <nvme/accessors-fabrics.h>
#include <nvme/tid.h>

#include "string-util.h"

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
			    const char *hostnqn, bool is_dc);

/* tid_free() - release a TID (delegates to libnvmf_tid_free). */
static inline void tid_free(struct libnvmf_tid *t)
{
	libnvmf_tid_free(t);
}

/*
 * tid_same() - are two TIDs the same connection?
 *
 * Byte-comparison of libnvmf_tid_get_canonical(). Correct here because every
 * TID discoverd compares is discoverd-built (sanitized/canonicalized by the
 * same constructors), so canonical-string equality is byte-reproducible for
 * this single producer. Do not reach for a sysfs connection-identity
 * matcher instead - that answers "is this live kernel connection the same",
 * a different question; this compares candidate TIDs from one producer
 * (the cache, config, or a Discovery Log Page).
 */
static inline bool tid_same(const struct libnvmf_tid *a,
			    const struct libnvmf_tid *b)
{
	return streq0(libnvmf_tid_get_canonical(a), libnvmf_tid_get_canonical(b));
}

/*
 * tid_unit_name() - systemd unit name for a TID.
 * Returns "nvme-discoverd-<12 hex chars>.service", the FNV-1a-64 hash of
 * libnvmf_tid_get_canonical() truncated to 48 bits. Caller must free the
 * returned string.
 */
char *tid_unit_name(const struct libnvmf_tid *t);
