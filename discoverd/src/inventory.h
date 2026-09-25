/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>

#include <nvme/config.h>

#include "tid.h"

struct discoverd_ctx;
struct inventory;

/* Allocate an empty inventory. */
struct inventory *inventory_new(void);
void inventory_free(struct inventory *inv);

/*
 * Populate the NBFT DC/IOC sets from the firmware NBFT ACPI table. Call
 * once at startup; the NBFT itself does not change at runtime, so unlike
 * inventory_load_config() this never needs a rebuild. A missing/absent
 * NBFT is not an error. A candidate that names no host gets @dctx's default
 * identity.
 * Returns 0 on success, negative errno on failure.
 */
int inventory_load_nbft(struct inventory *inv,
			const struct discoverd_ctx *dctx);

/*
 * Rebuild the config DC/IOC sets from the resolved fabrics configuration
 * (libnvmf_config_read()). Call at startup and again on every SIGHUP —
 * this always fully replaces the previous sets, never merges. A hostname
 * traddr is resolved here, blocking, one connection at a time — this is a
 * rare, small, startup/SIGHUP-only path, not the daemon's steady-state
 * event loop, so no worker thread is warranted. A connection whose traddr
 * cannot be resolved is skipped and logged. A candidate that names no host
 * gets @dctx's default identity. @dctx->fabrics_cfg may be NULL (equivalent
 * to an empty configuration).
 */
void inventory_load_config(struct inventory *inv,
			   const struct discoverd_ctx *dctx);

/*
 * The libnvmf_config_conn that produced @t via inventory_load_config(), or
 * NULL if @t is not a statically configured connection (i.e. it was
 * learned via NBFT, a Discovery Log Page, or FC kickstart). Used to
 * choose between libnvmf_config_conn_get_params() and
 * libnvmf_config_resolve_discovered() when resolving the connect
 * parameters for @t.
 */
const struct libnvmf_config_conn *inventory_config_conn_for(
		const struct inventory *inv, const struct libnvmf_tid *t);

/*
 * Same limit as the discovery walk in libnvme (NVMF_MAX_REFERRAL_DEPTH):
 * a DC is followed up to 8 referral hops past a DC with a source.
 */
#define INVENTORY_MAX_REFERRAL_HOPS	8

/*
 * Update the per-DC entry in the DLP cache when a DC's log page is
 * refreshed. iocs and referrals are NULL-terminated arrays of the IOC and
 * referral TIDs from the new DLP. The cache takes ownership of each TID in
 * the arrays; the arrays themselves are freed by this function.
 */
void inventory_update_dlp(struct inventory *inv,
			  const struct libnvmf_tid *dc_tid,
			  struct libnvmf_tid **iocs,
			  struct libnvmf_tid **referrals);

/*
 * Record a DC found through mDNS or FC kickstart. It stays desired until
 * inventory_forget_dc().
 */
void inventory_add_discovered_dc(struct inventory *inv,
				 const struct libnvmf_tid *tid);

/*
 * Forget a DC that nvme-discoverd gave up on: its DLP cache entry and its
 * place among the discovered DCs.
 */
void inventory_forget_dc(struct inventory *inv,
			 const struct libnvmf_tid *dc_tid);

/*
 * Referral hops from a DC with a source (NBFT, the configuration, or
 * discovered) to dc_tid: 0 for such a DC, or -1 if dc_tid is not reached
 * within INVENTORY_MAX_REFERRAL_HOPS.
 */
int inventory_referral_hops(const struct inventory *inv,
			    const struct libnvmf_tid *dc_tid);

/*
 * Query: is tid in the desired connection set?
 * Returns true if tid appears in the NBFT set, the config set, or the
 * discovered DCs, or in the cached DLP of a DC that is itself desired.
 * tid must be a candidate TID: one built from NBFT, config, a Discovery
 * Log Page, or mDNS. A TID read from sysfs seldom compares equal to the
 * candidate that produced it. Match those with tid_matches_existing().
 */
bool inventory_is_desired(const struct inventory *inv,
			  const struct libnvmf_tid *tid);

/*
 * Query: is tid in the NBFT set?
 * Used to determine whether to use --owner nbft.
 */
bool inventory_is_nbft(const struct inventory *inv,
		       const struct libnvmf_tid *t);

/*
 * Iterate over all DC TIDs that should be connected at startup.
 * (NBFT DCs + config DCs.)
 * Returns a NULL-terminated array; caller must free each element and the array.
 */
struct libnvmf_tid **inventory_desired_dcs(const struct inventory *inv);

/*
 * Iterate over all IOC TIDs that should be connected at startup.
 * (NBFT IOCs + config IOCs.)
 */
struct libnvmf_tid **inventory_desired_iocs(const struct inventory *inv);
