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

#define NBFT_SYSFS_PATH "/sys/firmware/acpi/tables"

/*
 * Populate the NBFT DC/IOC sets from the NBFT ACPI tables in @path,
 * normally NBFT_SYSFS_PATH. Call once at startup; the NBFT itself does
 * not change at runtime, so unlike inventory_load_config() this never
 * needs a rebuild. A missing/absent NBFT is not an error. A candidate
 * that names no host gets @dctx's default identity.
 * Returns 0 on success, negative errno on failure.
 */
int inventory_load_nbft(struct inventory *inv,
			const struct discoverd_ctx *dctx, char *path);

/*
 * Replace the pre-OS DC/IOC sets with the connections of @cfg, the
 * resolved RUNDIR/nvme/pre-os.conf the pre-OS environment wrote (see
 * nvme's pre-os.h), or empty them if @cfg is NULL. @cfg must outlive the
 * sets: the connections keep pointing into it for their parameters.
 */
void inventory_load_pre_os(struct inventory *inv,
			   const struct discoverd_ctx *dctx,
			   const struct libnvmf_config *cfg);

/*
 * Called from the event loop when the name lookup of a configured traddr
 * ends. @added is true if the lookup added a connection to the config sets.
 */
typedef void (*inventory_lookup_callback)(bool added, void *user_data);

void inventory_set_lookup_callback(struct inventory *inv,
				   inventory_lookup_callback cb,
				   void *user_data);

/*
 * Rebuild the config DC/IOC sets from the resolved fabrics configuration
 * (libnvmf_config_read()). Call at startup and again on every SIGHUP —
 * this always fully replaces the previous sets, never merges. A numeric
 * traddr is added at once. A host name is resolved through
 * @dctx->resolver, without blocking: the connection is added when its
 * lookup ends, and a failed lookup is tried again later. Loading the
 * configuration again cancels the lookups of the previous one. A
 * candidate that names no host gets @dctx's default identity.
 * @dctx->fabrics_cfg may be NULL (equivalent to an empty configuration).
 */
void inventory_load_config(struct inventory *inv,
			   const struct discoverd_ctx *dctx);

/*
 * True until the first lookup of each host name of the last
 * inventory_load_config() has ended. Until then, the config sets are not
 * complete.
 */
bool inventory_config_pending(const struct inventory *inv);

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
 * Where @tid comes from: "nbft", "pre-os", "config", "discovered", or
 * "dlp" with *@parent set to the desired DC whose cached DLP lists it.
 * NULL if @tid is not desired. *@parent is borrowed from @inv.
 */
const char *inventory_source(const struct inventory *inv,
			     const struct libnvmf_tid *tid,
			     const struct libnvmf_tid **parent);

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
 * Query: is tid a connection of the pre-OS environment? True for the
 * NBFT and pre-os.conf sets, and for what the cached DLP of such a DC
 * lists. nvme-discoverd keeps these connected with the owner pre-os and
 * never disconnects them.
 */
bool inventory_is_pre_os(const struct inventory *inv,
			 const struct libnvmf_tid *t);

/*
 * The pre-os.conf entry of @t, or for what a pre-OS DC lists, the entry of
 * the nearest DC above it that has one: "connect-all" in the pre-OS
 * environment gave its options to everything it connected. NULL if none.
 */
const struct libnvmf_config_conn *inventory_pre_os_conn_for(
		const struct inventory *inv, const struct libnvmf_tid *t);

/* Whether @conn is an entry of pre-os.conf. */
bool inventory_is_pre_os_conn(const struct inventory *inv,
			      const struct libnvmf_config_conn *conn);

/*
 * Iterate over all DC TIDs that should be connected at startup.
 * (NBFT DCs + config DCs + discovered DCs.)
 * Returns a NULL-terminated array; caller must free each element and the array.
 */
struct libnvmf_tid **inventory_desired_dcs(const struct inventory *inv);

/*
 * Iterate over all IOC TIDs that should be connected at startup.
 * (NBFT IOCs + config IOCs.)
 */
struct libnvmf_tid **inventory_desired_iocs(const struct inventory *inv);
