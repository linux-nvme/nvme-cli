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

struct libnvme_global_ctx;
struct inventory;

/* Allocate an empty inventory. */
struct inventory *inventory_new(void);
void inventory_free(struct inventory *inv);

/*
 * Populate the NBFT DC/IOC sets from the firmware NBFT ACPI table. Call
 * once at startup; the NBFT itself does not change at runtime, so unlike
 * inventory_load_config() this never needs a rebuild. A missing/absent
 * NBFT is not an error.
 * Returns 0 on success, negative errno on failure.
 */
int inventory_load_nbft(struct inventory *inv,
			struct libnvme_global_ctx *nvme_ctx);

/*
 * Rebuild the config DC/IOC sets from the resolved fabrics configuration
 * (libnvmf_config_read()). Call at startup and again on every SIGHUP —
 * this always fully replaces the previous sets, never merges. A hostname
 * traddr is resolved here, blocking, one connection at a time — this is a
 * rare, small, startup/SIGHUP-only path, not the daemon's steady-state
 * event loop, so no worker thread is warranted. A connection whose traddr
 * cannot be resolved is skipped and logged.
 * @fabrics_cfg may be NULL (equivalent to an empty configuration).
 */
void inventory_load_config(struct inventory *inv,
			   const struct libnvmf_config *fabrics_cfg);

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
 * Update the per-DC entry in the DLP cache when a DC's log page is
 * refreshed. ioc_tids is a NULL-terminated array of TIDs from the new
 * DLP. The cache takes ownership of each TID in the array; the array
 * itself is freed by this function.
 */
void inventory_update_dlp(struct inventory *inv,
			  const struct libnvmf_tid *dc_tid,
			  struct libnvmf_tid **ioc_tids);

/* Remove the DLP cache entry for dc_tid (e.g. when DC disconnects). */
void inventory_remove_dlp(struct inventory *inv,
			  const struct libnvmf_tid *dc_tid);

/*
 * Query: is tid in the desired connection set?
 * Returns true if tid appears in the NBFT set, the config set, or any
 * per-DC entry in the DLP cache.
 */
bool inventory_is_desired(const struct inventory *inv,
			  const struct libnvmf_tid *t);

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
