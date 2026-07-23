/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>

#include "tid.h"

struct cache;

/* Allocate an empty cache. */
struct cache *cache_new(void);
void cache_free(struct cache *c);

/*
 * Update the per-DC DLP cache when a DC's log page is refreshed.
 * ioc_tids is a NULL-terminated array of TIDs from the new DLP.
 * The cache takes ownership of each TID in the array; the array itself
 * is freed by this function.
 */
void cache_update_dlp(struct cache *c, const struct libnvmf_tid *dc_tid,
		      struct libnvmf_tid **ioc_tids);

/* Remove the per-DC DLP cache entry for dc_tid (e.g. when DC disconnects). */
void cache_remove_dlp(struct cache *c, const struct libnvmf_tid *dc_tid);

/*
 * Query: is tid in the desired connection set?
 * Returns true if tid appears in the NBFT cache, config cache, or any
 * per-DC DLP cache.
 */
bool cache_is_desired(const struct cache *c, const struct libnvmf_tid *t);

/*
 * Query: is tid in the NBFT cache?
 * Used to determine whether to use --owner nbft.
 */
bool cache_is_nbft(const struct cache *c, const struct libnvmf_tid *t);

/*
 * Iterate over all DC TIDs that should be connected at startup.
 * (NBFT DCs + config DCs.)
 * Returns a NULL-terminated array; caller must free each element and the array.
 */
struct libnvmf_tid **cache_desired_dcs(const struct cache *c);

/*
 * Iterate over all IOC TIDs that should be connected at startup.
 * (NBFT IOCs + config IOCs.)
 */
struct libnvmf_tid **cache_desired_iocs(const struct cache *c);
