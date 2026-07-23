// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdlib.h>

#include "cache.h"

/* Simple growable TID array. */
struct tid_list {
	struct libnvmf_tid **items;
	size_t len;
	size_t cap;
};

/* Per-DC DLP cache entry. */
struct dlp_entry {
	struct dlp_entry *next;
	struct libnvmf_tid *dc_tid; // key
	struct tid_list iocs;       // value: IOC TIDs from last DLP fetch
};

/*
 * nbft_dcs/nbft_iocs/cfg_dcs/cfg_iocs are populated by the NBFT and
 * fabrics-config loaders (added alongside those data sources); this
 * file only owns the cache mechanism itself.
 */
struct cache {
	struct tid_list nbft_dcs;
	struct tid_list nbft_iocs;
	struct tid_list cfg_dcs;
	struct tid_list cfg_iocs;
	struct dlp_entry *dlp;
};

/*
 * Append t to l, growing the backing array (doubling capacity) as
 * needed. l takes ownership of t - the caller must not free it.
 */
static int tlist_append(struct tid_list *l, struct libnvmf_tid *t)
{
	if (l->len == l->cap) {
		size_t newcap = l->cap ? l->cap * 2 : 8;
		struct libnvmf_tid **items = realloc(l->items,
						     newcap * sizeof(*items));

		if (!items)
			return -ENOMEM;
		l->items = items;
		l->cap = newcap;
	}
	l->items[l->len++] = t;
	return 0;
}

/* Free every TID in l, then the backing array, leaving l empty. */
static void tlist_free_items(struct tid_list *l)
{
	size_t i;

	for (i = 0; i < l->len; i++)
		tid_free(l->items[i]);
	free(l->items);
	l->items = NULL;
	l->len = l->cap = 0;
}

/*
 * The four flat TID sets (nbft_dcs/nbft_iocs/cfg_dcs/cfg_iocs) have no key —
 * membership is a linear scan (tlist_contains()). dlp is a map keyed by DC
 * TID, each entry holding that DC's last-fetched IOC set; lookups
 * (cache_update_dlp(), cache_remove_dlp(), cache_is_desired()) walk it with
 * tid_same(), not a hash or tree — fine given how few DCs are tracked at
 * once.
 */
struct cache *cache_new(void)
{
	return calloc(1, sizeof(struct cache));
}

/*
 * Free a cache and everything in it: the four flat TID sets and every
 * per-DC dlp_entry (and that entry's own IOC set) in the dlp list.
 */
void cache_free(struct cache *c)
{
	struct dlp_entry *e, *next;

	if (!c)
		return;
	tlist_free_items(&c->nbft_dcs);
	tlist_free_items(&c->nbft_iocs);
	tlist_free_items(&c->cfg_dcs);
	tlist_free_items(&c->cfg_iocs);
	for (e = c->dlp; e; e = next) {
		next = e->next;
		tid_free(e->dc_tid);
		tlist_free_items(&e->iocs);
		free(e);
	}
	free(c);
}

/*
 * Replace the IOC set learned from dc_tid's Discovery Log Page. Called
 * each time a DC's DLP is (re-)fetched, so this is a clean per-DC
 * replacement, not an incremental merge - any IOC that dropped out of
 * the new DLP simply disappears from the cache for this DC.
 */
void cache_update_dlp(struct cache *c, const struct libnvmf_tid *dc_tid,
		      struct libnvmf_tid **ioc_tids)
{
	struct dlp_entry *e;
	size_t i;

	/* Find the existing per-DC entry, if any. */
	for (e = c->dlp; e; e = e->next) {
		if (tid_same(e->dc_tid, dc_tid))
			break;
	}

	if (!e) {
		/*
		 * First DLP ever seen for this DC: allocate an entry and
		 * link it in, keyed by a private copy of dc_tid.
		 */
		e = calloc(1, sizeof(*e));
		if (!e)
			return;
		e->dc_tid = libnvmf_tid_dup(dc_tid);
		if (!e->dc_tid) {
			free(e);
			return;
		}
		e->next = c->dlp;
		c->dlp = e;
	} else {
		/*
		 * DLP refresh for a DC we already track: drop the
		 * previous IOC set before repopulating it below.
		 */
		tlist_free_items(&e->iocs);
	}

	/*
	 * Take ownership of ioc_tids: each TID moves into e->iocs, and
	 * the now-empty array itself is freed (per cache.h contract).
	 */
	if (ioc_tids) {
		for (i = 0; ioc_tids[i]; i++)
			tlist_append(&e->iocs, ioc_tids[i]);
		free(ioc_tids);
	}
}

/*
 * Drop the per-DC dlp_entry for dc_tid entirely (e.g. the DC was
 * removed from config on SIGHUP, or disconnected for good) - unlike
 * cache_update_dlp(), which replaces an entry's IOC set in place,
 * this removes the entry itself, key and all, from the dlp list.
 * A no-op if dc_tid has no entry.
 */
void cache_remove_dlp(struct cache *c, const struct libnvmf_tid *dc_tid)
{
	struct dlp_entry **ep, *e;

	for (ep = &c->dlp; *ep; ep = &(*ep)->next) {
		e = *ep;
		if (tid_same(e->dc_tid, dc_tid)) {
			*ep = e->next;
			tid_free(e->dc_tid);
			tlist_free_items(&e->iocs);
			free(e);
			return;
		}
	}
}

/*
 * Linear membership test: is t the same (per tid_same()) as any item
 * already in l?
 */
static bool tlist_contains(const struct tid_list *l,
			    const struct libnvmf_tid *t)
{
	size_t i;

	for (i = 0; i < l->len; i++) {
		if (tid_same(l->items[i], t))
			return true;
	}
	return false;
}

/*
 * Is t something discoverd should be (re)connecting? True if t is in
 * any of the four flat sets, or if t is itself a tracked DC (a key in
 * the dlp list), or if t is in any tracked DC's IOC set. This is the
 * union of every controller source discoverd knows about - NBFT,
 * config, and everything learned via DLP - and is the gate used
 * before reconnecting a dropped controller.
 */
bool cache_is_desired(const struct cache *c, const struct libnvmf_tid *t)
{
	struct dlp_entry *e;

	if (tlist_contains(&c->nbft_dcs, t) ||
	    tlist_contains(&c->nbft_iocs, t) ||
	    tlist_contains(&c->cfg_dcs, t) ||
	    tlist_contains(&c->cfg_iocs, t))
		return true;

	for (e = c->dlp; e; e = e->next) {
		if (tid_same(e->dc_tid, t))
			return true;
		if (tlist_contains(&e->iocs, t))
			return true;
	}
	return false;
}

/*
 * Is t firmware-sourced (present in nbft_dcs or nbft_iocs)? Used to
 * decide whether a reconnect should use --owner nbft instead of
 * --owner discoverd, preserving the NBFT ownership invariant.
 */
bool cache_is_nbft(const struct cache *c, const struct libnvmf_tid *t)
{
	return tlist_contains(&c->nbft_dcs, t) ||
	       tlist_contains(&c->nbft_iocs, t);
}

/*
 * Build the NULL-terminated, deduplicated list of every DC that
 * should be connected at startup: nbft_dcs union cfg_dcs. Does not
 * include DCs only known via the dlp list (those are reconnected via
 * unit RestartUnit, not from this startup list). Caller owns the
 * returned array and every TID in it.
 */
struct libnvmf_tid **cache_desired_dcs(const struct cache *c)
{
	struct tid_list combined = { 0 };
	struct libnvmf_tid **arr;
	size_t i;

	/* Merge nbft_dcs + cfg_dcs (deduplicated). */
	for (i = 0; i < c->nbft_dcs.len; i++) {
		struct libnvmf_tid *t = libnvmf_tid_dup(c->nbft_dcs.items[i]);

		if (t)
			tlist_append(&combined, t);
	}
	for (i = 0; i < c->cfg_dcs.len; i++) {
		if (!tlist_contains(&combined, c->cfg_dcs.items[i])) {
			struct libnvmf_tid *t = libnvmf_tid_dup(c->cfg_dcs.items[i]);

			if (t)
				tlist_append(&combined, t);
		}
	}

	arr = malloc((combined.len + 1) * sizeof(*arr));
	if (!arr) {
		tlist_free_items(&combined);
		return NULL;
	}
	for (i = 0; i < combined.len; i++)
		arr[i] = combined.items[i];
	arr[combined.len] = NULL;
	free(combined.items);
	return arr;
}

/*
 * Same as cache_desired_dcs(), but for IOCs: the NULL-terminated,
 * deduplicated union of nbft_iocs and cfg_iocs. DLP-sourced IOCs are
 * excluded for the same reason DLP-sourced DCs are excluded from
 * cache_desired_dcs() - they come back via unit restart, not a
 * startup list.
 */
struct libnvmf_tid **cache_desired_iocs(const struct cache *c)
{
	struct tid_list combined = { 0 };
	struct libnvmf_tid **arr;
	size_t i;

	for (i = 0; i < c->nbft_iocs.len; i++) {
		struct libnvmf_tid *t = libnvmf_tid_dup(c->nbft_iocs.items[i]);

		if (t)
			tlist_append(&combined, t);
	}
	for (i = 0; i < c->cfg_iocs.len; i++) {
		if (!tlist_contains(&combined, c->cfg_iocs.items[i])) {
			struct libnvmf_tid *t = libnvmf_tid_dup(c->cfg_iocs.items[i]);

			if (t)
				tlist_append(&combined, t);
		}
	}

	arr = malloc((combined.len + 1) * sizeof(*arr));
	if (!arr) {
		tlist_free_items(&combined);
		return NULL;
	}
	for (i = 0; i < combined.len; i++)
		arr[i] = combined.items[i];
	arr[combined.len] = NULL;
	free(combined.items);
	return arr;
}
