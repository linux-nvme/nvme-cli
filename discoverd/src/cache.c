// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef NVME_HAVE_NETDB
#include <netdb.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#include <nvme/lib.h>
#include <nvme/nbft.h>

#include "cache.h"
#include "log.h"

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
 * Pairs a statically-configured TID with the libnvmf_config_conn it came
 * from, so connect-time code can fetch that connection's own resolved
 * params instead of falling back to libnvmf_config_resolve_discovered().
 * conn is borrowed — valid only while the fabrics_cfg passed to
 * cache_load_config() stays alive.
 */
struct cfg_conn_entry {
	struct cfg_conn_entry *next;
	struct libnvmf_tid *tid;
	const struct libnvmf_config_conn *conn;
};

struct cache {
	struct tid_list nbft_dcs;
	struct tid_list nbft_iocs;
	struct tid_list cfg_dcs;
	struct tid_list cfg_iocs;
	struct dlp_entry *dlp;
	struct cfg_conn_entry *cfg_conns;
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
	struct cfg_conn_entry *ce, *cnext;

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
	for (ce = c->cfg_conns; ce; ce = cnext) {
		cnext = ce->next;
		tid_free(ce->tid);
		free(ce);
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
 * Extract the host address from an NVMe URI of the form
 * "nvme+transport://host:port/..." or "nvme+transport://host/...".
 * Returns an allocated string or NULL.
 */
static char *uri_host(const char *uri)
{
	const char *p, *end;

	if (!uri)
		return NULL;
	p = strstr(uri, "://");
	if (!p)
		return NULL;
	p += 3;
	end = strpbrk(p, ":/");
	return end ? strndup(p, (size_t)(end - p)) : strdup(p);
}

static char *uri_port(const char *uri)
{
	const char *p, *end;

	if (!uri)
		return NULL;
	p = strstr(uri, "://");
	if (!p)
		return NULL;
	p += 3;
	p = strchr(p, ':');
	if (!p)
		return NULL;
	p++;
	end = strchr(p, '/');
	return end ? strndup(p, (size_t)(end - p)) : strdup(p);
}

/*
 * Boot Spec 1.5.7 / Figure 20: <PROTOCOL> (the "+<trtype>" part of the
 * scheme) is mandatory in an NVMe-oF URI. Returns NULL if uri is NULL or
 * the "+<trtype>" segment is missing — callers must treat a present-but-
 * malformed URI as invalid, not default the transport.
 */
static char *uri_transport(const char *uri)
{
	const char *plus, *end;

	if (!uri)
		return NULL;
	plus = strchr(uri, '+');
	if (!plus)
		return NULL;
	plus++;
	end = strstr(plus, "://");
	return end ? strndup(plus, (size_t)(end - plus)) : strdup(plus);
}

int cache_load_nbft(struct cache *c, struct libnvme_global_ctx *nvme_ctx)
{
	struct libnbft_info *nbft = NULL;
	int ret, i;

	ret = libnvmf_read_nbft(nvme_ctx, &nbft, NULL);
	if (ret)
		return 0; // no NBFT is not an error

	if (nbft->discovery_list) {
		for (i = 0; nbft->discovery_list[i]; i++) {
			struct libnbft_discovery *d = nbft->discovery_list[i];
			struct libnvmf_tid *t;
			char *traddr, *trsvcid, *transport;
			const char *host_traddr = NULL;

			if (!d->hfi || !d->nqn)
				continue;

			// Reject a malformed or incomplete URI.
			transport = uri_transport(d->uri);
			if (!transport)
				continue;

			traddr = uri_host(d->uri);
			if (!traddr) {
				free(transport);
				continue;
			}

			trsvcid = uri_port(d->uri); // optional: NULL ok
			host_traddr = d->hfi->tcp_info.ipaddr;

			t = tid_new(transport, traddr, trsvcid, d->nqn,
				    host_traddr, NULL, NULL, true);
			free(traddr);
			free(trsvcid);
			free(transport);
			if (t)
				tlist_append(&c->nbft_dcs, t);
		}
	}

	if (nbft->subsystem_ns_list) {
		for (i = 0; nbft->subsystem_ns_list[i]; i++) {
			struct libnbft_subsystem_ns *ns =
				nbft->subsystem_ns_list[i];
			struct libnvmf_tid *t;
			const char *host_traddr = NULL;

			if (ns->hfis && ns->hfis[0])
				host_traddr = ns->hfis[0]->tcp_info.ipaddr;

			t = tid_new(ns->transport, ns->traddr,
				    ns->trsvcid, ns->subsys_nqn,
				    host_traddr, NULL, NULL, false);
			if (t)
				tlist_append(&c->nbft_iocs, t);
		}
	}

	libnvmf_free_nbft(nvme_ctx, nbft);
	return 0;
}

/*
 * Resolve traddr to a numeric address if it names a tcp/rdma hostname.
 * libnvmf_config_conn_get_traddr() never returns a hostname for FC (no
 * hostname concept there), and an already-numeric address is returned
 * unchanged. Deliberately blocking and sequential, one getaddrinfo() call
 * at a time, no worker thread: config load runs once at startup and, more
 * rarely, on SIGHUP — a rare, small path, not the daemon's steady-state
 * event loop, so a blocking resolve here is acceptable.
 * Returns an allocated numeric-address string, or NULL if traddr is not
 * numeric and cannot be resolved.
 */
static char *resolve_traddr(const char *transport, const char *traddr)
{
	if (libnvmf_traddr_is_numeric(traddr))
		return strdup(traddr);

#ifdef NVME_HAVE_NETDB
	struct addrinfo hints = { .ai_family = AF_UNSPEC };
	struct addrinfo *host_info = NULL;
	char addrstr[NVMF_TRADDR_SIZE];
	const char *p = NULL;
	char *resolved = NULL;
	int ret;

	if (strcmp(transport, "tcp") && strcmp(transport, "rdma"))
		return NULL;

	ret = getaddrinfo(traddr, NULL, &hints, &host_info);
	if (ret) {
		disc_warn("failed to resolve host '%s': %s",
			  traddr, gai_strerror(ret));
		return NULL;
	}

	switch (host_info->ai_family) {
	case AF_INET:
		p = inet_ntop(AF_INET,
			&((struct sockaddr_in *)host_info->ai_addr)->sin_addr,
			addrstr, sizeof(addrstr));
		break;
	case AF_INET6:
		p = inet_ntop(AF_INET6,
			&((struct sockaddr_in6 *)host_info->ai_addr)->sin6_addr,
			addrstr, sizeof(addrstr));
		break;
	default:
		break;
	}
	if (p)
		resolved = strdup(addrstr);

	freeaddrinfo(host_info);
	return resolved;
#else
	disc_warn("cannot resolve host '%s': hostname resolution not available "
		  "in this build", traddr);
	return NULL;
#endif
}

static void load_config_conn_cback(const struct libnvmf_config_conn *conn,
				   void *user_data)
{
	struct cache *c = user_data;
	const char *transport = libnvmf_config_conn_get_transport(conn);
	const char *raw_traddr = libnvmf_config_conn_get_traddr(conn);
	bool is_dc = libnvmf_config_conn_is_dc(conn);
	char *traddr;
	struct libnvmf_tid *t, *t2;
	struct cfg_conn_entry *ce;

	traddr = resolve_traddr(transport, raw_traddr);
	if (!traddr) {
		disc_warn("%s - failed to resolve, skipping", raw_traddr);
		return;
	}

	t = tid_new(transport, traddr,
		   libnvmf_config_conn_get_trsvcid(conn),
		   libnvmf_config_conn_get_subsysnqn(conn),
		   libnvmf_config_conn_get_host_traddr(conn),
		   libnvmf_config_conn_get_host_iface(conn),
		   libnvmf_config_conn_get_hostnqn(conn), is_dc);
	free(traddr);
	if (!t)
		return;

	// t2 feeds the plain membership set; t is kept (paired with conn)
	// for cache_config_conn_for() lookups — each list owns its copy.
	t2 = libnvmf_tid_dup(t);
	if (!t2 || tlist_append(is_dc ? &c->cfg_dcs : &c->cfg_iocs, t2) < 0) {
		tid_free(t2);
		tid_free(t);
		return;
	}

	ce = calloc(1, sizeof(*ce));
	if (!ce) {
		tid_free(t);
		return;
	}
	ce->tid = t;
	ce->conn = conn;
	ce->next = c->cfg_conns;
	c->cfg_conns = ce;
}

void cache_load_config(struct cache *c,
		       const struct libnvmf_config *fabrics_cfg)
{
	struct cfg_conn_entry *ce, *next;

	tlist_free_items(&c->cfg_dcs);
	tlist_free_items(&c->cfg_iocs);
	for (ce = c->cfg_conns; ce; ce = next) {
		next = ce->next;
		tid_free(ce->tid);
		free(ce);
	}
	c->cfg_conns = NULL;

	if (fabrics_cfg)
		libnvmf_config_conn_for_each(fabrics_cfg,
					     load_config_conn_cback, c);

	disc_dbg("loaded %zu DC(s), %zu IOC(s) from the fabrics config",
		 c->cfg_dcs.len, c->cfg_iocs.len);
}

const struct libnvmf_config_conn *cache_config_conn_for(
		const struct cache *c, const struct libnvmf_tid *t)
{
	struct cfg_conn_entry *ce;

	for (ce = c->cfg_conns; ce; ce = ce->next) {
		if (tid_same(ce->tid, t))
			return ce->conn;
	}
	return NULL;
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
