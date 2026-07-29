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

#include <ccan/list/list.h>

#include <array-util.h>
#include <nvme/fabrics.h>
#include <nvme/lib.h>
#include <nvme/nbft.h>

#include "inventory.h"
#include "log.h"

/* Simple growable TID array, backed by struct shr_ptrarray. */
SHR_PTRARRAY_DEFINE(tid_list, struct libnvmf_tid);

/* Per-DC DLP cache entry. */
struct dlp_entry {
	struct list_node entry;
	struct libnvmf_tid *dc_tid; // key
	struct tid_list iocs;       // value: IOC TIDs from last DLP fetch
};

/*
 * Pairs a statically-configured TID with the libnvmf_config_conn it came
 * from, so connect-time code can fetch that connection's own resolved
 * params instead of falling back to libnvmf_config_resolve_discovered().
 * conn is borrowed — valid only while the fabrics_cfg passed to
 * inventory_load_config() stays alive.
 */
struct cfg_conn_entry {
	struct list_node entry;
	struct libnvmf_tid *tid;
	const struct libnvmf_config_conn *conn;
};

struct inventory {
	struct tid_list nbft_dcs;
	struct tid_list nbft_iocs;
	struct tid_list cfg_dcs;
	struct tid_list cfg_iocs;
	struct list_head dlp_cache;
	struct list_head cfg_conns;
};

/* Free every TID in l, then the backing array, leaving l empty. */
static void tlist_free_items(struct tid_list *l)
{
	size_t i;

	for (i = 0; i < l->len; i++)
		tid_free(l->items[i]);
	tid_list_free(l);
}

/*
 * The four flat TID sets (nbft_dcs/nbft_iocs/cfg_dcs/cfg_iocs) have no key —
 * membership is a linear scan (tlist_contains()). dlp_cache is a map keyed
 * by DC TID, each entry holding that DC's last-fetched IOC set; lookups
 * (inventory_update_dlp(), inventory_remove_dlp(), inventory_is_desired())
 * walk it with tid_same(), not a hash or tree — fine given how few DCs are
 * tracked at once.
 */
struct inventory *inventory_new(void)
{
	struct inventory *inv = calloc(1, sizeof(*inv));

	if (!inv)
		return NULL;
	list_head_init(&inv->dlp_cache);
	list_head_init(&inv->cfg_conns);
	return inv;
}

/*
 * Free an inventory and everything in it: the four flat TID sets and
 * every per-DC dlp_entry (and that entry's own IOC set) in dlp_cache.
 */
void inventory_free(struct inventory *inv)
{
	struct dlp_entry *e, *next;
	struct cfg_conn_entry *ce, *cnext;

	if (!inv)
		return;
	tlist_free_items(&inv->nbft_dcs);
	tlist_free_items(&inv->nbft_iocs);
	tlist_free_items(&inv->cfg_dcs);
	tlist_free_items(&inv->cfg_iocs);
	list_for_each_safe(&inv->dlp_cache, e, next, entry) {
		tid_free(e->dc_tid);
		tlist_free_items(&e->iocs);
		free(e);
	}
	list_for_each_safe(&inv->cfg_conns, ce, cnext, entry) {
		tid_free(ce->tid);
		free(ce);
	}
	free(inv);
}

/*
 * Replace the IOC set learned from dc_tid's Discovery Log Page. Called
 * each time a DC's DLP is (re-)fetched, so this is a clean per-DC
 * replacement, not an incremental merge - any IOC that dropped out of
 * the new DLP simply disappears from the DLP cache for this DC.
 */
void inventory_update_dlp(struct inventory *inv,
			  const struct libnvmf_tid *dc_tid,
			  struct libnvmf_tid **ioc_tids)
{
	struct dlp_entry *e = NULL, *it;
	size_t i;

	/* Find the existing per-DC entry, if any. */
	list_for_each(&inv->dlp_cache, it, entry) {
		if (tid_same(it->dc_tid, dc_tid)) {
			e = it;
			break;
		}
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
		list_add(&inv->dlp_cache, &e->entry);
	} else {
		/*
		 * DLP refresh for a DC we already track: drop the
		 * previous IOC set before repopulating it below.
		 */
		tlist_free_items(&e->iocs);
	}

	/*
	 * Take ownership of ioc_tids: each TID moves into e->iocs, and
	 * the now-empty array itself is freed (per inventory.h contract).
	 */
	if (ioc_tids) {
		for (i = 0; ioc_tids[i]; i++)
			tid_list_append(&e->iocs, ioc_tids[i]);
		free(ioc_tids);
	}
}

/*
 * Drop the per-DC dlp_entry for dc_tid entirely (e.g. the DC was
 * removed from config on SIGHUP, or disconnected for good) - unlike
 * inventory_update_dlp(), which replaces an entry's IOC set in place,
 * this removes the entry itself, key and all, from dlp_cache.
 * A no-op if dc_tid has no entry.
 */
void inventory_remove_dlp(struct inventory *inv,
			  const struct libnvmf_tid *dc_tid)
{
	struct dlp_entry *e;

	list_for_each(&inv->dlp_cache, e, entry) {
		if (tid_same(e->dc_tid, dc_tid)) {
			list_del_init(&e->entry);
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
 * dlp_cache), or if t is in any tracked DC's IOC set. This is the
 * union of every controller source discoverd knows about - NBFT,
 * config, and everything learned via DLP - and is the gate used
 * before reconnecting a dropped controller.
 */
bool inventory_is_desired(const struct inventory *inv,
			  const struct libnvmf_tid *t)
{
	struct dlp_entry *e;

	if (tlist_contains(&inv->nbft_dcs, t) ||
	    tlist_contains(&inv->nbft_iocs, t) ||
	    tlist_contains(&inv->cfg_dcs, t) ||
	    tlist_contains(&inv->cfg_iocs, t))
		return true;

	list_for_each(&inv->dlp_cache, e, entry) {
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
bool inventory_is_nbft(const struct inventory *inv, const struct libnvmf_tid *t)
{
	return tlist_contains(&inv->nbft_dcs, t) ||
	       tlist_contains(&inv->nbft_iocs, t);
}

/*
 * Build the NULL-terminated, deduplicated list of every DC that
 * should be connected at startup: nbft_dcs union cfg_dcs. Does not
 * include DCs only known via dlp_cache (those are reconnected via
 * unit RestartUnit, not from this startup list). Caller owns the
 * returned array and every TID in it.
 */
struct libnvmf_tid **inventory_desired_dcs(const struct inventory *inv)
{
	struct tid_list combined = { 0 };
	struct libnvmf_tid **arr;
	size_t i;

	/* Merge nbft_dcs + cfg_dcs (deduplicated). */
	for (i = 0; i < inv->nbft_dcs.len; i++) {
		struct libnvmf_tid *t = libnvmf_tid_dup(inv->nbft_dcs.items[i]);

		if (t)
			tid_list_append(&combined, t);
	}
	for (i = 0; i < inv->cfg_dcs.len; i++) {
		if (!tlist_contains(&combined, inv->cfg_dcs.items[i])) {
			struct libnvmf_tid *t =
				libnvmf_tid_dup(inv->cfg_dcs.items[i]);

			if (t)
				tid_list_append(&combined, t);
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

#define NBFT_SYSFS_PATH "/sys/firmware/acpi/tables"

static void load_one_nbft(struct inventory *inv, struct libnbft_info *nbft)
{
	int i;

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
				tid_list_append(&inv->nbft_dcs, t);
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
				tid_list_append(&inv->nbft_iocs, t);
		}
	}
}

int inventory_load_nbft(struct inventory *inv,
			struct libnvme_global_ctx *nvme_ctx)
{
	char *nbft_path = NBFT_SYSFS_PATH;
	struct nbft_file_entry *head = NULL;
	struct nbft_file_entry *e;
	int ret;

	ret = libnvmf_nbft_read_files(nvme_ctx, nbft_path, &head);
	if (ret)
		return 0; // no NBFT is not an error

	for (e = head; e; e = e->next)
		load_one_nbft(inv, e->nbft);

	libnvmf_nbft_free(nvme_ctx, head);
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

static void load_config_conn_callback(const struct libnvmf_config_conn *conn,
				   void *user_data)
{
	struct inventory *inv = user_data;
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
	// for inventory_config_conn_for() lookups — each list owns its copy.
	t2 = libnvmf_tid_dup(t);
	if (!t2 ||
	    tid_list_append(is_dc ? &inv->cfg_dcs : &inv->cfg_iocs, t2) < 0) {
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
	list_add(&inv->cfg_conns, &ce->entry);
}

void inventory_load_config(struct inventory *inv,
		       const struct libnvmf_config *fabrics_cfg)
{
	struct cfg_conn_entry *ce, *next;

	tlist_free_items(&inv->cfg_dcs);
	tlist_free_items(&inv->cfg_iocs);
	list_for_each_safe(&inv->cfg_conns, ce, next, entry) {
		tid_free(ce->tid);
		free(ce);
	}
	list_head_init(&inv->cfg_conns);

	if (fabrics_cfg)
		libnvmf_config_conn_for_each(fabrics_cfg,
					     load_config_conn_callback, inv);

	disc_dbg("loaded %zu DC(s), %zu IOC(s) from the fabrics config",
		 inv->cfg_dcs.len, inv->cfg_iocs.len);
}

const struct libnvmf_config_conn *inventory_config_conn_for(
		const struct inventory *inv, const struct libnvmf_tid *t)
{
	struct cfg_conn_entry *ce;

	list_for_each(&inv->cfg_conns, ce, entry) {
		if (tid_same(ce->tid, t))
			return ce->conn;
	}
	return NULL;
}

/*
 * Same as inventory_desired_dcs(), but for IOCs: the NULL-terminated,
 * deduplicated union of nbft_iocs and cfg_iocs. DLP-sourced IOCs are
 * excluded for the same reason DLP-sourced DCs are excluded from
 * inventory_desired_dcs() - they come back via unit restart, not a
 * startup list.
 */
struct libnvmf_tid **inventory_desired_iocs(const struct inventory *inv)
{
	struct tid_list combined = { 0 };
	struct libnvmf_tid **arr;
	size_t i;

	for (i = 0; i < inv->nbft_iocs.len; i++) {
		struct libnvmf_tid *t =
			libnvmf_tid_dup(inv->nbft_iocs.items[i]);

		if (t)
			tid_list_append(&combined, t);
	}
	for (i = 0; i < inv->cfg_iocs.len; i++) {
		if (!tlist_contains(&combined, inv->cfg_iocs.items[i])) {
			struct libnvmf_tid *t =
				libnvmf_tid_dup(inv->cfg_iocs.items[i]);

			if (t)
				tid_list_append(&combined, t);
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
