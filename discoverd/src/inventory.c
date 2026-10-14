// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <ccan/list/list.h>

#include <daemon-util/log.h>
#include <daemon-util/resolve.h>
#include <nvme/fabrics.h>
#include <nvme/lib.h>
#include <nvme/nbft.h>
#include <nvme/util.h>

#include "ctx.h"
#include "inventory.h"

/* Per-DC DLP cache entry. */
struct dlp_entry {
	struct list_node entry;
	struct libnvmf_tid *dc_tid;  // key
	struct tid_list iocs;        // IOC entries from the last fetch
	struct tid_list referrals;   // referral entries from the last fetch
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

// The name lookup of a configured traddr: first try, then each retry.
#define LOOKUP_TIMEOUT_USEC	(10 * 1000000ULL)
#define LOOKUP_RETRY_MIN_SEC	1
#define LOOKUP_RETRY_MAX_SEC	300

/*
 * A configured connection whose traddr is a host name, until the name
 * resolves. conn is borrowed, as in cfg_conn_entry.
 */
struct cfg_lookup {
	struct list_node entry;
	struct inventory *inv;
	const struct discoverd_ctx *dctx;
	const struct libnvmf_config_conn *conn;
	struct dmn_resolve_query *query;
	sd_event_source *retry_timer;
	unsigned int retry_sec;
	bool first;	// the first lookup since the configuration was loaded
};

struct inventory {
	struct tid_list nbft_dcs;
	struct tid_list nbft_iocs;
	struct tid_list cfg_dcs;
	struct tid_list cfg_iocs;
	struct tid_list discovered_dcs; // found through mDNS or FC kickstart
	struct list_head dlp_cache;
	struct list_head cfg_conns;
	struct list_head lookups;
	unsigned int nr_first_lookups;	// first lookups not ended yet
	inventory_lookup_callback lookup_cb;
	void *lookup_data;
};

/*
 * The flat TID sets (nbft_dcs/nbft_iocs/cfg_dcs/cfg_iocs/discovered_dcs)
 * have no key — membership is a linear scan (tid_list_contains()). dlp_cache
 * is a map keyed by DC TID, each entry holding that DC's last-fetched
 * entries; lookups (inventory_update_dlp(), inventory_forget_dc(),
 * inventory_is_desired()) walk it with tid_same(), not a hash or tree —
 * fine given how few DCs are tracked at once.
 */
struct inventory *inventory_new(void)
{
	struct inventory *inv = calloc(1, sizeof(*inv));

	if (!inv)
		return NULL;
	list_head_init(&inv->dlp_cache);
	list_head_init(&inv->cfg_conns);
	list_head_init(&inv->lookups);
	return inv;
}

void inventory_set_lookup_callback(struct inventory *inv,
				   inventory_lookup_callback cb,
				   void *user_data)
{
	inv->lookup_cb = cb;
	inv->lookup_data = user_data;
}

static void lookup_free(struct cfg_lookup *l)
{
	list_del(&l->entry);
	dmn_resolve_cancel(l->query);
	sd_event_source_disable_unref(l->retry_timer);
	free(l);
}

// Stop every lookup, without calling the callback.
static void lookups_free(struct inventory *inv)
{
	struct cfg_lookup *l, *next;

	list_for_each_safe(&inv->lookups, l, next, entry)
		lookup_free(l);
	inv->nr_first_lookups = 0;
}

/*
 * Give @tid the daemon's default host if it names none. A candidate
 * without a host connects as the default host, and its TID must say so to
 * match the connection it makes. Frees @tid and returns NULL on failure.
 */
static struct libnvmf_tid *with_default_host(const struct discoverd_ctx *dctx,
					     struct libnvmf_tid *tid)
{
	if (tid && tid_set_default_host_if_unset(tid, dctx->hostnqn,
						 dctx->hostid) < 0) {
		tid_free(tid);
		return NULL;
	}

	return tid;
}

/*
 * Free an inventory and everything in it: the flat TID sets and every
 * per-DC dlp_entry (and that entry's own list) in dlp_cache.
 */
void inventory_free(struct inventory *inv)
{
	struct dlp_entry *e, *next;
	struct cfg_conn_entry *ce, *cnext;

	if (!inv)
		return;
	lookups_free(inv);
	tid_list_free_items(&inv->nbft_dcs);
	tid_list_free_items(&inv->nbft_iocs);
	tid_list_free_items(&inv->cfg_dcs);
	tid_list_free_items(&inv->cfg_iocs);
	tid_list_free_items(&inv->discovered_dcs);
	list_for_each_safe(&inv->dlp_cache, e, next, entry) {
		tid_free(e->dc_tid);
		tid_list_free_items(&e->iocs);
		tid_list_free_items(&e->referrals);
		free(e);
	}
	list_for_each_safe(&inv->cfg_conns, ce, cnext, entry) {
		tid_free(ce->tid);
		free(ce);
	}
	free(inv);
}

/* Move the NULL-terminated @tids into @l, and free the array. */
static void tid_list_take(struct tid_list *l, struct libnvmf_tid **tids)
{
	size_t i;

	if (!tids)
		return;
	for (i = 0; tids[i]; i++) {
		if (tid_list_append(l, tids[i]) < 0)
			tid_free(tids[i]);
	}
	free(tids);
}

/* Free the NULL-terminated @tids and every TID in it. */
static void tids_free(struct libnvmf_tid **tids)
{
	size_t i;

	if (!tids)
		return;
	for (i = 0; tids[i]; i++)
		tid_free(tids[i]);
	free(tids);
}

/*
 * Replace the entries learned from dc_tid's Discovery Log Page. Called
 * each time a DC's DLP is (re-)fetched, so this is a clean per-DC
 * replacement, not an incremental merge - any entry that dropped out of
 * the new DLP simply disappears from the DLP cache for this DC.
 */
void inventory_update_dlp(struct inventory *inv,
			  const struct libnvmf_tid *dc_tid,
			  struct libnvmf_tid **iocs,
			  struct libnvmf_tid **referrals)
{
	struct dlp_entry *e = NULL, *it;

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
			goto free_tids;
		e->dc_tid = libnvmf_tid_dup(dc_tid);
		if (!e->dc_tid) {
			free(e);
			goto free_tids;
		}
		list_add(&inv->dlp_cache, &e->entry);
	} else {
		/*
		 * DLP refresh for a DC we already track: drop the
		 * previous entries before repopulating them below.
		 */
		tid_list_free_items(&e->iocs);
		tid_list_free_items(&e->referrals);
	}

	/* Take ownership of both arrays (per inventory.h contract). */
	tid_list_take(&e->iocs, iocs);
	tid_list_take(&e->referrals, referrals);
	return;

free_tids:
	tids_free(iocs);
	tids_free(referrals);
}

/*
 * Linear membership test: is t the same (per tid_same()) as any item
 * already in l?
 */
static bool tid_list_contains(const struct tid_list *l,
			      const struct libnvmf_tid *t)
{
	size_t i;

	for (i = 0; i < l->len; i++) {
		if (tid_same(l->items[i], t))
			return true;
	}
	return false;
}

/* Remove the item of @l that is the same as @tid, if any. */
static void tid_list_remove(struct tid_list *l, const struct libnvmf_tid *tid)
{
	size_t i;

	for (i = 0; i < l->len; i++) {
		if (tid_same(l->items[i], tid)) {
			tid_free(l->items[i]);
			l->items[i] = l->items[--l->len];
			return;
		}
	}
}

void inventory_add_discovered_dc(struct inventory *inv,
				 const struct libnvmf_tid *tid)
{
	struct libnvmf_tid *dup;

	if (tid_list_contains(&inv->discovered_dcs, tid))
		return;

	dup = libnvmf_tid_dup(tid);
	if (dup && tid_list_append(&inv->discovered_dcs, dup) < 0)
		tid_free(dup);
}

/*
 * Forget a DC that nvme-discoverd gave up on: drop its dlp_entry, key and
 * all, and its place in discovered_dcs. A no-op for what @dc_tid is not in.
 */
void inventory_forget_dc(struct inventory *inv,
			 const struct libnvmf_tid *dc_tid)
{
	struct dlp_entry *e;

	tid_list_remove(&inv->discovered_dcs, dc_tid);

	list_for_each(&inv->dlp_cache, e, entry) {
		if (tid_same(e->dc_tid, dc_tid)) {
			list_del_init(&e->entry);
			tid_free(e->dc_tid);
			tid_list_free_items(&e->iocs);
			tid_list_free_items(&e->referrals);
			free(e);
			return;
		}
	}
}

/*
 * Hops from a DC with a source (NBFT, the configuration, or discovered)
 * to @tid through referral entries, but no more than @budget. Returns the
 * fewest hops, or -1 if @tid cannot be reached. The budget also ends a
 * referral loop.
 */
static int hops(const struct inventory *inv, const struct libnvmf_tid *tid,
		unsigned int budget)
{
	struct dlp_entry *e;
	int best = -1;

	if (tid_list_contains(&inv->nbft_dcs, tid) ||
	    tid_list_contains(&inv->cfg_dcs, tid) ||
	    tid_list_contains(&inv->discovered_dcs, tid))
		return 0;

	if (!budget)
		return -1;

	list_for_each(&inv->dlp_cache, e, entry) {
		int h;

		if (!tid_list_contains(&e->referrals, tid))
			continue;
		h = hops(inv, e->dc_tid, budget - 1);
		if (h >= 0 && (best < 0 || h + 1 < best))
			best = h + 1;
	}

	return best;
}

int inventory_referral_hops(const struct inventory *inv,
			    const struct libnvmf_tid *dc_tid)
{
	return hops(inv, dc_tid, INVENTORY_MAX_REFERRAL_HOPS);
}

/*
 * A cached DLP counts only while its DC is desired. So removing a DC from
 * its source also removes everything learned through it.
 */
const char *inventory_source(const struct inventory *inv,
			     const struct libnvmf_tid *tid,
			     const struct libnvmf_tid **parent)
{
	struct dlp_entry *e;

	*parent = NULL;
	if (tid_list_contains(&inv->nbft_dcs, tid) ||
	    tid_list_contains(&inv->nbft_iocs, tid))
		return "nbft";
	if (tid_list_contains(&inv->cfg_dcs, tid) ||
	    tid_list_contains(&inv->cfg_iocs, tid))
		return "config";
	if (tid_list_contains(&inv->discovered_dcs, tid))
		return "discovered";

	list_for_each(&inv->dlp_cache, e, entry) {
		if ((tid_list_contains(&e->iocs, tid) ||
		     tid_list_contains(&e->referrals, tid)) &&
		    inventory_referral_hops(inv, e->dc_tid) >= 0) {
			*parent = e->dc_tid;
			return "dlp";
		}
	}
	return NULL;
}

bool inventory_is_desired(const struct inventory *inv,
			  const struct libnvmf_tid *t)
{
	struct dlp_entry *e;

	if (tid_list_contains(&inv->nbft_iocs, t) ||
	    tid_list_contains(&inv->cfg_iocs, t) ||
	    inventory_referral_hops(inv, t) >= 0)
		return true;

	list_for_each(&inv->dlp_cache, e, entry) {
		if (tid_list_contains(&e->iocs, t) &&
		    inventory_referral_hops(inv, e->dc_tid) >= 0)
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
	return tid_list_contains(&inv->nbft_dcs, t) ||
	       tid_list_contains(&inv->nbft_iocs, t);
}

/*
 * Build the NULL-terminated, deduplicated list of every DC that
 * should be connected at startup: nbft_dcs, cfg_dcs and discovered_dcs.
 * Does not include DCs only known via dlp_cache (those are reconnected
 * via unit RestartUnit, not from this startup list). Caller owns the
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
		if (!tid_list_contains(&combined, inv->cfg_dcs.items[i])) {
			struct libnvmf_tid *t =
				libnvmf_tid_dup(inv->cfg_dcs.items[i]);

			if (t)
				tid_list_append(&combined, t);
		}
	}
	for (i = 0; i < inv->discovered_dcs.len; i++) {
		const struct libnvmf_tid *dc = inv->discovered_dcs.items[i];
		struct libnvmf_tid *tid;

		if (tid_list_contains(&combined, dc))
			continue;
		tid = libnvmf_tid_dup(dc);
		if (tid)
			tid_list_append(&combined, tid);
	}

	arr = malloc((combined.len + 1) * sizeof(*arr));
	if (!arr) {
		tid_list_free_items(&combined);
		return NULL;
	}
	for (i = 0; i < combined.len; i++)
		arr[i] = combined.items[i];
	arr[combined.len] = NULL;
	free(combined.items);
	return arr;
}

static bool uuid_is_null(const unsigned char uuid[NVME_UUID_LEN])
{
	static const unsigned char null_uuid[NVME_UUID_LEN];

	return !memcmp(uuid, null_uuid, sizeof(null_uuid));
}

/*
 * The hostid from the NBFT's Host Descriptor, as the boot connections used
 * it, written to @buf. Returns @buf, or NULL if the firmware left the Host
 * ID empty.
 */
static const char *nbft_hostid(const struct libnbft_info *nbft,
			       char buf[NVME_UUID_LEN_STRING])
{
	if (uuid_is_null(nbft->host.id))
		return NULL;
	if (libnvme_uuid_to_string(nbft->host.id, buf))
		return NULL;

	return buf;
}

static void load_one_nbft(struct inventory *inv,
			  const struct discoverd_ctx *dctx,
			  struct libnbft_info *nbft)
{
	char hostid_buf[NVME_UUID_LEN_STRING];
	const char *hostid = nbft_hostid(nbft, hostid_buf);
	int i;

	if (nbft->discovery_list) {
		for (i = 0; nbft->discovery_list[i]; i++) {
			struct libnbft_discovery *d = nbft->discovery_list[i];
			struct libnvmf_uri *uri = NULL;
			__cleanup_free char *trsvcid = NULL;
			const char *transport, *traddr;
			struct libnvmf_tid *t;
			int port;

			if (!d->hfi || !d->nqn)
				continue;
			if (libnvmf_uri_parse(d->uri, &uri) < 0)
				continue;

			// The Boot Specification requires the transport.
			transport = libnvmf_uri_get_protocol(uri);
			traddr = libnvmf_uri_get_host(uri);
			port = libnvmf_uri_get_port(uri);
			if (!transport || !traddr ||
			    (port > 0 && asprintf(&trsvcid, "%d", port) < 0)) {
				libnvmf_uri_free(uri);
				continue;
			}

			t = tid_new(transport, traddr, trsvcid, d->nqn,
				    d->hfi->tcp_info.ipaddr, NULL,
				    nbft->host.nqn, hostid, true);
			t = with_default_host(dctx, t);
			libnvmf_uri_free(uri);
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
				    host_traddr, NULL, nbft->host.nqn, hostid,
				    false);
			t = with_default_host(dctx, t);
			if (t)
				tid_list_append(&inv->nbft_iocs, t);
		}
	}
}

int inventory_load_nbft(struct inventory *inv,
			const struct discoverd_ctx *dctx, char *path)
{
	struct nbft_file_entry *head = NULL;
	struct nbft_file_entry *e;
	int ret;

	ret = libnvmf_nbft_read_files(dctx->nvme_ctx, path, &head);
	if (ret)
		return 0; // no NBFT is not an error

	for (e = head; e; e = e->next)
		load_one_nbft(inv, dctx, e->nbft);

	libnvmf_nbft_free(dctx->nvme_ctx, head);
	return 0;
}

/*
 * Add the configured connection @conn, with @traddr as its numeric
 * address. Returns false if the connection cannot be added.
 */
static bool add_config_conn(struct inventory *inv,
		const struct discoverd_ctx *dctx,
		const struct libnvmf_config_conn *conn, const char *traddr)
{
	bool is_dc = libnvmf_config_conn_is_dc(conn);
	struct libnvmf_tid *t, *t2;
	struct cfg_conn_entry *ce;

	t = tid_new(libnvmf_config_conn_get_transport(conn), traddr,
		   libnvmf_config_conn_get_trsvcid(conn),
		   libnvmf_config_conn_get_subsysnqn(conn),
		   libnvmf_config_conn_get_host_traddr(conn),
		   libnvmf_config_conn_get_host_iface(conn),
		   libnvmf_config_conn_get_hostnqn(conn),
		   libnvmf_config_conn_get_hostid(conn), is_dc);
	t = with_default_host(dctx, t);
	if (!t)
		return false;

	// t2 feeds the plain membership set; t is kept (paired with conn)
	// for inventory_config_conn_for() lookups — each list owns its copy.
	t2 = libnvmf_tid_dup(t);
	if (!t2 ||
	    tid_list_append(is_dc ? &inv->cfg_dcs : &inv->cfg_iocs, t2) < 0) {
		tid_free(t2);
		tid_free(t);
		return false;
	}

	ce = calloc(1, sizeof(*ce));
	if (!ce) {
		tid_free(t);
		return false;
	}
	ce->tid = t;
	ce->conn = conn;
	list_add(&inv->cfg_conns, &ce->entry);

	return true;
}

static int start_lookup(struct cfg_lookup *l);

static int retry_lookup(sd_event_source *src __attribute__((unused)),
			uint64_t usec __attribute__((unused)), void *user_data)
{
	struct cfg_lookup *l = user_data;

	l->retry_timer = sd_event_source_disable_unref(l->retry_timer);
	start_lookup(l);

	return 0;
}

static void schedule_lookup_retry(struct cfg_lookup *l)
{
	int r;

	r = sd_event_add_time_relative(l->dctx->event, &l->retry_timer,
				       CLOCK_MONOTONIC,
				       l->retry_sec * 1000000ULL, 0,
				       retry_lookup, l);
	if (r < 0) {
		log_warn("%s - cannot schedule a new lookup: %s",
			 libnvmf_config_conn_get_traddr(l->conn),
			 strerror(-r));
		return;
	}
	if (l->retry_sec < LOOKUP_RETRY_MAX_SEC)
		l->retry_sec *= 2;
	if (l->retry_sec > LOOKUP_RETRY_MAX_SEC)
		l->retry_sec = LOOKUP_RETRY_MAX_SEC;
}

/* The first address of @res, as a numeric string in @buf. */
static const char *first_addr(const struct addrinfo *res, char *buf,
			      size_t size)
{
	const struct sockaddr_in6 *sin6;
	const struct sockaddr_in *sin;

	for (; res; res = res->ai_next) {
		if (res->ai_family == AF_INET) {
			sin = (const struct sockaddr_in *)res->ai_addr;
			return inet_ntop(AF_INET, &sin->sin_addr, buf, size);
		}
		if (res->ai_family == AF_INET6) {
			sin6 = (const struct sockaddr_in6 *)res->ai_addr;
			return inet_ntop(AF_INET6, &sin6->sin6_addr, buf, size);
		}
	}

	return NULL;
}

static void on_lookup(int gai, const struct addrinfo *res, void *user_data)
{
	struct cfg_lookup *l = user_data;
	struct inventory *inv = l->inv;
	const char *name = libnvmf_config_conn_get_traddr(l->conn);
	char addrstr[INET6_ADDRSTRLEN];
	int err = errno;	// for EAI_SYSTEM
	bool first = l->first;
	bool added = false;
	const char *addr;

	l->query = NULL;
	if (first) {
		l->first = false;
		inv->nr_first_lookups--;
	}

	addr = gai ? NULL : first_addr(res, addrstr, sizeof(addrstr));
	if (addr) {
		log_info("%s - resolved to %s", name, addr);
		added = add_config_conn(inv, l->dctx, l->conn, addr);
		lookup_free(l);
	} else {
		const char *why = gai == EAI_SYSTEM ? strerror(err) :
				  gai ? gai_strerror(gai) : "no IP address";

		if (first)
			log_warn("%s - failed to resolve: %s, trying again",
				 name, why);
		else
			log_dbg("%s - failed to resolve: %s", name, why);
		schedule_lookup_retry(l);
	}

	if (inv->lookup_cb)
		inv->lookup_cb(added, inv->lookup_data);
}

static int start_lookup(struct cfg_lookup *l)
{
	static const struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};
	const char *name = libnvmf_config_conn_get_traddr(l->conn);
	int r;

	r = dmn_resolve(l->dctx->resolver, name, NULL, &hints,
			LOOKUP_TIMEOUT_USEC, on_lookup, l, &l->query);
	if (r < 0) {
		log_warn("%s - cannot start the lookup: %s", name,
			 strerror(-r));
		schedule_lookup_retry(l);
	}

	return r;
}

/* Resolve the host name of @conn without blocking. */
static void add_lookup(struct inventory *inv, const struct discoverd_ctx *dctx,
		       const struct libnvmf_config_conn *conn)
{
	struct cfg_lookup *l;

	if (!dctx->resolver) {
		log_warn("%s - cannot resolve, skipping",
			 libnvmf_config_conn_get_traddr(conn));
		return;
	}

	l = calloc(1, sizeof(*l));
	if (!l)
		return;
	l->inv = inv;
	l->dctx = dctx;
	l->conn = conn;
	l->retry_sec = LOOKUP_RETRY_MIN_SEC;
	list_add_tail(&inv->lookups, &l->entry);

	if (!start_lookup(l)) {
		l->first = true;
		inv->nr_first_lookups++;
	}
}

struct load_config_args {
	struct inventory *inv;
	const struct discoverd_ctx *dctx;
};

static void load_config_conn_callback(const struct libnvmf_config_conn *conn,
				   void *user_data)
{
	struct load_config_args *args = user_data;
	const char *transport = libnvmf_config_conn_get_transport(conn);
	const char *traddr = libnvmf_config_conn_get_traddr(conn);

	if (libnvmf_traddr_is_numeric(traddr)) {
		add_config_conn(args->inv, args->dctx, conn, traddr);
		return;
	}

	// A host name exists only for tcp and rdma.
	if (strcmp(transport, "tcp") && strcmp(transport, "rdma")) {
		log_warn("%s - failed to resolve, skipping", traddr);
		return;
	}

	add_lookup(args->inv, args->dctx, conn);
}

void inventory_load_config(struct inventory *inv,
		       const struct discoverd_ctx *dctx)
{
	struct load_config_args args = { .inv = inv, .dctx = dctx };
	struct cfg_conn_entry *ce, *next;

	lookups_free(inv);
	tid_list_free_items(&inv->cfg_dcs);
	tid_list_free_items(&inv->cfg_iocs);
	list_for_each_safe(&inv->cfg_conns, ce, next, entry) {
		tid_free(ce->tid);
		free(ce);
	}
	list_head_init(&inv->cfg_conns);

	if (dctx->fabrics_cfg)
		libnvmf_config_conn_for_each(dctx->fabrics_cfg,
					     load_config_conn_callback, &args);

	log_dbg("fabrics config: %zu DC(s), %zu IOC(s), %u name lookup(s)",
		inv->cfg_dcs.len, inv->cfg_iocs.len, inv->nr_first_lookups);
}

bool inventory_config_pending(const struct inventory *inv)
{
	return inv->nr_first_lookups > 0;
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
		if (!tid_list_contains(&combined, inv->cfg_iocs.items[i])) {
			struct libnvmf_tid *t =
				libnvmf_tid_dup(inv->cfg_iocs.items[i]);

			if (t)
				tid_list_append(&combined, t);
		}
	}

	arr = malloc((combined.len + 1) * sizeof(*arr));
	if (!arr) {
		tid_list_free_items(&combined);
		return NULL;
	}
	for (i = 0; i < combined.len; i++)
		arr[i] = combined.items[i];
	arr[combined.len] = NULL;
	free(combined.items);
	return arr;
}
