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

#include <nvme/fabrics.h>
#include <nvme/lib.h>
#include <nvme/nbft.h>
#include <nvme/util.h>

#include "ctx.h"
#include "inventory.h"
#include "log.h"

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

struct inventory {
	struct tid_list nbft_dcs;
	struct tid_list nbft_iocs;
	struct tid_list cfg_dcs;
	struct tid_list cfg_iocs;
	struct tid_list discovered_dcs; // found through mDNS or FC kickstart
	struct list_head dlp_cache;
	struct list_head cfg_conns;
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
	return inv;
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
	for (i = 0; tids[i]; i++)
		tid_list_append(l, tids[i]);
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
		 * previous entries before repopulating them below.
		 */
		tid_list_free_items(&e->iocs);
		tid_list_free_items(&e->referrals);
	}

	/* Take ownership of both arrays (per inventory.h contract). */
	tid_list_take(&e->iocs, iocs);
	tid_list_take(&e->referrals, referrals);
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
		if (!tid_list_contains(&combined, inv->cfg_dcs.items[i])) {
			struct libnvmf_tid *t =
				libnvmf_tid_dup(inv->cfg_dcs.items[i]);

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
				    host_traddr, NULL, nbft->host.nqn, hostid,
				    true);
			t = with_default_host(dctx, t);
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
				    host_traddr, NULL, nbft->host.nqn, hostid,
				    false);
			t = with_default_host(dctx, t);
			if (t)
				tid_list_append(&inv->nbft_iocs, t);
		}
	}
}

int inventory_load_nbft(struct inventory *inv,
			const struct discoverd_ctx *dctx)
{
	char *nbft_path = NBFT_SYSFS_PATH;
	struct nbft_file_entry *head = NULL;
	struct nbft_file_entry *e;
	int ret;

	ret = libnvmf_nbft_read_files(dctx->nvme_ctx, nbft_path, &head);
	if (ret)
		return 0; // no NBFT is not an error

	for (e = head; e; e = e->next)
		load_one_nbft(inv, dctx, e->nbft);

	libnvmf_nbft_free(dctx->nvme_ctx, head);
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

struct load_config_args {
	struct inventory *inv;
	const struct discoverd_ctx *dctx;
};

static void load_config_conn_callback(const struct libnvmf_config_conn *conn,
				   void *user_data)
{
	struct load_config_args *args = user_data;
	struct inventory *inv = args->inv;
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
		   libnvmf_config_conn_get_hostnqn(conn),
		   libnvmf_config_conn_get_hostid(conn), is_dc);
	t = with_default_host(args->dctx, t);
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
		       const struct discoverd_ctx *dctx)
{
	struct load_config_args args = { .inv = inv, .dctx = dctx };
	struct cfg_conn_entry *ce, *next;

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
