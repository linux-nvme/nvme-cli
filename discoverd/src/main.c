// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-device.h>
#include <systemd/sd-event.h>

#include <ccan/list/list.h>
#include <ccan/str/str.h>

#include <shared/array-util.h>
#include <shared/cleanup-util.h>
#include <shared/string-util.h>
#include <shared/time-util.h>
#include <nvme/config.h>
#include <nvme/exclusion.h>
#include <nvme/fabrics.h>
#include <nvme/lib.h>
#include <nvme/registry.h>
#include <nvme/util.h>

#include "inventory.h"
#include "config.h"
#include "ctx.h"
#include "dlp.h"
#include "events.h"
#include "fc.h"
#include "log.h"
#include "mdns.h"
#include "state.h"
#include "tid.h"
#include "units.h"

// Exponential backoff for failed (re)connect attempts: 1s, 2s, 4s, ... capped
// at 5 min. A dynamically-discovered DC (not NBFT- or config-sourced — a
// referral or FC-kickstart find) additionally gives up after
// dc-giveup-timeout (default 72hours) of unbroken failure and is dropped
// from tracking, since nothing but its own retries vouches for it any more.
// Static and NBFT-sourced DCs represent deliberate admin/firmware intent
// and always retry forever.
#define RETRY_INITIAL_DELAY_SEC 1
#define RETRY_MAX_DELAY_SEC     300

struct active_ctrl {
	struct list_node entry;
	char *unit_name;    // "nvme-discoverd-<12hex>.service"
	char *devname;      // "nvmeX"; NULL until confirmed in sysfs
	struct libnvmf_tid *tid;
	bool is_dc;
	unsigned int attempts;   // consecutive failed (re)connect attempts
	uint64_t giveup_at_usec; // 0 = no deadline armed (ctrl_arm_giveup)
	sd_event_source *retry_timer; // NULL when no retry pending

	/*
	 * EPCSD this DC's own referral entry carried in its parent's
	 * Discovery Log Page, if this DC was reached via referral. Fallback
	 * for when this DC's own self entry (SUBTYPE 03h) turns out to be
	 * absent from its own Discovery Log Page. Unset for primary DCs
	 * (statically configured, mDNS-discovered, or NBFT) — they have no
	 * parent.
	 */
	bool parent_epcsd_known;
	bool parent_epcsd; // meaningful only if parent_epcsd_known

	// This DC's resolved "persistent" setting is "force": keep it
	// connected regardless of what its own EPCSD bit reports.
	bool force_persistent;
	bool force_persistent_logged; // disc_info_once() marker

	sd_event_source *epcsd_poll_timer; // NULL when not EPCSD-parked

	// Desired at the last release_undesired() pass, see there.
	bool desired;

	// A DC whose DLP was fetched since nvme-discoverd started.
	bool dlp_fetched;
};

/*
 * A controller from the file of last known desired controllers that is
 * not decided yet. See decide_saved().
 */
struct saved_ctrl {
	struct list_node entry;
	char *source;
	struct libnvmf_tid *tid;
	struct libnvmf_tid *parent; // the DC that listed it, for "dlp"
};

static LIST_HEAD(g_saved);

static LIST_HEAD(g_ctrls);
static struct discoverd_ctx ctx;

static struct active_ctrl *ctrl_find_by_unit(const char *unit_name)
{
	struct active_ctrl *e;

	list_for_each(&g_ctrls, e, entry) {
		if (streq(e->unit_name, unit_name))
			return e;
	}
	return NULL;
}

static struct active_ctrl *ctrl_find_by_devname(const char *devname)
{
	struct active_ctrl *e;

	list_for_each(&g_ctrls, e, entry) {
		if (shr_streq0(e->devname, devname))
			return e;
	}
	return NULL;
}

static void ctrl_free(struct active_ctrl *e)
{
	if (!e)
		return;
	sd_event_source_unref(e->retry_timer);
	sd_event_source_unref(e->epcsd_poll_timer);
	tid_free(e->tid);
	free(e->unit_name);
	free(e->devname);
	free(e);
}

static void schedule_release(bool check_exclusions);

static int ctrl_add(const char *unit_name, const struct libnvmf_tid *t,
		    bool is_dc, const struct libnvmf_params *params)
{
	struct active_ctrl *e;

	if (ctrl_find_by_unit(unit_name))
		return 0; // already tracked

	e = calloc(1, sizeof(*e));
	if (!e)
		return -ENOMEM;

	e->unit_name = strdup(unit_name);
	e->tid = libnvmf_tid_dup(t);
	e->is_dc = is_dc;
	e->desired = inventory_is_desired(ctx.inventory, t);
	e->force_persistent = params &&
		shr_streqcase0(libnvmf_params_get(params, "persistent"),
			       "force");
	if (!e->unit_name || !e->tid) {
		ctrl_free(e);
		return -ENOMEM;
	}

	list_add(&g_ctrls, &e->entry);
	schedule_release(false); // the saved desired set changes
	return 0;
}

static void ctrl_remove(struct active_ctrl *entry)
{
	list_del_init(&entry->entry);
	ctrl_free(entry);
	schedule_release(false); // the saved desired set changes
}

/*
 * Release @unit_name's controller, and leave its connection up. The state
 * goes first, so that the unit's ExecStop= has nothing to disconnect. Then
 * the unit is stopped and the registry owner is cleared. @devname may be
 * NULL when the controller is not connected.
 */
static void release_unit(const char *unit_name, const char *devname,
			 const struct libnvmf_tid *tid, const char *reason)
{
	state_remove_devid(unit_name);
	if (devname) {
		__cleanup_free char *owner_unit = state_read_unit(devname);

		if (shr_streq0(owner_unit, unit_name))
			state_remove_ctrl(devname);
	}

	if (unit_exists(ctx.umgr, unit_name))
		unit_stop(ctx.umgr, unit_name);

	/* Only clear an owner that is still ours. */
	if (devname &&
	    !libnvmf_registry_attr_equal(ctx.nvme_ctx, devname, "owner",
					 "discoverd"))
		libnvmf_registry_update(ctx.nvme_ctx, devname, "owner", NULL);

	disc_info("%s | %s - %s, released", libnvmf_tid_str(tid),
		  devname ? devname : "-", reason);
}

/* Release a tracked controller, and stop tracking it. */
static void ctrl_release(struct active_ctrl *e, const char *reason)
{
	__cleanup_free char *read_devname = NULL;
	const char *devname = e->devname;

	if (!devname)
		devname = read_devname = unit_read_devid(e->unit_name);

	release_unit(e->unit_name, devname, e->tid, reason);
	ctrl_remove(e);
}

static bool devname_matches_tid(const char *devname,
				const struct libnvmf_tid *tid);

static void saved_free(struct saved_ctrl *s)
{
	list_del_init(&s->entry);
	free(s->source);
	tid_free(s->tid);
	tid_free(s->parent);
	free(s);
}

/*
 * Decide a saved controller that nvme-discoverd did not adopt at startup.
 * Returns true when it is decided, and false while it waits for the DLP of
 * the DC that listed it.
 */
static bool decide_saved(struct saved_ctrl *s)
{
	__cleanup_free char *unit_name = tid_unit_name(s->tid);
	__cleanup_free char *devname = NULL;

	if (!unit_name || ctrl_find_by_unit(unit_name) ||
	    inventory_is_desired(ctx.inventory, s->tid))
		return true;

	if (streq(s->source, "dlp") && s->parent &&
	    inventory_is_desired(ctx.inventory, s->parent)) {
		__cleanup_free char *dc_unit = tid_unit_name(s->parent);
		struct active_ctrl *dc = dc_unit ?
			ctrl_find_by_unit(dc_unit) : NULL;

		if (!dc || !dc->dlp_fetched)
			return false;
	}

	/* The kernel reuses device names: check it is still this one. */
	devname = unit_read_devid(unit_name);
	if (devname && !devname_matches_tid(devname, s->tid)) {
		free(devname);
		devname = NULL;
	}

	/* No unit and no connection: nothing is left to release. */
	if (!devname && !unit_exists(ctx.umgr, unit_name))
		return true;

	release_unit(unit_name, devname, s->tid,
		     "no longer desired since the last run");
	return true;
}

/*
 * Rewrite the file of last known desired controllers: the tracked
 * controllers that are desired, and the saved ones not decided yet.
 */
static void save_desired(void)
{
	__cleanup_free char *content = NULL;
	struct active_ctrl *e;
	struct saved_ctrl *s;
	size_t size = 0;
	FILE *f;
	int r;

	f = open_memstream(&content, &size);
	if (!f)
		return;

	list_for_each(&g_ctrls, e, entry) {
		const struct libnvmf_tid *parent;
		const char *source;

		if (!e->desired)
			continue;
		source = inventory_source(ctx.inventory, e->tid, &parent);
		if (!source)
			continue;
		fprintf(f, "%s\t%s\t%s\n", source,
			libnvmf_tid_get_canonical(e->tid),
			parent ? libnvmf_tid_get_canonical(parent) : "-");
	}
	list_for_each(&g_saved, s, entry)
		fprintf(f, "%s\t%s\t%s\n", s->source,
			libnvmf_tid_get_canonical(s->tid),
			s->parent ? libnvmf_tid_get_canonical(s->parent) : "-");

	if (fclose(f) != 0)
		return;

	r = state_write_desired(content);
	if (r < 0)
		disc_warn("cannot save the desired controllers: %s",
			  strerror(-r));
}

/*
 * Read the file of last known desired controllers. Discovered DCs become
 * desired again, as they were before the restart. The others wait in
 * g_saved for decide_saved().
 */
static void load_saved(void)
{
	__cleanup_free char *content = state_read_desired();
	char *line, *next;

	for (line = content; line && *line; line = next) {
		char *source, *canon, *parent;
		struct saved_ctrl *s;

		next = strchr(line, '\n');
		if (next)
			*next++ = '\0';
		else
			next = line + strlen(line);

		source = strtok(line, "\t");
		canon = strtok(NULL, "\t");
		parent = strtok(NULL, "\t");
		if (!source || !canon || !parent)
			continue;

		s = calloc(1, sizeof(*s));
		if (!s)
			return;
		list_node_init(&s->entry);
		s->source = strdup(source);
		if (!s->source ||
		    libnvmf_tid_parse(ctx.nvme_ctx, canon, &s->tid) < 0 ||
		    (!streq(parent, "-") &&
		     libnvmf_tid_parse(ctx.nvme_ctx, parent, &s->parent) < 0)) {
			saved_free(s);
			continue;
		}

		if (streq(s->source, "discovered")) {
			inventory_add_discovered_dc(ctx.inventory, s->tid);
			saved_free(s);
			continue;
		}
		list_add_tail(&g_saved, &s->entry);
	}
}

static bool release_pending;
static bool release_check_exclusions;

/*
 * Release the controllers that are no longer desired: desired at the last
 * pass, and not desired now. A controller that was never desired, such as
 * an mDNS DC whose DLP is not fetched yet, is never released here. With
 * @release_check_exclusions, also release the controllers that the
 * exclusion list now matches. NBFT controllers are never released.
 */
static int release_undesired(sd_event_source *src,
			     void *user_data __attribute__((unused)))
{
	bool check_exclusions = release_check_exclusions;
	struct active_ctrl *e, *next;
	struct saved_ctrl *s, *snext;

	release_pending = false;
	release_check_exclusions = false;
	sd_event_source_disable_unref(src);

	list_for_each_safe(&g_ctrls, e, next, entry) {
		bool desired = inventory_is_desired(ctx.inventory, e->tid);

		if (inventory_is_nbft(ctx.inventory, e->tid))
			continue;

		if (check_exclusions &&
		    libnvmf_exclusion_match(ctx.nvme_ctx, e->tid)) {
			ctrl_release(e, "excluded");
			continue;
		}

		if (e->desired && !desired) {
			ctrl_release(e, "no longer desired");
			continue;
		}

		e->desired = desired;
	}

	list_for_each_safe(&g_saved, s, snext, entry) {
		if (decide_saved(s))
			saved_free(s);
	}

	save_desired();

	return 0;
}

/*
 * Run release_undesired() from the event loop, after the change that
 * called this is complete. Several changes before the pass share it.
 */
static void schedule_release(bool check_exclusions)
{
	sd_event_source *src;
	int r;

	release_check_exclusions |= check_exclusions;
	if (release_pending)
		return;

	r = sd_event_add_defer(ctx.event, &src, release_undesired, NULL);
	if (r < 0) {
		disc_warn("cannot schedule the release check: %s",
			  strerror(-r));
		return;
	}
	release_pending = true;
}

/*
 * Take the current desired state as the new reference, without releasing
 * anything. For inventory changes that must not release, such as giving up
 * on a DC.
 */
static void refresh_desired(void)
{
	struct active_ctrl *e;

	list_for_each(&g_ctrls, e, entry)
		e->desired = inventory_is_desired(ctx.inventory, e->tid);
}

/* One connected controller, as sysfs reports it. */
struct scanned_ctrl {
	char *devname;
	struct libnvmf_tid *tid;
	bool is_dc;
};

SHR_PTRARRAY_DEFINE(scanned_ctrl_list, struct scanned_ctrl);

static void scanned_ctrl_free(struct scanned_ctrl *sc)
{
	if (!sc)
		return;
	tid_free(sc->tid);
	free(sc->devname);
	free(sc);
}

/*
 * Snapshot of every connected controller plus the host's interface
 * addresses. Matching one candidate needs both, and both are expensive to
 * build: a sysfs walk reads six attributes per controller, and getifaddrs()
 * dumps the whole address table. A caller about to test many candidates --
 * every entry of a Discovery Log Page, every desired connection at startup
 * -- builds one snapshot and passes it down, instead of paying for both per
 * candidate.
 *
 * The snapshot is deliberately not cached across calls. Addresses and
 * controllers change under a daemon that runs for weeks, and a stale
 * snapshot produces wrong match results rather than merely slow ones.
 */
struct conn_scan {
	struct ifaddrs *iface_list;
	struct scanned_ctrl_list ctrls;
};

static void conn_scan_load(struct conn_scan *scan);
static void conn_scan_free(struct conn_scan *scan);
static const char *find_devname_for_tid(const struct conn_scan *scan,
					const struct libnvmf_tid *tid);

/* Frees a conn_scan on scope exit; a zeroed scan is a safe no-op. */
#define __cleanup_conn_scan __attribute__((cleanup(conn_scan_free)))

/*
 * Exclusion + registry-owner check — called before every connect decision.
 *
 * Exclusion applies to NBFT-sourced controllers too: the exclusion list is
 * the host administrator's explicit, root-only instruction, and is the
 * supported way to take a boot path out of service for testing or
 * maintenance. owner=nbft still protects a boot-path controller from every
 * *other* orchestrator via the registry — it just does not override the
 * local admin's own exclusion entry.
 *
 * The registry check skips a controller another orchestrator (e.g.
 * nvme-stas) already owns. "discoverd" and "nbft" are discoverd's own
 * registry owner strings (see unit_start_dc()/unit_start_ioc() in units.c),
 * so a controller discoverd itself owns is never skipped here.
 *
 * @scan is a snapshot the caller built before a loop, or NULL to build a
 * throwaway one for this call. It is only consulted when @known_devname
 * is NULL.
 *
 * @known_devname is the existing (or just-removed) device name for @tid,
 * when the caller already has it in hand (on_nvme_remove()); NULL
 * otherwise, in which case this function resolves it itself from @scan
 * (find_devname_for_tid()). Either way the registry is checked directly by
 * device name, never through libnvme's in-process topology tree: that tree
 * is only populated by a caller that has just run libnvme_scan_topology()
 * (true for the CLI's one-shot fabrics commands, never true for this
 * long-running daemon), so a tree-based match would silently report "no
 * owner" for every already-connected controller discoverd didn't itself
 * just scan.
 */
static bool should_connect(const struct conn_scan *scan,
			   const struct libnvmf_tid *tid,
			   const char *known_devname)
{
	__cleanup_conn_scan struct conn_scan local = { 0 };
	__cleanup_free char *owner = NULL;
	const char *devname = known_devname;
	int r;

	if (libnvmf_exclusion_match(ctx.nvme_ctx, tid)) {
		disc_info("%s - excluded, skipping", libnvmf_tid_str(tid));
		return false;
	}

	if (!devname) {
		if (!scan) {
			conn_scan_load(&local);
			scan = &local;
		}
		devname = find_devname_for_tid(scan, tid);
	}

	if (devname) {
		r = libnvmf_registry_retrieve(ctx.nvme_ctx, devname, "owner",
					      &owner);
		if (r == -ENOENT)
			r = 0;
	} else {
		r = 0; // nothing currently connected matching tid
	}

	if (r < 0) {
		disc_warn("%s - failed to check registry owner: %s",
			  libnvmf_tid_str(tid), strerror(-r));
		return false;
	}
	if (owner && !streq(owner, "discoverd") && !streq(owner, "nbft")) {
		disc_info("%s - owned by '%s', skipping",
			  libnvmf_tid_str(tid), owner);
		return false;
	}

	return true;
}

/*
 * Resolved connect parameters for @t: a statically configured connection's
 * own params, or — for anything discoverd found on its own (NBFT, DLP, FC
 * kickstart) — the discovered-controller defaults for the scope @via_dc
 * was learned through (NULL if @t has no configured parent DC either).
 * See libnvmf_config_resolve_discovered() in <nvme/config.h>.
 */
static const struct libnvmf_params *params_for(
		const struct libnvmf_tid *t, bool is_dc,
		const struct libnvmf_config_conn *via_dc)
{
	const struct libnvmf_config_conn *conn =
		inventory_config_conn_for(ctx.inventory, t);

	if (conn)
		return libnvmf_config_conn_get_params(conn);
	if (!ctx.fabrics_cfg)
		return NULL;
	return libnvmf_config_resolve_discovered(ctx.fabrics_cfg, via_dc,
						 is_dc);
}

static void fetch_and_process_dlp(const char *devname,
				  const struct libnvmf_tid *dc_tid);
static bool devname_matches_tid(const char *devname,
				const struct libnvmf_tid *tid);

/* Fetch the DLP of an adopted DC. Runs once, from the event loop. */
static int adopted_dc_fetch(sd_event_source *src, void *user_data)
{
	char *unit_name = user_data;
	struct active_ctrl *e = ctrl_find_by_unit(unit_name);

	if (e && e->devname)
		fetch_and_process_dlp(e->devname, e->tid);

	free(unit_name);
	sd_event_source_disable_unref(src);

	return 0;
}

/*
 * Track a unit this daemon started before it restarted. The connection is
 * already up and @devname names it. Takes ownership of @devname.
 */
static void adopt_ctrl(const char *unit_name, const struct libnvmf_tid *tid,
		       bool is_dc, const struct libnvmf_params *params,
		       char *devname)
{
	struct active_ctrl *e;

	ctrl_add(unit_name, tid, is_dc, params);
	e = ctrl_find_by_unit(unit_name);
	if (!e) {
		free(devname);
		return;
	}
	e->devname = devname;

	disc_info("%s | %s - adopted, already connected",
		  libnvmf_tid_str(tid), devname);

	/*
	 * An adopted DC produces no device-add event, so fetch its DLP here.
	 * Otherwise its DLP-sourced IOCs never enter the desired set and are
	 * not reconnected if they drop. Defer the fetch: a referral DC is
	 * adopted while its parent's DLP is being processed, and the parent's
	 * entries reach the inventory only when that is done.
	 */
	if (is_dc) {
		sd_event_source *src;
		char *name = strdup(unit_name);
		int r = -ENOMEM;

		if (name)
			r = sd_event_add_defer(ctx.event, &src,
					       adopted_dc_fetch, name);
		if (r < 0) {
			disc_warn("%s - cannot defer DLP fetch: %s",
				  libnvmf_tid_str(tid), strerror(-r));
			free(name);
			fetch_and_process_dlp(devname, tid);
		}
	}
}

/*
 * Start a transient unit for @tid (as a DC or an IOC) and track it, or adopt
 * the unit if a previous run of this daemon left it connected. Skipped when
 * a unit for this TID is already tracked, so that the same IOC behind two
 * DCs does not issue a duplicate StartTransient. The caller is responsible
 * for the should_connect() decision. @via_dc is the parent DC's config
 * connection, if @tid was learned via that DC's Discovery Log Page; NULL
 * otherwise.
 */
static void start_ctrl(const struct libnvmf_tid *tid, bool is_dc,
		       const struct libnvmf_config_conn *via_dc)
{
	__cleanup_free char *unit_name = tid_unit_name(tid);
	const struct libnvmf_params *params;
	bool is_nbft;
	int r;

	if (!unit_name)
		return;
	if (ctrl_find_by_unit(unit_name))
		return; // already tracked — no duplicate connect

	params = params_for(tid, is_dc, via_dc);

	/*
	 * A transient unit outlives the daemon. Starting it again fails with
	 * -EEXIST, and the recovery for that stops the unit, which
	 * disconnects. So adopt it if its recorded device is still this
	 * connection. Otherwise the unit is stale, and the -EEXIST recovery
	 * below replaces it.
	 *
	 * The kernel reuses nvmeN names, so the recorded device may now be
	 * another orchestrator's connection. Delete the stale state first:
	 * ExecStop= disconnects whatever device it records.
	 */
	if (unit_exists(ctx.umgr, unit_name)) {
		char *devname = unit_read_devid(unit_name);

		if (devname && devname_matches_tid(devname, tid)) {
			adopt_ctrl(unit_name, tid, is_dc, params, devname);
			return;
		}
		state_remove_devid(unit_name);
		if (devname) {
			__cleanup_free char *owner_unit =
				state_read_unit(devname);

			if (shr_streq0(owner_unit, unit_name))
				state_remove_ctrl(devname);
		}
		free(devname);
	}

	is_nbft = inventory_is_nbft(ctx.inventory, tid);

	r = is_dc ? unit_start_dc(ctx.umgr, tid, params, is_nbft)
		  : unit_start_ioc(ctx.umgr, tid, params, is_nbft);
	if (r >= 0) {
		ctrl_add(unit_name, tid, is_dc, params);
		disc_dbg("%s: requested %s unit", libnvmf_tid_str(tid),
			 is_dc ? "DC" : "IOC");
	} else {
		disc_warn("%s - failed to start %s unit: %s",
			  libnvmf_tid_str(tid), is_dc ? "DC" : "IOC",
			  strerror(-r));
	}
}

struct dlp_fetch_ctx {
	const struct libnvmf_config_conn *via_dc; // dc_tid's own conn, if any
	const struct conn_scan *scan; // shared by every entry's connect check
	struct tid_list iocs;      // for the inventory
	struct tid_list referrals; // for the inventory
	int hops; // the DC's referral hops from its source, -1 if none
	bool self_seen;
	bool epcsd; // meaningful only if self_seen
};

static void dlp_ioc_callback(const struct libnvmf_tid *t, void *user_data)
{
	struct dlp_fetch_ctx *fctx = user_data;
	struct libnvmf_tid *dup;

	dup = libnvmf_tid_dup(t);
	if (!dup || tid_list_append(&fctx->iocs, dup) < 0) {
		tid_free(dup);
		return;
	}

	if (should_connect(fctx->scan, t, NULL))
		start_ctrl(t, false, fctx->via_dc);
}

/*
 * Record the EPCSD bit @t's own referral entry carried in its parent's
 * Discovery Log Page, as a fallback for when @t is later connected to and
 * its own self entry turns out to be absent. A no-op if @t is not tracked
 * yet (should_connect() rejected it, or start_ctrl() failed).
 */
static void record_parent_epcsd(const struct libnvmf_tid *t, bool epcsd)
{
	char *unit_name = tid_unit_name(t);
	struct active_ctrl *e;

	if (!unit_name)
		return;

	e = ctrl_find_by_unit(unit_name);
	if (e) {
		e->parent_epcsd_known = true;
		e->parent_epcsd = epcsd;
	}
	free(unit_name);
}

static void dlp_dc_callback(const struct libnvmf_tid *t, bool epcsd,
			    void *user_data)
{
	struct dlp_fetch_ctx *fctx = user_data;
	struct libnvmf_tid *dup;

	dup = libnvmf_tid_dup(t);
	if (!dup || tid_list_append(&fctx->referrals, dup) < 0)
		tid_free(dup);

	/*
	 * Follow a referral only within the hop limit, as the libnvme
	 * discovery walk does. The referrals of a DC that is no longer
	 * desired are not followed either.
	 */
	if (fctx->hops < 0)
		return;
	if (fctx->hops >= INVENTORY_MAX_REFERRAL_HOPS) {
		disc_info("%s - referral %d hops from its source, not followed",
			  libnvmf_tid_str(t), fctx->hops + 1);
		return;
	}

	if (should_connect(fctx->scan, t, NULL)) {
		start_ctrl(t, true, fctx->via_dc);
		record_parent_epcsd(t, epcsd);
	}
}

static void dlp_self_callback(bool epcsd, void *user_data)
{
	struct dlp_fetch_ctx *fctx = user_data;

	fctx->self_seen = true;
	fctx->epcsd = epcsd;
}

/*
 * Self entry seen: its own EPCSD. Else the parent's referral-entry view
 * of this DC, if any. Else assume EPCSD=0, matching core libnvme's
 * dc_decide().
 */
static bool dc_effective_epcsd(const struct dlp_fetch_ctx *fctx,
			       const struct active_ctrl *e)
{
	if (fctx->self_seen)
		return fctx->epcsd;
	if (e && e->parent_epcsd_known)
		return e->parent_epcsd;
	return false;
}

static void epcsd_park(struct active_ctrl *e);

static void fetch_and_process_dlp(const char *devname,
				  const struct libnvmf_tid *dc_tid)
{
	__cleanup_conn_scan struct conn_scan scan = { 0 };
	struct dlp_fetch_ctx fctx = {
		.via_dc = inventory_config_conn_for(ctx.inventory, dc_tid),
		.hops = inventory_referral_hops(ctx.inventory, dc_tid),
	};
	struct active_ctrl *e = ctrl_find_by_devname(devname);
	bool epcsd;
	int r;

	// One snapshot for every entry this log page turns out to hold.
	conn_scan_load(&scan);
	fctx.scan = &scan;

	r = dlp_fetch(&ctx, devname, dc_tid, dlp_ioc_callback,
		      dlp_dc_callback, dlp_self_callback, &fctx);

	epcsd = dc_effective_epcsd(&fctx, e);
	disc_dbg("%s: self entry %s, effective EPCSD=%d",
		 libnvmf_tid_str(dc_tid), fctx.self_seen ? "seen" : "absent",
		 epcsd);

	if (e && e->is_dc && !epcsd) {
		if (e->force_persistent)
			disc_info_once(&e->force_persistent_logged,
					"%s - EPCSD=0, but persistent=force: staying connected",
					libnvmf_tid_str(dc_tid));
		else
			epcsd_park(e);
	}

	/*
	 * A failed fetch tells nothing about the DC's entries, so keep the
	 * last list. A log page without IOC entries replaces it.
	 */
	if (r == 0 && tid_list_append(&fctx.iocs, NULL) == 0 &&
	    tid_list_append(&fctx.referrals, NULL) == 0) {
		inventory_update_dlp(ctx.inventory, dc_tid, fctx.iocs.items,
				     fctx.referrals.items);
		if (e)
			e->dlp_fetched = true;
		schedule_release(false);
	} else {
		tid_list_free_items(&fctx.iocs);
		tid_list_free_items(&fctx.referrals);
	}
}

/*
 * Arm a dynamically-discovered DC's give-up deadline the first time it is
 * seen failing to (re)connect. Static/NBFT-sourced DCs and IOCs never get
 * one and retry forever, and so does a dynamic DC when dc-giveup-timeout
 * is configured to infinity.
 *
 * Note the two distinct zeros: giveup_at_usec == 0 means no deadline is
 * armed, while a dc-giveup-timeout of 0 means give up on the first
 * failure. The latter still arms, because now + 0 is not 0.
 */
static void ctrl_arm_giveup(struct active_ctrl *e)
{
	uint64_t now;

	if (e->giveup_at_usec || !e->is_dc)
		return;
	if (inventory_is_nbft(ctx.inventory, e->tid) ||
	    inventory_config_conn_for(ctx.inventory, e->tid))
		return;
	if (ctx.cfg->dc_giveup_timeout_usec == SHR_USEC_INFINITY)
		return;

	if (sd_event_now(ctx.event, CLOCK_BOOTTIME, &now) < 0)
		return;

	// A span so large the deadline would wrap means forever, not now.
	if (ctx.cfg->dc_giveup_timeout_usec >= SHR_USEC_INFINITY - now)
		return;

	e->giveup_at_usec = now + ctx.cfg->dc_giveup_timeout_usec;
}

static uint64_t backoff_delay_usec(unsigned int attempts)
{
	uint64_t sec = RETRY_INITIAL_DELAY_SEC;
	unsigned int i;

	for (i = 0; i < attempts && sec < RETRY_MAX_DELAY_SEC; i++)
		sec *= 2;
	if (sec > RETRY_MAX_DELAY_SEC)
		sec = RETRY_MAX_DELAY_SEC;
	return sec * UINT64_C(1000000);
}

static int retry_timeout(sd_event_source *src, uint64_t usec, void *user_data);

static int schedule_retry(struct active_ctrl *e)
{
	uint64_t now, delay;
	int r;

	if (e->retry_timer)
		return 0; // already scheduled

	ctrl_arm_giveup(e);

	r = sd_event_now(ctx.event, CLOCK_BOOTTIME, &now);
	if (r < 0)
		return r;

	delay = backoff_delay_usec(e->attempts);
	e->attempts++;

	return sd_event_add_time(ctx.event, &e->retry_timer, CLOCK_BOOTTIME,
				 now + delay, 0, retry_timeout, e);
}

/*
 * Restart @e's unit (parameters are baked in). Falls back to a fresh
 * StartTransient — using the top-level discovered-controller scope, not
 * @e's original parent DC's scope, a deliberate simplification since
 * active_ctrl does not track that borrowed config_conn across a possible
 * SIGHUP config reload — if the unit was garbage-collected.
 */
static int restart_or_start(struct active_ctrl *e)
{
	int r = unit_restart(ctx.umgr, e->unit_name);

	if (r < 0) {
		const struct libnvmf_params *params =
			params_for(e->tid, e->is_dc, NULL);
		bool is_nbft = inventory_is_nbft(ctx.inventory, e->tid);

		if (e->is_dc)
			r = unit_start_dc(ctx.umgr, e->tid, params, is_nbft);
		else
			r = unit_start_ioc(ctx.umgr, e->tid, params, is_nbft);
	}
	return r;
}

static int retry_timeout(sd_event_source *src,
			 uint64_t usec __attribute__((unused)),
			 void *user_data)
{
	struct active_ctrl *e = user_data;
	uint64_t now;
	int r;

	sd_event_source_unref(src);
	e->retry_timer = NULL;

	if (!inventory_is_desired(ctx.inventory, e->tid)) {
		disc_info("%s - no longer desired, not retrying",
			  libnvmf_tid_str(e->tid));
		ctrl_remove(e);
		return 0;
	}

	if (e->giveup_at_usec &&
	    sd_event_now(ctx.event, CLOCK_BOOTTIME, &now) >= 0 &&
	    now >= e->giveup_at_usec) {
		disc_warn("%s - giving up after repeated failures",
			  libnvmf_tid_str(e->tid));
		if (e->is_dc) {
			inventory_forget_dc(ctx.inventory, e->tid);
			refresh_desired(); // giving up releases nothing
		}
		ctrl_remove(e);
		return 0;
	}

	r = restart_or_start(e);
	if (r < 0) {
		disc_err("%s - retry failed: %s",
			 libnvmf_tid_str(e->tid), strerror(-r));
		schedule_retry(e);
	}
	return 0;
}

static int epcsd_poll_timeout(sd_event_source *src,
			      uint64_t usec __attribute__((unused)),
			      void *user_data)
{
	struct active_ctrl *e = user_data;
	int r;

	sd_event_source_unref(src);
	e->epcsd_poll_timer = NULL;

	if (!inventory_is_desired(ctx.inventory, e->tid)) {
		disc_info("%s - no longer desired, dropping",
			  libnvmf_tid_str(e->tid));
		ctrl_remove(e);
		return 0;
	}

	disc_dbg("%s - EPCSD poll: reconnecting to re-check",
		 libnvmf_tid_str(e->tid));
	r = restart_or_start(e);
	if (r < 0) {
		disc_err("%s - EPCSD poll reconnect failed: %s",
			 libnvmf_tid_str(e->tid), strerror(-r));
		schedule_retry(e);
	}
	return 0;
}

/*
 * Disconnect a DC whose effective EPCSD is 0 and arm a long poll timer to
 * reconnect and re-check it later. Never retried with the failure
 * backoff/give-up path — EPCSD=0 is an expected, stable outcome, not a
 * connect failure.
 */
static void epcsd_park(struct active_ctrl *e)
{
	uint64_t now, interval;

	if (e->epcsd_poll_timer)
		return; // already parked

	unit_stop(ctx.umgr, e->unit_name);

	if (sd_event_now(ctx.event, CLOCK_BOOTTIME, &now) < 0)
		return;

	interval = (uint64_t)ctx.cfg->epcsd_poll_interval_minutes *
		   60 * UINT64_C(1000000);

	if (sd_event_add_time(ctx.event, &e->epcsd_poll_timer, CLOCK_BOOTTIME,
			      now + interval, 0, epcsd_poll_timeout, e) < 0) {
		disc_warn("%s - failed to arm EPCSD poll timer",
			  libnvmf_tid_str(e->tid));
		return;
	}

	disc_info("%s - EPCSD=0, disconnecting; re-checking in %u min",
		 libnvmf_tid_str(e->tid), ctx.cfg->epcsd_poll_interval_minutes);
}

// Periodic FC kickstart (opt-in via fc-kickstart-interval-minutes).
static int fc_kickstart_timeout(sd_event_source *src,
				uint64_t usec __attribute__((unused)),
				void *user_data __attribute__((unused)))
{
	uint64_t now;

	fc_kickstart();

	if (sd_event_now(ctx.event, CLOCK_BOOTTIME, &now) >= 0) {
		uint64_t interval =
			(uint64_t)ctx.cfg->fc_kickstart_interval_minutes *
			60 * UINT64_C(1000000);

		sd_event_source_set_time(src, now + interval);
		sd_event_source_set_enabled(src, SD_EVENT_ONESHOT);
	}
	return 0;
}

/*
 * Link a newly connected DC to its device and fetch its DLP. Both the
 * device's add event and the unit's job completion call this, in either
 * order. Only the first call does the work.
 */
static void dc_connected(struct active_ctrl *e, const char *devname)
{
	if (e->devname)
		return;

	e->devname = strdup(devname);

	/*
	 * DLP entries inherit host-side fields from the DC's TID. Use the
	 * candidate TID, not one read from sysfs: sysfs reports the source
	 * address the kernel selected, which the configuration did not ask
	 * for.
	 */
	fetch_and_process_dlp(devname, e->tid);
}

static void on_job_done(const char *unit_name, bool success,
			void *user_data __attribute__((unused)))
{
	struct active_ctrl *e;

	e = ctrl_find_by_unit(unit_name);
	if (!e) {
		if (!success)
			disc_warn("unit %s failed (untracked)", unit_name);
		return;
	}

	if (success) {
		e->attempts = 0;
		e->giveup_at_usec = 0;

		/*
		 * The device's add event is soaked for about a second and
		 * can be processed before ExecStartPost= wrote the state
		 * file. The job completes only after ExecStartPost=.
		 */
		if (e->is_dc) {
			__cleanup_free char *devname =
				unit_read_devid(unit_name);

			if (devname)
				dc_connected(e, devname);
		}
		return;
	}

	disc_warn("%s - connection unit failed", libnvmf_tid_str(e->tid));
	if (schedule_retry(e) < 0)
		disc_err("%s - failed to schedule retry",
			 libnvmf_tid_str(e->tid));
}

static void on_dc_add(const char *devname,
		      void *user_data __attribute__((unused)))
{
	struct active_ctrl *e;
	char *unit_name;

	// Only a DC that nvme-discoverd connected has a state file.
	unit_name = state_read_unit(devname);
	if (!unit_name)
		return;

	e = ctrl_find_by_unit(unit_name);
	free(unit_name);
	if (e)
		dc_connected(e, devname);
}

static void on_dc_changed(const char *devname,
			  void *user_data __attribute__((unused)))
{
	struct active_ctrl *e;

	e = ctrl_find_by_devname(devname);
	if (!e || !e->tid) {
		disc_warn("%s - dc_changed for untracked device", devname);
		return;
	}

	disc_dbg("%s | %s: discovery log changed, re-fetching",
		 libnvmf_tid_str(e->tid), devname);
	fetch_and_process_dlp(devname, e->tid);
}

static void on_ioc_add(const char *devname,
		       void *user_data __attribute__((unused)))
{
	struct active_ctrl *e;
	char *unit_name;

	unit_name = state_read_unit(devname);
	if (!unit_name)
		return;

	e = ctrl_find_by_unit(unit_name);
	if (e && !e->devname)
		e->devname = strdup(devname);
	free(unit_name);
}

static void on_nvme_remove(const char *devname,
			   void *user_data __attribute__((unused)))
{
	struct active_ctrl *e;
	bool is_fc;

	e = ctrl_find_by_devname(devname);
	state_remove_ctrl(devname);
	if (!e)
		return; // might be a controller we didn't start — ignore

	state_remove_devid(e->unit_name); // ExecStopPost usually beat us to it

	free(e->devname);
	e->devname = NULL;

	/*
	 * Both checks must pass before reconnecting: a matching exclusion
	 * entry wins even over a still-desired controller — it is the
	 * administrator's explicit override.
	 */
	if (!should_connect(NULL, e->tid, devname)) {
		unit_stop(ctx.umgr, e->unit_name);
		ctrl_remove(e);
		return;
	}

	/*
	 * Checked before "not desired": this removal is discoverd's own
	 * doing, and the poll timer owns what happens next. Checking
	 * "desired" first can call ctrl_remove(), which frees the timer
	 * epcsd_park() armed moments ago. The timer re-checks "desired"
	 * itself when it fires, so nothing is skipped by deferring.
	 */
	if (e->epcsd_poll_timer)
		return;

	if (!inventory_is_desired(ctx.inventory, e->tid)) {
		disc_info("%s | %s - removed, not desired, dropping",
			  libnvmf_tid_str(e->tid), devname);
		ctrl_remove(e);
		return;
	}

	disc_info("%s | %s - removed but still desired, reconnecting",
		  libnvmf_tid_str(e->tid), devname);

	is_fc = shr_streq0(libnvmf_tid_get_transport(e->tid), "fc");

	if (is_fc) {
		// FC: stop old unit, re-issue kickstart.
		unit_stop(ctx.umgr, e->unit_name);
		ctrl_remove(e);
		fc_kickstart();
	} else if (restart_or_start(e) < 0) {
		if (schedule_retry(e) < 0)
			disc_err("%s - failed to schedule retry",
				 libnvmf_tid_str(e->tid));
	}
}

static void on_fc_discovery(const struct libnvmf_tid *t,
			    void *user_data __attribute__((unused)))
{
	__cleanup_tid struct libnvmf_tid *tid = libnvmf_tid_dup(t);

	// The uevent names no host: connect as the default host.
	if (!tid ||
	    tid_set_default_host_if_unset(tid, ctx.hostnqn, ctx.hostid) < 0)
		return;

	/*
	 * fc_monitor_handler() is the only producer of fc_discovery
	 * callbacks, and the kernel only fires that uevent for an FC
	 * remote port advertising FC_PORT_ROLE_NVME_DISCOVERY - so tid is
	 * always a DC here, never an IOC. Connect as a DC; we fetch its
	 * DLP (and discover any IOCs behind it) once the device appears.
	 */
	inventory_add_discovered_dc(ctx.inventory, tid);
	if (should_connect(NULL, tid, NULL))
		start_ctrl(tid, true, NULL);
}

/*
 * Whether the kernel accepts a discovery connect to a DC's own NQN (TP8013).
 * On any error, answer no: the well-known discovery NQN always works.
 */
static bool kernel_supports_discovery_nqn(void)
{
	bool supported;
	int r;

	r = libnvmf_kernel_option_supported(ctx.nvme_ctx, "discovery",
					    &supported);
	if (r < 0) {
		disc_dbg("kernel fabrics options: %s", libnvme_strerror(-r));
		return false;
	}

	return supported;
}

/*
 * mDNS found a DC. Connect with its advertised NQN if the kernel allows
 * it, else with the well-known discovery NQN. The DLP gives the real NQN
 * either way. host_iface is only valid for tcp. A link-local traddr gets
 * the interface as its scope, because rdma has no host_iface.
 */
static void on_mdns_add(const char *traddr, const char *trsvcid,
			const char *transport, const char *nqn,
			const char *ifname,
			int ifindex __attribute__((unused)),
			void *user_data __attribute__((unused)))
{
	const char *subsysnqn = NVME_DISC_SUBSYS_NAME;
	__cleanup_tid struct libnvmf_tid *tid = NULL;
	bool is_tcp = shr_streq0(transport, "tcp");
	__cleanup_free char *scoped = NULL;

	if (nqn && kernel_supports_discovery_nqn())
		subsysnqn = nqn;

	scoped = tid_scope_link_local(traddr, ifname);
	if (!scoped)
		return;

	tid = tid_new(transport, scoped, trsvcid, subsysnqn, NULL,
		      is_tcp ? ifname : NULL, NULL, NULL, true);
	if (!tid ||
	    tid_set_default_host_if_unset(tid, ctx.hostnqn, ctx.hostid) < 0)
		return;

	inventory_add_discovered_dc(ctx.inventory, tid);
	if (should_connect(NULL, tid, NULL))
		start_ctrl(tid, true, NULL);
}

/*
 * No service_remove callback: an mDNS announcement can disappear briefly
 * (cache expiry, link flap). A connected DC is managed by the same paths
 * as any other DC, not by its announcement.
 */
static const struct mdns_callbacks mdns_callbacks = {
	.service_add = on_mdns_add,
};

/* Start or stop mDNS to match the zeroconf setting. */
static void apply_zeroconf(void)
{
	int r;

	if (ctx.cfg->zeroconf && !ctx.mdns) {
		r = mdns_start(ctx.event, &mdns_callbacks, NULL, &ctx.mdns);
		if (r == -ENOSYS)
			disc_warn("mdns: zeroconf is enabled, but nvme-discoverd was built without mDNS support");
		else if (r == -EOPNOTSUPP)
			disc_warn("mdns: zeroconf is enabled, but systemd-resolved has no BrowseServices (needs >= v258)");
		else if (r < 0)
			disc_warn("mdns: zeroconf is enabled, but mDNS cannot start: %s",
				  strerror(-r));
	} else if (!ctx.cfg->zeroconf && ctx.mdns) {
		mdns_stop(ctx.mdns);
		ctx.mdns = NULL;
	}
}

static struct libnvmf_tid *sysfs_read_tid(const char *devname, bool *is_dc)
{
	sd_device *dev = NULL;
	char syspath[256];
	struct libnvmf_tid *t;

	if (is_dc)
		*is_dc = false;

	snprintf(syspath, sizeof(syspath), "/sys/class/nvme/%s", devname);
	if (sd_device_new_from_syspath(&dev, syspath) < 0)
		return NULL;

	t = tid_from_sysfs(dev, is_dc);
	sd_device_unref(dev);
	return t;
}

/*
 * Is @devname a connection that satisfies @tid? A device name alone does not
 * identify a controller, because the kernel reuses nvmeN names.
 */
static bool devname_matches_tid(const char *devname,
				const struct libnvmf_tid *tid)
{
	__cleanup_tid struct libnvmf_tid *existing = NULL;
	struct ifaddrs *iface_list = NULL;
	bool is_dc, match;

	existing = sysfs_read_tid(devname, &is_dc);
	if (!existing)
		return false;

	if (getifaddrs(&iface_list) < 0) {
		disc_warn("getifaddrs: %s", strerror(errno));
		iface_list = NULL;
	}

	match = tid_matches_existing(tid, existing, is_dc, iface_list);
	freeifaddrs(iface_list);

	return match;
}

static void conn_scan_free(struct conn_scan *scan)
{
	size_t i;

	for (i = 0; i < scan->ctrls.len; i++)
		scanned_ctrl_free(scan->ctrls.items[i]);
	scanned_ctrl_list_free(&scan->ctrls);
	freeifaddrs(scan->iface_list);
	memset(scan, 0, sizeof(*scan));
}

/*
 * Read every connected controller out of sysfs and snapshot the host's
 * interface addresses. A controller whose TID cannot be built is left out:
 * it cannot be matched against anyway. On failure the scan is left short
 * rather than failed, which costs a missed match, not a crash.
 */
static void conn_scan_load(struct conn_scan *scan)
{
	DIR *d;
	struct dirent *ent;

	memset(scan, 0, sizeof(*scan));

	if (getifaddrs(&scan->iface_list) < 0) {
		disc_warn("getifaddrs: %s", strerror(errno));
		scan->iface_list = NULL;
	}

	d = opendir("/sys/class/nvme");
	if (!d) {
		if (errno != ENOENT)
			disc_warn("opendir /sys/class/nvme: %s",
				  strerror(errno));
		return;
	}

	while ((ent = readdir(d))) {
		struct scanned_ctrl *sc;

		if (ent->d_name[0] == '.')
			continue;

		sc = calloc(1, sizeof(*sc));
		if (!sc) {
			disc_warn("connection scan: out of memory");
			break;
		}

		sc->tid = sysfs_read_tid(ent->d_name, &sc->is_dc);
		sc->devname = shr_xstrdup(ent->d_name);
		if (!sc->tid || !sc->devname) {
			scanned_ctrl_free(sc);
			continue;
		}

		if (scanned_ctrl_list_append(&scan->ctrls, sc) < 0) {
			disc_warn("connection scan: out of memory");
			scanned_ctrl_free(sc);
			break;
		}
	}
	closedir(d);
}

/*
 * Find the device name (e.g. "nvme3") of a connected controller that
 * satisfies @tid, using the snapshot rather than libnvme's topology tree
 * (see should_connect()'s comment for why that tree can't be relied on
 * here). Returns NULL if nothing in the snapshot matches. The returned
 * string belongs to the scan.
 */
static const char *find_devname_for_tid(const struct conn_scan *scan,
					const struct libnvmf_tid *tid)
{
	size_t i;

	for (i = 0; i < scan->ctrls.len; i++) {
		const struct scanned_ctrl *sc = scan->ctrls.items[i];

		if (tid_matches_existing(tid, sc->tid, sc->is_dc,
					 scan->iface_list))
			return sc->devname;
	}
	return NULL;
}

static void connect_desired(void)
{
	__cleanup_conn_scan struct conn_scan scan = { 0 };
	struct libnvmf_tid **dcs, **iocs;
	int i;

	conn_scan_load(&scan);

	dcs = inventory_desired_dcs(ctx.inventory);
	if (dcs) {
		for (i = 0; dcs[i]; i++) {
			if (should_connect(&scan, dcs[i], NULL))
				start_ctrl(dcs[i], true, NULL);
			tid_free(dcs[i]);
		}
		free(dcs);
	}

	iocs = inventory_desired_iocs(ctx.inventory);
	if (iocs) {
		for (i = 0; iocs[i]; i++) {
			if (should_connect(&scan, iocs[i], NULL))
				start_ctrl(iocs[i], false, NULL);
			tid_free(iocs[i]);
		}
		free(iocs);
	}
}

/*
 * Apply the effective log level to both discoverd and its in-process libnvme
 * context. A command-line --debug (ctx.force_debug) forces DEBUG and
 * overrides the config; otherwise the configured debug-level (default INFO)
 * is used. Called at startup after config_load() and again after a SIGHUP
 * reload, since the libnvme context outlives any single config.
 */
static void apply_log_level(void)
{
	int level = ctx.force_debug ? DISC_LOG_DEBUG : ctx.cfg->debug_level;

	log_set_level(level);
	libnvme_set_logging_level(ctx.nvme_ctx, level, false, false);
}

static int sighup_handler(sd_event_source *src __attribute__((unused)),
			  const struct signalfd_siginfo *si __attribute__((unused)),
			  void *user_data __attribute__((unused)))
{
	struct discoverd_config *new_cfg;
	struct libnvmf_config *new_fabrics_cfg;
	uint64_t now = 0;

	/*
	 * Type=notify-reload: systemd ignores RELOADING=1 without
	 * MONOTONIC_USEC=, and the reload job times out.
	 */
	sd_event_now(ctx.event, CLOCK_MONOTONIC, &now);
	sd_notifyf(0, "RELOADING=1\n"
		      "MONOTONIC_USEC=%" PRIu64 "\n"
		      "STATUS=Reloading configuration...", now);

	new_cfg = config_load(ctx.conf_path);
	if (!new_cfg) {
		disc_err("failed to reload config");
		sd_notify(0, "READY=1");
		return 0;
	}
	config_free(ctx.cfg);
	ctx.cfg = new_cfg;
	apply_log_level();

	if (libnvmf_config_read(ctx.nvme_ctx, NULL, &new_fabrics_cfg) == 0) {
		libnvmf_config_free(ctx.fabrics_cfg);
		ctx.fabrics_cfg = new_fabrics_cfg;
	} else {
		disc_err("failed to reload fabrics config, keeping last-good");
	}
	inventory_load_config(ctx.inventory, &ctx);

	/*
	 * Connect any newly added desired controllers. Release those the
	 * configuration or the exclusion list removed, without disconnecting
	 * them.
	 */
	connect_desired();
	schedule_release(true);
	apply_zeroconf();

	sd_notify(0, "READY=1");
	return 0;
}

// Graceful shutdown: leave the event loop so main()'s cleanup runs.
static int sigterm_handler(sd_event_source *src __attribute__((unused)),
			   const struct signalfd_siginfo *si __attribute__((unused)),
			   void *user_data __attribute__((unused)))
{
	sd_event_exit(ctx.event, 0);
	return 0;
}

/*
 * Resolve the identity a connect without --hostnqn uses. Must run before
 * anything scans a controller into the libnvme tree:
 * libnvmf_host_get_ids() prefers a host already in the tree.
 */
static int resolve_default_host(void)
{
	int r;

	r = libnvmf_host_get_ids(ctx.nvme_ctx, NULL, NULL,
				 &ctx.hostnqn, &ctx.hostid);
	if (r < 0)
		return r;

	disc_dbg("default host identity: %s, %s", ctx.hostnqn, ctx.hostid);

	return 0;
}

int main(int argc, char **argv)
{
	static const struct events_callbacks callbacks = {
		.dc_add       = on_dc_add,
		.dc_changed   = on_dc_changed,
		.ioc_add      = on_ioc_add,
		.nvme_remove  = on_nvme_remove,
		.fc_discovery = on_fc_discovery,
	};
	static const struct option long_opts[] = {
		{ "config",    required_argument, NULL, 'c' },
		{ "nvme-path", required_argument, NULL, 'N' },
		{ "debug",     no_argument,       NULL, 'd' },
		{ "help",      no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	const char *nvme_path = NULL, *config_path = NULL;
	char *nvme_path_abs = NULL, *config_path_abs = NULL;
	bool debug = false;
	sigset_t mask;
	int r, c;

	while ((c = getopt_long(argc, argv, "c:dh", long_opts, NULL)) != -1) {
		switch (c) {
		case 'c':
			config_path = optarg;
			break;
		case 'N':
			nvme_path = optarg;
			break;
		case 'd':
			debug = true;
			break;
		case 'h':
			printf("Usage: %s [OPTIONS]\n"
			       "\n"
			       "All options are optional; specify one only to override its default.\n"
			       "  --config FILE, -c FILE  discoverd configuration file\n"
			       "                          (default: " DISCOVERD_CONF_PATH ")\n"
			       "  --nvme-path PATH        nvme binary the connection units exec\n"
			       "                          (default: <sbindir>/nvme)\n"
			       "  --debug, -d             enable debug logging (journal + libnvme)\n"
			       "  --help, -h              show this help and exit\n",
			       argv[0]);
			return 0;
		default:
			fprintf(stderr, "Try '%s --help'.\n", argv[0]);
			return 1;
		}
	}

	if (debug)
		log_set_level(DISC_LOG_DEBUG);
	ctx.force_debug = debug;

	/*
	 * The nvme path is baked into each transient unit's ExecStart=, which
	 * systemd requires to be absolute. Canonicalize it (resolving a
	 * relative path against the current directory) so the daemon can be
	 * launched as, e.g., --nvme-path ./.build/nvme. realpath() also
	 * confirms the binary exists, failing fast on a typo.
	 */
	if (nvme_path) {
		nvme_path_abs = realpath(nvme_path, NULL);
		if (!nvme_path_abs) {
			fprintf(stderr, "--nvme-path: cannot resolve '%s': %s\n",
				nvme_path, strerror(errno));
			return 1;
		}
	}

	if (config_path) {
		config_path_abs = realpath(config_path, NULL);
		if (!config_path_abs) {
			fprintf(stderr, "--config: cannot resolve '%s': %s\n",
				config_path, strerror(errno));
			return 1;
		}
	}
	ctx.conf_path = config_path_abs ? config_path_abs : DISCOVERD_CONF_PATH;

	r = sd_event_default(&ctx.event);
	if (r < 0) {
		disc_err("sd_event_default: %s", strerror(-r));
		return 1;
	}

	r = sd_bus_open_system(&ctx.bus);
	if (r < 0) {
		disc_err("sd_bus_open_system: %s", strerror(-r));
		return 1;
	}

	r = sd_bus_attach_event(ctx.bus, ctx.event, SD_EVENT_PRIORITY_NORMAL);
	if (r < 0) {
		disc_err("sd_bus_attach_event: %s", strerror(-r));
		return 1;
	}

	r = state_init();
	if (r < 0) {
		disc_err("state_init: %s", strerror(-r));
		return 1;
	}
	state_gc();

	ctx.nvme_ctx = libnvme_create_global_ctx();
	if (!ctx.nvme_ctx) {
		disc_err("libnvme_create_global_ctx: failed");
		return 1;
	}
	libnvme_set_logging_level(ctx.nvme_ctx,
				  debug ? LIBNVME_LOG_DEBUG : LIBNVME_LOG_ERR,
				  false, false);

	ctx.cfg = config_load(ctx.conf_path);
	if (!ctx.cfg) {
		disc_err("config_load: failed");
		return 1;
	}
	apply_log_level();

	r = libnvmf_config_read(ctx.nvme_ctx, NULL, &ctx.fabrics_cfg);
	if (r < 0) {
		disc_err("libnvmf_config_read: %s", strerror(-r));
		return 1;
	}

	r = resolve_default_host();
	if (r < 0) {
		disc_err("failed to resolve the host identity: %s",
			 strerror(-r));
		return 1;
	}

	ctx.inventory = inventory_new();
	if (!ctx.inventory)
		return 1;

	if (ctx.cfg->nbft)
		inventory_load_nbft(ctx.inventory, &ctx);
	inventory_load_config(ctx.inventory, &ctx);
	load_saved();

	ctx.umgr = unit_mgr_new(ctx.bus, ctx.event, on_job_done, NULL,
				nvme_path_abs);
	if (!ctx.umgr)
		return 1;

	ctx.evts = events_start(ctx.event, &callbacks, NULL);
	if (!ctx.evts)
		return 1;

	// Block these from normal delivery; handle them via sd_event.
	sigemptyset(&mask);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	r = sd_event_add_signal(ctx.event, NULL, SIGHUP, sighup_handler, NULL);
	if (r < 0) {
		disc_err("sd_event_add_signal(SIGHUP): %s", strerror(-r));
		return 1;
	}

	// SIGTERM (systemctl stop) and SIGINT (Ctrl-C) → graceful shutdown.
	r = sd_event_add_signal(ctx.event, NULL, SIGTERM, sigterm_handler, NULL);
	if (r < 0) {
		disc_err("sd_event_add_signal(SIGTERM): %s", strerror(-r));
		return 1;
	}
	r = sd_event_add_signal(ctx.event, NULL, SIGINT, sigterm_handler, NULL);
	if (r < 0) {
		disc_err("sd_event_add_signal(SIGINT): %s", strerror(-r));
		return 1;
	}

	/*
	 * Connect the desired set. start_ctrl() adopts anything a previous
	 * run of this daemon left connected. The release pass then decides
	 * what the last run wanted and this one does not.
	 */
	connect_desired();
	schedule_release(false);

	/*
	 * One-shot startup FC kickstart: mimics nvmefc-boot-connections.service
	 * (which discoverd replaces). Always issued — fc_kickstart() is a
	 * no-op (returns 0 on ENOENT) when no FC HBA is present, so it is
	 * harmless on non-FC hosts. Independent of the periodic-kickstart
	 * knob below.
	 */
	fc_kickstart();

	apply_zeroconf();

	// Periodic FC kickstart: opt-in (default 0 = disabled).
	if (ctx.cfg->fc_kickstart_interval_minutes > 0) {
		uint64_t now, interval;

		interval = (uint64_t)ctx.cfg->fc_kickstart_interval_minutes *
			   60 * UINT64_C(1000000);
		r = sd_event_now(ctx.event, CLOCK_BOOTTIME, &now);
		if (r >= 0)
			r = sd_event_add_time(ctx.event, NULL, CLOCK_BOOTTIME,
					      now + interval, 0,
					      fc_kickstart_timeout, NULL);
		if (r < 0)
			disc_err("failed to arm FC kickstart timer: %s",
				 strerror(-r));
	}

	sd_notify(0, "READY=1");

	r = sd_event_loop(ctx.event);
	if (r < 0)
		disc_err("sd_event_loop: %s", strerror(-r));

	mdns_stop(ctx.mdns);
	events_stop(ctx.evts);
	unit_mgr_free(ctx.umgr);
	free(nvme_path_abs);
	free(config_path_abs);
	inventory_free(ctx.inventory);
	free(ctx.hostnqn);
	free(ctx.hostid);
	config_free(ctx.cfg);
	libnvmf_config_free(ctx.fabrics_cfg);
	libnvme_free_global_ctx(ctx.nvme_ctx);
	sd_bus_unref(ctx.bus);
	sd_event_unref(ctx.event);

	return r < 0 ? 1 : 0;
}
