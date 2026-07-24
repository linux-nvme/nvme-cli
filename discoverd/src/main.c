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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-device.h>
#include <systemd/sd-event.h>

#include <ccan/list/list.h>

#include <nvme/config.h>
#include <nvme/exclusion.h>
#include <nvme/lib.h>
#include <nvme/registry.h>

#include "cache.h"
#include "config.h"
#include "ctx.h"
#include "dlp.h"
#include "events.h"
#include "fc.h"
#include "log.h"
#include "state.h"
#include "tid.h"
#include "units.h"

// Exponential backoff for failed (re)connect attempts: 1s, 2s, 4s, ... capped
// at 5 min. A dynamically-discovered DC (not NBFT- or config-sourced — a
// referral or FC-kickstart find) additionally gives up after 72h of
// unbroken failure and is dropped from tracking, since nothing but its own
// retries vouches for it any more. Static and NBFT-sourced DCs represent
// deliberate admin/firmware intent and always retry forever.
#define RETRY_INITIAL_DELAY_SEC 1
#define RETRY_MAX_DELAY_SEC     300
#define DC_GIVEUP_USEC          (UINT64_C(72) * 3600 * UINT64_C(1000000))

struct active_ctrl {
	struct list_node entry;
	char *unit_name;    // "nvme-discoverd-<12hex>.service"
	char *devname;      // "nvmeX"; NULL until confirmed in sysfs
	struct libnvmf_tid *tid;
	bool is_dc;
	unsigned int attempts;   // consecutive failed (re)connect attempts
	uint64_t giveup_at_usec; // 0 = no deadline armed (ctrl_arm_giveup)
	sd_event_source *retry_timer; // NULL when no retry pending
};

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
		if (streq0(e->devname, devname))
			return e;
	}
	return NULL;
}

static void ctrl_free(struct active_ctrl *e)
{
	if (!e)
		return;
	sd_event_source_unref(e->retry_timer);
	tid_free(e->tid);
	free(e->unit_name);
	free(e->devname);
	free(e);
}

static int ctrl_add(const char *unit_name, const struct libnvmf_tid *t,
		    bool is_dc)
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
	if (!e->unit_name || !e->tid) {
		ctrl_free(e);
		return -ENOMEM;
	}

	list_add(&g_ctrls, &e->entry);
	return 0;
}

static void ctrl_remove(struct active_ctrl *entry)
{
	list_del_init(&entry->entry);
	ctrl_free(entry);
}

static char *find_devname_for_tid(const struct libnvmf_tid *t);

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
 * @known_devname is the live (or just-removed) device name for @t, when
 * the caller already has it in hand (on_nvme_remove(), startup_audit()'s
 * sysfs walk); NULL otherwise, in which case this function resolves it
 * itself via a live sysfs scan (find_devname_for_tid()). Either way the
 * registry is checked directly by device name, never through libnvme's
 * in-process topology tree: that tree is only populated by a caller that
 * has just run libnvme_scan_topology() (true for the CLI's one-shot
 * fabrics commands, never true for this long-running daemon), so a
 * tree-based match would silently report "no owner" for every
 * already-connected controller discoverd didn't itself just scan.
 */
static bool should_connect(const struct libnvmf_tid *t,
			   const char *known_devname)
{
	char *owner = NULL;
	char *resolved_devname = NULL;
	const char *devname = known_devname;
	int r;

	if (libnvmf_exclusion_match(ctx.nvme_ctx, t)) {
		disc_info("%s - excluded, skipping", libnvmf_tid_str(t));
		return false;
	}

	if (!devname) {
		resolved_devname = find_devname_for_tid(t);
		devname = resolved_devname;
	}

	if (devname) {
		r = libnvmf_registry_retrieve(ctx.nvme_ctx, devname, "owner",
					      &owner);
		if (r == -ENOENT)
			r = 0;
	} else {
		r = 0; // nothing currently connected matching t
	}
	free(resolved_devname);

	if (r < 0) {
		disc_warn("%s - failed to check registry owner: %s",
			  libnvmf_tid_str(t), strerror(-r));
		return false;
	}
	if (owner && strcmp(owner, "discoverd") && strcmp(owner, "nbft")) {
		disc_info("%s - owned by '%s', skipping",
			  libnvmf_tid_str(t), owner);
		free(owner);
		return false;
	}

	free(owner);
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
		cache_config_conn_for(ctx.cache, t);

	if (conn)
		return libnvmf_config_conn_get_params(conn);
	if (!ctx.fabrics_cfg)
		return NULL;
	return libnvmf_config_resolve_discovered(ctx.fabrics_cfg, via_dc,
						 is_dc);
}

/*
 * Start a transient unit for @t (as a DC or an IOC) and track it — unless a
 * unit for this TID is already tracked, in which case we skip to avoid
 * issuing a duplicate StartTransient (e.g. startup_audit and
 * connect_desired both reaching the same controller, or the same IOC
 * appearing behind two DCs). The caller is responsible for the
 * should_connect() decision. @via_dc is the parent DC's config connection,
 * if @t was learned via that DC's Discovery Log Page; NULL otherwise.
 */
static void start_ctrl(const struct libnvmf_tid *t, bool is_dc, bool is_nbft,
		       const struct libnvmf_config_conn *via_dc)
{
	char *unit_name = tid_unit_name(t);
	const struct libnvmf_params *params;
	int r;

	if (!unit_name)
		return;
	if (ctrl_find_by_unit(unit_name)) {
		free(unit_name); // already tracked — no duplicate connect
		return;
	}

	params = params_for(t, is_dc, via_dc);

	r = is_dc ? unit_start_dc(ctx.umgr, t, params, is_nbft)
		  : unit_start_ioc(ctx.umgr, t, params, is_nbft);
	if (r >= 0) {
		ctrl_add(unit_name, t, is_dc);
		disc_dbg("%s: requested %s unit", libnvmf_tid_str(t),
			 is_dc ? "DC" : "IOC");
	} else {
		disc_warn("%s - failed to start %s unit: %s",
			  libnvmf_tid_str(t), is_dc ? "DC" : "IOC",
			  strerror(-r));
	}
	free(unit_name);
}

struct dlp_fetch_ctx {
	const struct libnvmf_config_conn *via_dc; // dc_tid's own conn, if any
	struct libnvmf_tid **ioc_tids;
	size_t nioc, cap_ioc;
};

static void dlp_ioc_cback(const struct libnvmf_tid *t, void *user_data)
{
	struct dlp_fetch_ctx *fctx = user_data;
	bool is_nbft = cache_is_nbft(ctx.cache, t);

	// Accumulate IOC TIDs for cache_update_dlp().
	if (fctx->nioc == fctx->cap_ioc) {
		size_t newcap = fctx->cap_ioc ? fctx->cap_ioc * 2 : 8;
		struct libnvmf_tid **newarr =
			realloc(fctx->ioc_tids, (newcap + 1) * sizeof(*newarr));
		if (!newarr)
			return;
		fctx->ioc_tids = newarr;
		fctx->cap_ioc = newcap;
	}
	fctx->ioc_tids[fctx->nioc] = libnvmf_tid_dup(t);
	if (!fctx->ioc_tids[fctx->nioc])
		return;
	fctx->nioc++;
	fctx->ioc_tids[fctx->nioc] = NULL;

	if (should_connect(t, NULL))
		start_ctrl(t, false, is_nbft, fctx->via_dc);
}

static void dlp_dc_cback(const struct libnvmf_tid *t, void *user_data)
{
	struct dlp_fetch_ctx *fctx = user_data;
	bool is_nbft = cache_is_nbft(ctx.cache, t);

	if (should_connect(t, NULL))
		start_ctrl(t, true, is_nbft, fctx->via_dc);
}

static void fetch_and_process_dlp(const char *devname,
				  const struct libnvmf_tid *dc_tid)
{
	struct dlp_fetch_ctx fctx = {
		.via_dc = cache_config_conn_for(ctx.cache, dc_tid),
	};

	dlp_fetch(&ctx, devname, dc_tid, dlp_ioc_cback, dlp_dc_cback, &fctx);

	if (fctx.ioc_tids)
		cache_update_dlp(ctx.cache, dc_tid, fctx.ioc_tids);
}

/*
 * Arm a dynamically-discovered DC's give-up deadline the first time it is
 * seen failing to (re)connect. Static/NBFT-sourced DCs and IOCs never get
 * one and retry forever.
 */
static void ctrl_arm_giveup(struct active_ctrl *e)
{
	uint64_t now;

	if (e->giveup_at_usec || !e->is_dc)
		return;
	if (cache_is_nbft(ctx.cache, e->tid) ||
	    cache_config_conn_for(ctx.cache, e->tid))
		return;
	if (sd_event_now(ctx.event, CLOCK_BOOTTIME, &now) >= 0)
		e->giveup_at_usec = now + DC_GIVEUP_USEC;
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
		bool is_nbft = cache_is_nbft(ctx.cache, e->tid);

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

	if (!cache_is_desired(ctx.cache, e->tid)) {
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
		if (e->is_dc)
			cache_remove_dlp(ctx.cache, e->tid);
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
		return;
	}

	disc_warn("%s - connection unit failed", libnvmf_tid_str(e->tid));
	if (schedule_retry(e) < 0)
		disc_err("%s - failed to schedule retry",
			 libnvmf_tid_str(e->tid));
}

static void on_dc_add(const char *devname, const struct libnvmf_tid *t,
		      void *user_data __attribute__((unused)))
{
	struct active_ctrl *e;
	char *unit_name;

	// Link devname to the in-memory entry via state file.
	unit_name = state_read_unit(devname);
	if (unit_name) {
		e = ctrl_find_by_unit(unit_name);
		if (e && !e->devname)
			e->devname = strdup(devname);
		free(unit_name);
	}

	fetch_and_process_dlp(devname, t);
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
	if (!should_connect(e->tid, devname)) {
		unit_stop(ctx.umgr, e->unit_name);
		ctrl_remove(e);
		return;
	}

	if (!cache_is_desired(ctx.cache, e->tid)) {
		disc_info("%s | %s - removed, not desired, dropping",
			  libnvmf_tid_str(e->tid), devname);
		ctrl_remove(e);
		return;
	}

	disc_info("%s | %s - removed but still desired, reconnecting",
		  libnvmf_tid_str(e->tid), devname);

	is_fc = streq0(libnvmf_tid_get_transport(e->tid), "fc");

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
	bool is_nbft = cache_is_nbft(ctx.cache, t);

	/*
	 * fc_monitor_handler() is the only producer of fc_discovery
	 * callbacks, and the kernel only fires that uevent for an FC
	 * remote port advertising FC_PORT_ROLE_NVME_DISCOVERY - so t is
	 * always a DC here, never an IOC. Connect as a DC; we fetch its
	 * DLP (and discover any IOCs behind it) once the device appears.
	 */
	if (should_connect(t, NULL))
		start_ctrl(t, true, is_nbft, NULL);
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
 * Find the device name (e.g. "nvme3") of a currently-connected controller
 * matching t, by walking sysfs directly -- the same approach
 * sysfs_read_tid()'s callers already use, not libnvme's topology tree (see
 * should_connect()'s comment for why that tree can't be relied on here).
 * Returns NULL if nothing currently connected matches t. Caller frees the
 * result.
 */
static char *find_devname_for_tid(const struct libnvmf_tid *t)
{
	DIR *d = opendir("/sys/class/nvme");
	struct dirent *ent;
	char *match = NULL;

	if (!d)
		return NULL;

	while (!match && (ent = readdir(d))) {
		struct libnvmf_tid *dt;
		bool is_dc;

		if (ent->d_name[0] == '.')
			continue;
		dt = sysfs_read_tid(ent->d_name, &is_dc);
		if (!dt)
			continue;
		if (tid_same(dt, t))
			match = strdup(ent->d_name);
		tid_free(dt);
	}
	closedir(d);
	return match;
}

static bool nvme_dev_exists(const char *devname)
{
	char path[256];
	struct stat st;

	snprintf(path, sizeof(path), "/sys/class/nvme/%s", devname);
	return stat(path, &st) == 0;
}

static void startup_audit(void)
{
	char **devids;
	int i;

	// Phase 1: handle controllers with state files.
	devids = state_list_ctrls();
	if (devids) {
		for (i = 0; devids[i]; i++) {
			const char *devid = devids[i];
			char *unit_name = state_read_unit(devid);

			if (!unit_name) {
				free(devids[i]);
				continue;
			}

			if (nvme_dev_exists(devid)) {
				// Device alive: read its TID, track it.
				bool is_dc = false;
				struct libnvmf_tid *t =
					sysfs_read_tid(devid, &is_dc);

				if (t) {
					struct active_ctrl *e;

					ctrl_add(unit_name, t, is_dc);
					e = ctrl_find_by_unit(unit_name);
					if (e)
						e->devname = strdup(devid);

					/*
					 * An adopted DC produces no device-add
					 * event, so warm its DLP here.
					 * Otherwise its DLP-sourced IOCs never
					 * enter the desired set and would not
					 * be reconnected if they drop after a
					 * warm restart.
					 */
					if (is_dc)
						fetch_and_process_dlp(devid, t);

					tid_free(t);
				}
			} else {
				/*
				 * Device gone while we were down. Reconnect
				 * unless another orchestrator has since taken
				 * ownership (an intentional handoff while we
				 * were down) -- there is no TID available
				 * here to also run the exclusion check
				 * against, since state files don't store
				 * transport parameters, only the registry
				 * lookup by device name is possible.
				 */
				char *owner = NULL;
				int r = libnvmf_registry_retrieve(
						ctx.nvme_ctx, devid, "owner",
						&owner);

				if (r == -ENOENT)
					r = 0;
				if (r < 0) {
					disc_warn("%s - failed to check registry owner: %s",
						  devid, strerror(-r));
				} else if (owner &&
					   strcmp(owner, "discoverd") &&
					   strcmp(owner, "nbft")) {
					disc_info("%s - owned by '%s', not reconnecting",
						  devid, owner);
				} else {
					unit_restart(ctx.umgr, unit_name);
				}
				free(owner);
			}

			free(unit_name);
			free(devids[i]);
		}
		free(devids);
	}

	// Phase 2: find pre-existing connections without state files.
	{
		DIR *d = opendir("/sys/class/nvme");
		struct dirent *ent;

		if (!d)
			return;

		while ((ent = readdir(d))) {
			const char *devname = ent->d_name;
			char *existing_unit;
			struct libnvmf_tid *t;
			bool is_nbft, is_dc;

			if (devname[0] == '.')
				continue;
			existing_unit = state_read_unit(devname);
			if (existing_unit) {
				free(existing_unit);
				continue;
			}

			t = sysfs_read_tid(devname, &is_dc);
			if (!t)
				continue;

			if (!cache_is_desired(ctx.cache, t)) {
				disc_info("%s | %s - not desired, skipping",
					  libnvmf_tid_str(t), devname);
				tid_free(t);
				continue;
			}

			is_nbft = cache_is_nbft(ctx.cache, t);
			if (should_connect(t, devname))
				start_ctrl(t, is_dc, is_nbft, NULL);
			tid_free(t);
		}
		closedir(d);
	}
}

static void connect_desired(void)
{
	struct libnvmf_tid **dcs, **iocs;
	int i;

	dcs = cache_desired_dcs(ctx.cache);
	if (dcs) {
		for (i = 0; dcs[i]; i++) {
			bool is_nbft = cache_is_nbft(ctx.cache, dcs[i]);

			if (should_connect(dcs[i], NULL))
				start_ctrl(dcs[i], true, is_nbft, NULL);
			tid_free(dcs[i]);
		}
		free(dcs);
	}

	iocs = cache_desired_iocs(ctx.cache);
	if (iocs) {
		for (i = 0; iocs[i]; i++) {
			bool is_nbft = cache_is_nbft(ctx.cache, iocs[i]);

			if (should_connect(iocs[i], NULL))
				start_ctrl(iocs[i], false, is_nbft, NULL);
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

	sd_notify(0, "RELOADING=1\n"
		     "STATUS=Reloading configuration...");

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
	cache_load_config(ctx.cache, ctx.fabrics_cfg);

	// Connect any newly added desired controllers (no disconnects).
	connect_desired();

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

int main(int argc, char **argv)
{
	static const struct events_cbacks cbacks = {
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

	ctx.cache = cache_new();
	if (!ctx.cache)
		return 1;

	if (ctx.cfg->nbft)
		cache_load_nbft(ctx.cache, ctx.nvme_ctx);
	cache_load_config(ctx.cache, ctx.fabrics_cfg);

	ctx.umgr = unit_mgr_new(ctx.bus, ctx.event, on_job_done, NULL,
				nvme_path_abs);
	if (!ctx.umgr)
		return 1;

	ctx.evts = events_start(ctx.event, &cbacks, NULL);
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

	// Startup: adopt existing connections, then connect the desired set.
	startup_audit();
	connect_desired();

	/*
	 * One-shot startup FC kickstart: mimics nvmefc-boot-connections.service
	 * (which discoverd replaces). Always issued — fc_kickstart() is a
	 * no-op (returns 0 on ENOENT) when no FC HBA is present, so it is
	 * harmless on non-FC hosts. Independent of the periodic-kickstart
	 * knob below.
	 */
	fc_kickstart();

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

	events_stop(ctx.evts);
	unit_mgr_free(ctx.umgr);
	free(nvme_path_abs);
	free(config_path_abs);
	cache_free(ctx.cache);
	config_free(ctx.cfg);
	libnvmf_config_free(ctx.fabrics_cfg);
	libnvme_free_global_ctx(ctx.nvme_ctx);
	sd_bus_unref(ctx.bus);
	sd_event_unref(ctx.event);

	return r < 0 ? 1 : 0;
}
