// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <systemd/sd-bus.h>

#include <ccan/array_size/array_size.h>
#include <ccan/list/list.h>

#include <daemon-util/log.h>
#include <shared/cleanup-util.h>
#include <shared/time-util.h>

#include "state.h"
#include "sysfs.h"
#include "unit-spec.h"
#include "units.h"
#include "units-local.h"

/*
 * NVME_PATH is the absolute path to the nvme binary the transient units exec.
 * The build system supplies it from <sbindir>/nvme (see discoverd/meson.build)
 * rather than hardcoding it here.  It is the default; the --nvme-path command
 * line option overrides it (e.g. to run the daemon from a build tree), plumbed
 * through unit_mgr->nvme_path.
 */
#ifndef NVME_PATH
#error "NVME_PATH must be defined by the build system (<sbindir>/nvme)"
#endif

#define SH_PATH         "/bin/sh"

/*
 * systemd does NOT expand specifiers (%t, %N, %n) in a transient unit's Exec
 * arguments passed over the D-Bus StartTransientUnit API — that expansion only
 * happens when parsing a unit *file*.  So discoverd substitutes the real values
 * itself when building each unit: the state directory (state_units_dir() and
 * state_ctrls_dir() in state.h) and the unit name.  The per-unit devid file is
 * <state_units_dir()>/<unit-name-without-.service>.devid; the connect writes
 * the kernel device name into it and the ExecStartPost/ExecStop/ExecStopPost
 * shell commands (built in connection_commands()) read it back.
 */
static int unit_devid_path(char *buf, size_t len, const char *unit_name)
{
	static const char suffix[] = ".service";
	size_t slen = sizeof(suffix) - 1;
	size_t n = strlen(unit_name);

	if (n > slen && !strcmp(unit_name + n - slen, suffix))
		n -= slen;

	int r = snprintf(buf, len, "%s/%.*s.devid", state_units_dir(),
			 (int)n, unit_name);

	return r < 0 || (size_t)r >= len ? -ENAMETOOLONG : 0;
}

/* Tracked pending systemd job. */
struct pending_job {
	struct list_node entry;
	char *job_path;
	char *unit_name;
};

struct unit_mgr {
	sd_bus *bus;
	sd_event *event;
	unit_job_callback callback;
	void *user_data;
	struct list_head jobs;
	sd_bus_slot *job_removed_slot;
	/* nvme binary the transient units exec; borrowed (lives for argv's life). */
	const char *nvme_path;
	/* Set when the units run locally instead of through systemd. */
	struct local_units *local;
};

/*
 * These functions append a single (name, sv) struct to an already-open
 * container of type a(sv).
 */

static int append_string_prop(sd_bus_message *m, const char *name,
			       const char *val)
{
	int r;

	r = sd_bus_message_open_container(m, 'r', "sv");
	if (r < 0)
		return r;
	r = sd_bus_message_append_basic(m, 's', name);
	if (r < 0)
		return r;
	r = sd_bus_message_open_container(m, 'v', "s");
	if (r < 0)
		return r;
	r = sd_bus_message_append_basic(m, 's', val);
	if (r < 0)
		return r;
	r = sd_bus_message_close_container(m);
	if (r < 0)
		return r;
	return sd_bus_message_close_container(m);
}

static int append_bool_prop(sd_bus_message *m, const char *name, bool val)
{
	int bv = val ? 1 : 0;
	int r;

	r = sd_bus_message_open_container(m, 'r', "sv");
	if (r < 0)
		return r;
	r = sd_bus_message_append_basic(m, 's', name);
	if (r < 0)
		return r;
	r = sd_bus_message_open_container(m, 'v', "b");
	if (r < 0)
		return r;
	r = sd_bus_message_append_basic(m, 'b', &bv);
	if (r < 0)
		return r;
	r = sd_bus_message_close_container(m);
	if (r < 0)
		return r;
	return sd_bus_message_close_container(m);
}

static int append_uint64_prop(sd_bus_message *m, const char *name,
			       uint64_t val)
{
	int r;

	r = sd_bus_message_open_container(m, 'r', "sv");
	if (r < 0)
		return r;
	r = sd_bus_message_append_basic(m, 's', name);
	if (r < 0)
		return r;
	r = sd_bus_message_open_container(m, 'v', "t");
	if (r < 0)
		return r;
	r = sd_bus_message_append_basic(m, 't', &val);
	if (r < 0)
		return r;
	r = sd_bus_message_close_container(m);
	if (r < 0)
		return r;
	return sd_bus_message_close_container(m);
}

/* Append a string-array property: (name, a(s)). */
static int append_strv_prop(sd_bus_message *m, const char *name,
			     const char *const *strv)
{
	int r;

	r = sd_bus_message_open_container(m, 'r', "sv");
	if (r < 0)
		return r;
	r = sd_bus_message_append_basic(m, 's', name);
	if (r < 0)
		return r;
	r = sd_bus_message_open_container(m, 'v', "as");
	if (r < 0)
		return r;
	r = sd_bus_message_open_container(m, 'a', "s");
	if (r < 0)
		return r;
	for (; *strv; strv++) {
		r = sd_bus_message_append_basic(m, 's', *strv);
		if (r < 0)
			return r;
	}
	r = sd_bus_message_close_container(m);
	if (r < 0)
		return r;
	r = sd_bus_message_close_container(m);
	if (r < 0)
		return r;
	return sd_bus_message_close_container(m);
}

/*
 * Append an exec property (ExecStart, ExecStop, etc.) with a single entry.
 * argv[0] must be the executable path; argv is NULL-terminated.
 * ignore=true means non-zero exit is acceptable (the `-` prefix).
 */
static int append_exec_prop(sd_bus_message *m, const char *name,
			     const char *const *argv, bool ignore)
{
	int bv = ignore ? 1 : 0;
	int r;

	r = sd_bus_message_open_container(m, 'r', "sv");
	if (r < 0)
		return r;
	r = sd_bus_message_append_basic(m, 's', name);
	if (r < 0)
		return r;
	r = sd_bus_message_open_container(m, 'v', "a(sasb)");
	if (r < 0)
		return r;
	r = sd_bus_message_open_container(m, 'a', "(sasb)");
	if (r < 0)
		return r;

	r = sd_bus_message_open_container(m, 'r', "sasb");
	if (r < 0)
		return r;
	r = sd_bus_message_append_basic(m, 's', argv[0]);
	if (r < 0)
		return r;
	r = sd_bus_message_open_container(m, 'a', "s");
	if (r < 0)
		return r;
	for (const char *const *a = argv; *a; a++) {
		r = sd_bus_message_append_basic(m, 's', *a);
		if (r < 0)
			return r;
	}
	r = sd_bus_message_close_container(m); // as
	if (r < 0)
		return r;
	r = sd_bus_message_append_basic(m, 'b', &bv);
	if (r < 0)
		return r;
	r = sd_bus_message_close_container(m); // r sasb
	if (r < 0)
		return r;

	r = sd_bus_message_close_container(m); // a(sasb)
	if (r < 0)
		return r;
	r = sd_bus_message_close_container(m); // v
	if (r < 0)
		return r;
	return sd_bus_message_close_container(m); // r sv
}

/* Append a shell-command exec property with ignore=true. */
static int append_shell_exec_prop(sd_bus_message *m, const char *name,
				   const char *cmd)
{
	const char *argv[] = { SH_PATH, "-c", cmd, NULL };

	return append_exec_prop(m, name, argv, true);
}

static int track_job(struct unit_mgr *mgr, const char *job_path,
		     const char *unit_name)
{
	struct pending_job *j;

	j = calloc(1, sizeof(*j));
	if (!j)
		return -ENOMEM;
	j->job_path = strdup(job_path);
	j->unit_name = strdup(unit_name);
	if (!j->job_path || !j->unit_name) {
		free(j->job_path);
		free(j->unit_name);
		free(j);
		return -ENOMEM;
	}
	list_add(&mgr->jobs, &j->entry);
	return 0;
}

static int job_removed_handler(sd_bus_message *m, void *user_data,
				sd_bus_error *ret_err __attribute__((unused)))
{
	struct unit_mgr *mgr = user_data;
	struct pending_job *e;
	uint32_t id;
	const char *job_path, *unit_name, *result;
	int r;

	r = sd_bus_message_read(m, "uoss", &id, &job_path, &unit_name, &result);
	if (r < 0)
		return 0;

	list_for_each(&mgr->jobs, e, entry) {
		if (!streq(e->job_path, job_path))
			continue;

		list_del_init(&e->entry);
		if (mgr->callback)
			mgr->callback(e->unit_name,
				   streq(result, "done"),
				   mgr->user_data);
		free(e->job_path);
		free(e->unit_name);
		free(e);
		return 0;
	}
	return 0;
}

struct unit_mgr *unit_mgr_new(sd_bus *bus, sd_event *event,
			       unit_job_callback callback, void *user_data,
			       const char *nvme_path)
{
	struct unit_mgr *mgr;
	int r;

	mgr = calloc(1, sizeof(*mgr));
	if (!mgr)
		return NULL;

	mgr->bus = bus;
	mgr->event = event;
	mgr->callback = callback;
	mgr->user_data = user_data;
	mgr->nvme_path = (nvme_path && *nvme_path) ? nvme_path : NVME_PATH;
	list_head_init(&mgr->jobs);

	/*
	 * Subscribe to JobRemoved before any units are created.  The bus must
	 * already be attached to the event loop (sd_bus_attach_event) by the
	 * caller so that the signal is dispatched through the event loop.
	 */
	r = sd_bus_match_signal(bus, &mgr->job_removed_slot,
				SYSTEMD_BUS_NAME, SYSTEMD_OBJ_PATH,
				SYSTEMD_MGR_IFACE, "JobRemoved",
				job_removed_handler, mgr);
	if (r < 0) {
		log_err("sd_bus_match_signal(JobRemoved): %s", strerror(-r));
		free(mgr);
		return NULL;
	}

	return mgr;
}

struct unit_mgr *unit_mgr_new_local(sd_event *event, const char *dir,
				     unit_job_callback callback,
				     void *user_data, const char *nvme_path)
{
	struct unit_mgr *mgr;

	mgr = calloc(1, sizeof(*mgr));
	if (!mgr)
		return NULL;

	mgr->event = event;
	mgr->callback = callback;
	mgr->user_data = user_data;
	mgr->nvme_path = (nvme_path && *nvme_path) ? nvme_path : NVME_PATH;
	list_head_init(&mgr->jobs);

	mgr->local = local_units_new(event, dir, callback, user_data);
	if (!mgr->local) {
		free(mgr);
		return NULL;
	}

	return mgr;
}

void unit_mgr_free(struct unit_mgr *mgr)
{
	struct pending_job *e, *next;

	if (!mgr)
		return;
	local_units_free(mgr->local);
	sd_bus_slot_unref(mgr->job_removed_slot);
	list_for_each_safe(&mgr->jobs, e, next, entry) {
		free(e->job_path);
		free(e->unit_name);
		free(e);
	}
	free(mgr);
}

bool unit_exists(struct unit_mgr *mgr, const char *unit_name)
{
	sd_bus_error err = SD_BUS_ERROR_NULL;
	int r;

	if (mgr->local)
		return local_units_exists(mgr->local, unit_name);

	r = sd_bus_call_method(mgr->bus, SYSTEMD_BUS_NAME, SYSTEMD_OBJ_PATH,
			       SYSTEMD_MGR_IFACE, "GetUnit",
			       &err, NULL, "s", unit_name);
	sd_bus_error_free(&err);

	return r != -ENOENT;
}

char *unit_read_devid(const char *unit_name)
{
	char path[PATH_MAX];
	char buf[256];
	char *nl;
	FILE *f;

	if (unit_devid_path(path, sizeof(path), unit_name) < 0)
		return NULL;

	f = fopen(path, "r");
	if (!f)
		return NULL;

	nl = fgets(buf, sizeof(buf), f);
	fclose(f);
	if (!nl)
		return NULL;

	nl = strchr(buf, '\n');
	if (nl)
		*nl = '\0';

	return buf[0] ? strdup(buf) : NULL;
}

/*
 * Wait for @unit_name to stop being loaded, up to roughly
 * UNIT_GONE_TIMEOUT_MSEC. StopUnit() only enqueues the stop; the unit stays
 * loaded until that job runs and systemd garbage-collects it, which measures
 * in tens of milliseconds. Polling avoids needing the event loop to run,
 * since the caller is inside a synchronous D-Bus call, and the bound keeps a
 * unit that refuses to go away from wedging the daemon.
 *
 * Return: true once the name is free, false if it is still loaded.
 */
#define UNIT_GONE_POLL_MSEC	10
#define UNIT_GONE_TIMEOUT_MSEC	2000

static bool unit_wait_gone(struct unit_mgr *mgr, const char *unit_name)
{
	int i;

	for (i = 0; i < UNIT_GONE_TIMEOUT_MSEC / UNIT_GONE_POLL_MSEC; i++) {
		if (!unit_exists(mgr, unit_name))
			return true;

		usleep(UNIT_GONE_POLL_MSEC * 1000);
	}

	return false;
}

static void unit_spec_clear(struct unit_spec *s)
{
	free(s->exec_start_post);
	free(s->exec_stop);
	free(s->exec_stop_post);
}

#define __cleanup_unit_spec __attribute__((cleanup(unit_spec_clear)))

/*
 * Build the post/stop shell commands of connection unit @unit_name with the
 * real devid path, state directory and unit name substituted (systemd does
 * not expand %t/%N/%n here — see unit_devid_path()). The nvme path in
 * ExecStop is double-quoted to tolerate spaces.
 */
static int connection_commands(const struct unit_mgr *mgr,
			       const char *unit_name, const char *devid_path,
			       struct unit_spec *s)
{
	__cleanup_free char *nvme_dir = sysfs_path("/sys/class/nvme");
	const char *ctrls = state_ctrls_dir();

	if (!nvme_dir)
		return -ENOMEM;

	if (asprintf(&s->exec_start_post,
		     "set -e; "
		     "DEV=$(cat %s 2>/dev/null); "
		     "mkdir -p %s/$DEV; "
		     "echo %s > %s/$DEV/unit; "
		     "stat -Lc %%i %s/$DEV > %s/$DEV/ino",
		     devid_path, ctrls, unit_name, ctrls,
		     nvme_dir, ctrls) < 0) {
		s->exec_start_post = NULL;
		return -ENOMEM;
	}

	/*
	 * The kernel reuses device names. The inode check makes sure
	 * $DEV is still the controller this unit connected.
	 */
	if (asprintf(&s->exec_stop,
		     "DEV=$(cat %s 2>/dev/null); "
		     "[ -n \"$DEV\" ] || exit 0; "
		     "UNIT=$(cat %s/$DEV/unit 2>/dev/null); "
		     "[ \"$UNIT\" = \"%s\" ] || exit 0; "
		     "INO=$(cat %s/$DEV/ino 2>/dev/null); "
		     "CUR=$(stat -Lc %%i %s/$DEV 2>/dev/null); "
		     "[ \"$CUR\" = \"$INO\" ] || exit 0; "
		     "\"%s\" disconnect -d $DEV",
		     devid_path, ctrls, unit_name, ctrls,
		     nvme_dir, mgr->nvme_path) < 0) {
		s->exec_stop = NULL;
		return -ENOMEM;
	}

	if (asprintf(&s->exec_stop_post,
		     "DEV=$(cat %s 2>/dev/null); "
		     "rm -f %s; "
		     "[ -n \"$DEV\" ] || exit 0; "
		     "UNIT=$(cat %s/$DEV/unit 2>/dev/null); "
		     "[ \"$UNIT\" = \"%s\" ] || exit 0; "
		     "rm -rf %s/$DEV",
		     devid_path, devid_path, ctrls,
		     unit_name, ctrls) < 0) {
		s->exec_stop_post = NULL;
		return -ENOMEM;
	}

	return 0;
}

/* Build the StartTransientUnit message for @s. */
static int spec_to_message(struct unit_mgr *mgr, const struct unit_spec *s,
			   sd_bus_message **out)
{
	sd_bus_message *m = NULL;
	int r;

	r = sd_bus_message_new_method_call(mgr->bus, &m,
					   SYSTEMD_BUS_NAME,
					   SYSTEMD_OBJ_PATH,
					   SYSTEMD_MGR_IFACE,
					   "StartTransientUnit");
	if (r < 0)
		return r;

	/* Name and mode. */
	r = sd_bus_message_append(m, "ss", s->name, "replace");
	if (r < 0)
		goto err;

	/* Open the properties array a(sv). */
	r = sd_bus_message_open_container(m, 'a', "(sv)");
	if (r < 0)
		goto err;

	r = append_string_prop(m, "Type", "oneshot");
	if (r < 0)
		goto err;
	if (s->connection) {
		r = append_bool_prop(m, "RemainAfterExit", true);
		if (r < 0)
			goto err;
	}
	r = append_string_prop(m, "Description", s->description);
	if (r < 0)
		goto err;
	r = append_string_prop(m, "CollectMode", "inactive-or-failed");
	if (r < 0)
		goto err;

	if (s->connection) {
		/*
		 * Ordering: Before=nvme-discoverd.service always. At shutdown,
		 * the unit stops after the _netdev mounts are unmounted, so
		 * ExecStop= never disconnects a mounted namespace.
		 * remote-fs-pre.target is passive: Before= has no effect unless
		 * the unit also wants it.
		 */
		static const char *const before[] = {
			"nvme-discoverd.service", "remote-fs-pre.target", NULL
		};
		static const char *const wants[] = {
			"remote-fs-pre.target", NULL
		};
		static const char *const after[] = { "network.target", NULL };
		uint64_t stop_timeout = DISCONNECT_TIMEOUT_SEC *
					SHR_USEC_PER_SEC;

		r = append_uint64_prop(m, "TimeoutStopUSec", stop_timeout);
		if (r < 0)
			goto err;
		r = append_strv_prop(m, "Before", before);
		if (r < 0)
			goto err;
		r = append_strv_prop(m, "Wants", wants);
		if (r < 0)
			goto err;

		/* After=network.target for TCP/RDMA (omit for FC). */
		if (!s->is_fc) {
			r = append_strv_prop(m, "After", after);
			if (r < 0)
				goto err;
		}
	}

	r = append_exec_prop(m, "ExecStart", s->exec_start, false);
	if (r < 0)
		goto err;
	if (s->exec_start_post) {
		r = append_shell_exec_prop(m, "ExecStartPost",
					   s->exec_start_post);
		if (r < 0)
			goto err;
	}
	if (s->exec_stop) {
		r = append_shell_exec_prop(m, "ExecStop", s->exec_stop);
		if (r < 0)
			goto err;
	}
	if (s->exec_stop_post) {
		r = append_shell_exec_prop(m, "ExecStopPost",
					   s->exec_stop_post);
		if (r < 0)
			goto err;
	}

	r = sd_bus_message_close_container(m); // a(sv)
	if (r < 0)
		goto err;

	/* Empty auxiliary units array. */
	r = sd_bus_message_open_container(m, 'a', "(sa(sv))");
	if (r < 0)
		goto err;
	r = sd_bus_message_close_container(m);
	if (r < 0)
		goto err;

	*out = m;
	return 0;
err:
	sd_bus_message_unref(m);
	return r;
}

/*
 * Call StartTransientUnit for @s and track the returned job. We call
 * sd_bus_call() synchronously — StartTransientUnit only enqueues a systemd
 * job; the actual nvme-connect subprocess is managed by systemd and reports
 * back via JobRemoved. -EEXIST is left to the caller, see start_unit().
 */
static int systemd_start(struct unit_mgr *mgr, const struct unit_spec *s)
{
	sd_bus_error err = SD_BUS_ERROR_NULL;
	sd_bus_message *msg = NULL, *reply = NULL;
	const char *job_path;
	int r;

	r = spec_to_message(mgr, s, &msg);
	if (r < 0)
		return r;

	r = sd_bus_call(mgr->bus, msg, 0, &err, &reply);
	sd_bus_message_unref(msg);
	if (r < 0) {
		if (r != -EEXIST)
			log_err("StartTransientUnit(%s): %s",
				s->name, err.message ?: strerror(-r));
		sd_bus_error_free(&err);
		return r;
	}

	r = sd_bus_message_read(reply, "o", &job_path);
	if (r >= 0)
		r = track_job(mgr, job_path, s->name);

	sd_bus_message_unref(reply);
	return r;
}

static int backend_start(struct unit_mgr *mgr, const struct unit_spec *s)
{
	if (mgr->local)
		return local_units_start(mgr->local, s);

	return systemd_start(mgr, s);
}

/* Start the transient unit @s. */
static int start_unit(struct unit_mgr *mgr, const struct unit_spec *s)
{
	int r = backend_start(mgr, s);

	if (r != -EEXIST)
		return r;

	/*
	 * A unit from an earlier daemon lifetime still holds the name. Its
	 * connection is gone and its parameters may be stale, so replace it
	 * rather than restart it.
	 */
	log_info("%s - name held by a stale unit, replacing it", s->name);
	unit_stop(mgr, s->name);
	if (!unit_wait_gone(mgr, s->name)) {
		log_warn("%s - still loaded after stop, giving up", s->name);
		return r;
	}

	return backend_start(mgr, s);
}

/*
 * Build the nvme-connect argv into s->argv[] and return it.
 * @params: resolved connect parameters to emit (kato, ctrl-loss-tmo, tls, …).
 * is_nbft: use --owner=nbft; otherwise --owner=discoverd.
 * Strings are formatted into the provided scratch buffers (in the struct);
 * the TID fields and params share the extra[] pool.
 */
#define MAX_EXTRA_ARGS 40
struct connect_scratch {
	char owner[32];
	char devid_arg[PATH_MAX + 16];
	char extra[MAX_EXTRA_ARGS][320]; // TID fields + resolved params
	int n_extra;
	const char *argv[8 + MAX_EXTRA_ARGS];
};

/*
 * libnvmf_connect_args_emit() callback: copy one formatted option into the
 * extra[] pool.
 */
struct emit_ctx {
	struct connect_scratch *s;
	int *argc;
	bool skip_kato; // the caller emits --keep-alive-tmo itself
};

static void emit_arg(const char *arg, void *user_data)
{
	struct emit_ctx *e = user_data;
	struct connect_scratch *s = e->s;

	if (e->skip_kato && shr_startswith(arg, "--keep-alive-tmo="))
		return;
	if (s->n_extra >= MAX_EXTRA_ARGS ||
	    *e->argc >= (int)ARRAY_SIZE(s->argv) - 4)
		return; // leave room for --idempotent, owner, devid-file, NULL
	snprintf(s->extra[s->n_extra], sizeof(s->extra[0]), "%s", arg);
	s->argv[(*e->argc)++] = s->extra[s->n_extra++];
}

/*
 * The keep-alive timeout a DC connects with. A non-zero KATO asks the DC
 * for a persistent connection and for AENs (Base Spec, Discovery Service).
 * Without one, the kernel sets none for a DC.
 *
 * persistent=no: none, even if keep-alive-tmo is configured.
 * Otherwise: the configured keep-alive-tmo, or DC_DEFAULT_KATO.
 *
 * Return: the value to emit, or NULL to emit none.
 */
#define DC_DEFAULT_KATO "30"

static const char *dc_keep_alive_tmo(const struct libnvmf_params *params)
{
	const char *kato = libnvmf_params_get(params, "keep-alive-tmo");

	if (shr_streqcase0(libnvmf_params_get(params, "persistent"), "no"))
		return NULL;
	if (kato && *kato)
		return kato;

	return DC_DEFAULT_KATO;
}

static int build_connect_argv(const char *nvme_bin, const char *devid_path,
			       const struct libnvmf_tid *t,
			       const struct libnvmf_params *params,
			       bool is_dc, bool is_nbft,
			       struct connect_scratch *s)
{
	char kato_arg[32];
	struct emit_ctx ec;
	int i = 0;
	int r;

	s->argv[i++] = nvme_bin;
	s->argv[i++] = "connect";

	/*
	 * libnvmf_connect_args_emit() renders the TID's addressing/identity
	 * fields and the resolved parameters as "nvme connect" options, in
	 * that order; discoverd only appends the connect-manager-private
	 * options below (--idempotent, --owner, --devid-file).
	 */
	ec.s = s;
	ec.argc = &i;
	ec.skip_kato = is_dc;
	r = libnvmf_connect_args_emit(t, params, emit_arg, &ec);
	if (r < 0)
		return r;

	if (is_dc) {
		const char *kato = dc_keep_alive_tmo(params);

		/*
		 * Without --discovery, the kernel sees a DC with a unique
		 * NQN as an I/O controller.
		 */
		ec.skip_kato = false;
		emit_arg("--discovery", &ec);
		if (kato) {
			snprintf(kato_arg, sizeof(kato_arg),
				 "--keep-alive-tmo=%s", kato);
			emit_arg(kato_arg, &ec);
		}
	}

	s->argv[i++] = "--idempotent";
	snprintf(s->owner, sizeof(s->owner), "--owner=%s",
		 is_nbft ? "nbft" : "discoverd");
	s->argv[i++] = s->owner;
	snprintf(s->devid_arg, sizeof(s->devid_arg), "--devid-file=%s",
		 devid_path);
	s->argv[i++] = s->devid_arg;
	s->argv[i] = NULL;

	return 0;
}

static int start_connection(struct unit_mgr *mgr,
			    const struct libnvmf_tid *t,
			    const struct libnvmf_params *params,
			    bool is_dc, bool is_nbft)
{
	__cleanup_unit_spec struct unit_spec spec = { };
	struct connect_scratch scratch = { };
	char desc[320];
	char devid_path[PATH_MAX];
	__cleanup_free char *unit_name = tid_unit_name(t);
	const char *trsvcid = libnvmf_tid_get_trsvcid(t);
	int r;

	if (!unit_name)
		return -ENOMEM;

	r = unit_devid_path(devid_path, sizeof(devid_path), unit_name);
	if (r < 0)
		return r;

	r = build_connect_argv(mgr->nvme_path, devid_path, t, params, is_dc,
			       is_nbft, &scratch);
	if (r < 0)
		return r;

	snprintf(desc, sizeof(desc), "NVMe %s Controller %s @ %s:%s",
		 is_dc ? "Discovery" : "I/O", libnvmf_tid_get_subsysnqn(t),
		 libnvmf_tid_get_traddr(t), trsvcid ? trsvcid : "none");

	spec.name = unit_name;
	spec.description = desc;
	spec.connection = true;
	spec.is_fc = shr_streq0(libnvmf_tid_get_transport(t), "fc");
	spec.exec_start = scratch.argv;

	r = connection_commands(mgr, unit_name, devid_path, &spec);
	if (r < 0)
		return r;

	return start_unit(mgr, &spec);
}

int unit_start_dc(struct unit_mgr *mgr, const struct libnvmf_tid *t,
		  const struct libnvmf_params *params, bool is_nbft)
{
	return start_connection(mgr, t, params, true, is_nbft);
}

int unit_start_ioc(struct unit_mgr *mgr, const struct libnvmf_tid *t,
		   const struct libnvmf_params *params, bool is_nbft)
{
	return start_connection(mgr, t, params, false, is_nbft);
}

int unit_start_connect_all(struct unit_mgr *mgr, const char *devname,
			   const struct dc_addr *addr)
{
	static const char *const names[] = {
		"transport", "traddr", "trsvcid", "host-traddr", "host-iface",
	};
	const char *const vals[] = {
		addr->transport, addr->traddr, addr->trsvcid,
		addr->host_traddr, addr->host_iface,
	};
	char opts[ARRAY_SIZE(names) + 1][320];
	const char *argv[ARRAY_SIZE(names) + 5];
	__cleanup_unit_spec struct unit_spec spec = { };
	__cleanup_free char *unit_name = NULL;
	char desc[128];
	int argc = 0, n;
	size_t i;

	if (asprintf(&unit_name, "nvme-discoverd-connect-all-%s.service",
		     devname) < 0)
		return -ENOMEM;

	argv[argc++] = mgr->nvme_path;
	argv[argc++] = "connect-all";

	n = snprintf(opts[0], sizeof(opts[0]), "--device=%s", devname);
	if (n < 0 || n >= (int)sizeof(opts[0]))
		return -ENAMETOOLONG;
	argv[argc++] = opts[0];

	// The kernel reports a missing value as "none".
	for (i = 0; i < ARRAY_SIZE(names); i++) {
		if (!vals[i] || !*vals[i] || streq(vals[i], "none"))
			continue;

		n = snprintf(opts[i + 1], sizeof(opts[i + 1]), "--%s=%s",
			     names[i], vals[i]);
		if (n < 0 || n >= (int)sizeof(opts[i + 1]))
			return -ENAMETOOLONG;
		argv[argc++] = opts[i + 1];
	}

	argv[argc++] = "--quiet";
	argv[argc] = NULL;

	snprintf(desc, sizeof(desc),
		 "NVMe connect-all for Discovery Controller %s", devname);

	spec.name = unit_name;
	spec.description = desc;
	spec.exec_start = argv;

	return start_unit(mgr, &spec);
}

int unit_restart(struct unit_mgr *mgr, const char *unit_name)
{
	sd_bus_error err = SD_BUS_ERROR_NULL;
	sd_bus_message *reply = NULL;
	const char *job_path;
	int r;

	if (mgr->local)
		return local_units_restart(mgr->local, unit_name);

	r = sd_bus_call_method(mgr->bus,
			       SYSTEMD_BUS_NAME, SYSTEMD_OBJ_PATH,
			       SYSTEMD_MGR_IFACE, "RestartUnit",
			       &err, &reply, "ss", unit_name, "replace");
	if (r < 0) {
		// A failed transient unit is collected. The caller starts it.
		if (sd_bus_error_has_name(&err, SYSTEMD_NO_SUCH_UNIT))
			log_dbg("RestartUnit(%s): %s", unit_name, err.message);
		else
			log_err("RestartUnit(%s): %s",
				unit_name, err.message ?: strerror(-r));
		sd_bus_error_free(&err);
		return r;
	}

	r = sd_bus_message_read(reply, "o", &job_path);
	if (r >= 0)
		track_job(mgr, job_path, unit_name);

	sd_bus_message_unref(reply);
	return r < 0 ? r : 0;
}

int unit_stop(struct unit_mgr *mgr, const char *unit_name)
{
	sd_bus_error err = SD_BUS_ERROR_NULL;
	int r;

	if (mgr->local)
		return local_units_stop(mgr->local, unit_name);

	r = sd_bus_call_method(mgr->bus,
			       SYSTEMD_BUS_NAME, SYSTEMD_OBJ_PATH,
			       SYSTEMD_MGR_IFACE, "StopUnit",
			       &err, NULL, "ss", unit_name, "replace");
	if (r < 0) {
		log_err("StopUnit(%s): %s",
			unit_name, err.message ?: strerror(-r));
		sd_bus_error_free(&err);
	}
	return r;
}

int unit_reset_failed(struct unit_mgr *mgr, const char *unit_name)
{
	sd_bus_error err = SD_BUS_ERROR_NULL;
	int r;

	if (mgr->local)
		return local_units_reset_failed(mgr->local, unit_name);

	r = sd_bus_call_method(mgr->bus,
			       SYSTEMD_BUS_NAME, SYSTEMD_OBJ_PATH,
			       SYSTEMD_MGR_IFACE, "ResetFailedUnit",
			       &err, NULL, "s", unit_name);
	if (r < 0) {
		log_err("ResetFailedUnit(%s): %s",
			unit_name, err.message ?: strerror(-r));
		sd_bus_error_free(&err);
	}
	return r;
}
