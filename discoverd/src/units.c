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
#include <systemd/sd-bus.h>

#include "log.h"
#include "state.h"
#include "units.h"

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
 * itself when building each unit: the runtime directory (/run, via the STATE_*
 * paths in state.h) and the unit name.  The per-unit devid file is
 * STATE_UNITS_DIR/<unit-name-without-.service>.devid; the connect writes the
 * kernel device name into it and the ExecStartPost/ExecStop/ExecStopPost shell
 * commands (built in build_start_transient) read it back.
 */
static int unit_devid_path(char *buf, size_t len, const char *unit_name)
{
	static const char suffix[] = ".service";
	size_t slen = sizeof(suffix) - 1;
	size_t n = strlen(unit_name);

	if (n > slen && !strcmp(unit_name + n - slen, suffix))
		n -= slen;

	return snprintf(buf, len, STATE_UNITS_DIR "/%.*s.devid",
			(int)n, unit_name);
}

/* Tracked pending systemd job. */
struct pending_job {
	struct pending_job *next;
	char *job_path;
	char *unit_name;
};

struct unit_mgr {
	sd_bus *bus;
	sd_event *event;
	unit_job_cback cback;
	void *user_data;
	struct pending_job *jobs;
	sd_bus_slot *job_removed_slot;
	/* nvme binary the transient units exec; borrowed (lives for argv's life). */
	const char *nvme_path;
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
			     const char **argv, bool ignore)
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
	for (const char **a = argv; *a; a++) {
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
	j->next = mgr->jobs;
	mgr->jobs = j;
	return 0;
}

static int job_removed_handler(sd_bus_message *m, void *user_data,
				sd_bus_error *ret_err __attribute__((unused)))
{
	struct unit_mgr *mgr = user_data;
	struct pending_job **ep, *e;
	uint32_t id;
	const char *job_path, *unit_name, *result;
	int r;

	r = sd_bus_message_read(m, "uoss", &id, &job_path, &unit_name, &result);
	if (r < 0)
		return 0;

	for (ep = &mgr->jobs; *ep; ep = &(*ep)->next) {
		e = *ep;
		if (!streq(e->job_path, job_path))
			continue;

		*ep = e->next;
		if (mgr->cback)
			mgr->cback(e->unit_name,
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
			       unit_job_cback cback, void *user_data,
			       const char *nvme_path)
{
	struct unit_mgr *mgr;
	int r;

	mgr = calloc(1, sizeof(*mgr));
	if (!mgr)
		return NULL;

	mgr->bus = bus;
	mgr->event = event;
	mgr->cback = cback;
	mgr->user_data = user_data;
	mgr->nvme_path = (nvme_path && *nvme_path) ? nvme_path : NVME_PATH;

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
		disc_err("sd_bus_match_signal(JobRemoved): %s", strerror(-r));
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
	sd_bus_slot_unref(mgr->job_removed_slot);
	for (e = mgr->jobs; e; e = next) {
		next = e->next;
		free(e->job_path);
		free(e->unit_name);
		free(e);
	}
	free(mgr);
}

/*
 * Internal: call StartTransientUnit and track the returned job.
 *
 * Caller has built the message up through the properties array and must
 * close the properties array container and the aux array before calling.
 * We call sd_bus_call() synchronously — StartTransientUnit only enqueues a
 * systemd job; the actual nvme-connect subprocess is managed by systemd and
 * reports back via JobRemoved.
 */
static int do_start_transient(struct unit_mgr *mgr, sd_bus_message *msg,
			       const char *unit_name)
{
	sd_bus_error err = SD_BUS_ERROR_NULL;
	sd_bus_message *reply = NULL;
	const char *job_path;
	int r;

	r = sd_bus_call(mgr->bus, msg, 0, &err, &reply);
	if (r < 0) {
		disc_err("StartTransientUnit(%s): %s",
			 unit_name, err.message ?: strerror(-r));
		sd_bus_error_free(&err);
		return r;
	}

	r = sd_bus_message_read(reply, "o", &job_path);
	if (r < 0)
		goto out;

	r = track_job(mgr, job_path, unit_name);
out:
	sd_bus_message_unref(reply);
	return r;
}

/*
 * Build a StartTransientUnit message for an nvme connect unit.
 *
 * connect_argv is a NULL-terminated argv starting at the nvme binary path.
 * desc is the Description= value.
 * is_fc determines whether After=network.target is added.
 */
static int build_start_transient(struct unit_mgr *mgr, const char *unit_name,
				  const char *devid_path, const char *desc,
				  bool is_fc, const char **connect_argv,
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
	r = sd_bus_message_append(m, "ss", unit_name, "replace");
	if (r < 0)
		goto err;

	/* Open the properties array a(sv). */
	r = sd_bus_message_open_container(m, 'a', "(sv)");
	if (r < 0)
		goto err;

	r = append_string_prop(m, "Type", "oneshot");
	if (r < 0)
		goto err;
	r = append_bool_prop(m, "RemainAfterExit", true);
	if (r < 0)
		goto err;
	r = append_string_prop(m, "Description", desc);
	if (r < 0)
		goto err;
	r = append_string_prop(m, "CollectMode", "inactive-or-failed");
	if (r < 0)
		goto err;
	r = append_uint64_prop(m, "TimeoutStopUSec",
			       DISCONNECT_TIMEOUT_SEC * UINT64_C(1000000));
	if (r < 0)
		goto err;

	/* Ordering: Before=nvme-discoverd.service always. */
	{
		static const char *const before[] = { "nvme-discoverd.service", NULL };

		r = append_strv_prop(m, "Before", before);
		if (r < 0)
			goto err;
	}

	/* After=network.target for TCP/RDMA (omit for FC). */
	if (!is_fc) {
		static const char *const after[] = { "network.target", NULL };

		r = append_strv_prop(m, "After", after);
		if (r < 0)
			goto err;
	}

	r = append_exec_prop(m, "ExecStart", connect_argv, false);
	if (r < 0)
		goto err;

	/*
	 * Build the post/stop shell commands with the real devid path, state
	 * directory and unit name substituted (systemd does not expand %t/%N/%n
	 * here — see unit_devid_path()).  The nvme path in ExecStop is
	 * double-quoted to tolerate spaces.
	 */
	{
		char exec_start_post[512];
		char exec_stop[PATH_MAX + 512];
		char exec_stop_post[512];
		int n1, n2, n3;

		n1 = snprintf(exec_start_post, sizeof(exec_start_post),
			      "DEV=$(cat %s 2>/dev/null) && "
			      "mkdir -p %s/$DEV && "
			      "echo %s > %s/$DEV/unit",
			      devid_path, STATE_CTRLS_DIR,
			      unit_name, STATE_CTRLS_DIR);

		n2 = snprintf(exec_stop, sizeof(exec_stop),
			      "DEV=$(cat %s 2>/dev/null); "
			      "[ -n \"$DEV\" ] && "
			      "[ \"$(cat %s/$DEV/unit 2>/dev/null)\" = \"%s\" ] && "
			      "\"%s\" disconnect -d $DEV",
			      devid_path, STATE_CTRLS_DIR, unit_name,
			      mgr->nvme_path);

		n3 = snprintf(exec_stop_post, sizeof(exec_stop_post),
			      "DEV=$(cat %s 2>/dev/null); "
			      "rm -f %s; "
			      "[ -n \"$DEV\" ] && "
			      "[ \"$(cat %s/$DEV/unit 2>/dev/null)\" = \"%s\" ] && "
			      "rm -rf %s/$DEV",
			      devid_path, devid_path, STATE_CTRLS_DIR,
			      unit_name, STATE_CTRLS_DIR);

		if (n1 < 0 || n1 >= (int)sizeof(exec_start_post) ||
		    n2 < 0 || n2 >= (int)sizeof(exec_stop) ||
		    n3 < 0 || n3 >= (int)sizeof(exec_stop_post)) {
			r = -ENAMETOOLONG;
			goto err;
		}

		r = append_shell_exec_prop(m, "ExecStartPost", exec_start_post);
		if (r < 0)
			goto err;
		r = append_shell_exec_prop(m, "ExecStop", exec_stop);
		if (r < 0)
			goto err;
		r = append_shell_exec_prop(m, "ExecStopPost", exec_stop_post);
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
 * Build the nvme-connect argv into s->argv[] and return it.
 * @params: resolved connect parameters to emit (kato, ctrl-loss-tmo, tls, …).
 * is_nbft: use --owner=nbft; otherwise --owner=discoverd.
 * Strings are formatted into the provided scratch buffers (in the struct);
 * the TID fields and params share the extra[] pool.
 */
#define MAX_EXTRA_ARGS 40
struct connect_scratch {
	char owner[32];
	char devid_arg[160];
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
};

static void emit_arg(const char *arg, void *user_data)
{
	struct emit_ctx *e = user_data;
	struct connect_scratch *s = e->s;

	if (s->n_extra >= MAX_EXTRA_ARGS ||
	    *e->argc >= (int)ARRAY_SIZE(s->argv) - 4)
		return; // leave room for --idempotent, owner, devid-file, NULL
	snprintf(s->extra[s->n_extra], sizeof(s->extra[0]), "%s", arg);
	s->argv[(*e->argc)++] = s->extra[s->n_extra++];
}

static int build_connect_argv(const char *nvme_bin, const char *devid_path,
			       const struct libnvmf_tid *t,
			       const struct libnvmf_params *params,
			       bool is_nbft, struct connect_scratch *s)
{
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
	r = libnvmf_connect_args_emit(t, params, emit_arg, &ec);
	if (r < 0)
		return r;

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

int unit_start_dc(struct unit_mgr *mgr, const struct libnvmf_tid *t,
		  const struct libnvmf_params *params, bool is_nbft)
{
	struct connect_scratch scratch = { };
	char desc[320];
	char devid_path[128];
	char *unit_name;
	sd_bus_message *m = NULL;
	const char *subsysnqn = libnvmf_tid_get_subsysnqn(t);
	const char *transport = libnvmf_tid_get_transport(t);
	const char *traddr = libnvmf_tid_get_traddr(t);
	const char *trsvcid = libnvmf_tid_get_trsvcid(t);
	bool is_fc;
	int r;

	unit_name = tid_unit_name(t);
	if (!unit_name)
		return -ENOMEM;

	unit_devid_path(devid_path, sizeof(devid_path), unit_name);

	r = build_connect_argv(mgr->nvme_path, devid_path, t, params, is_nbft,
			       &scratch);
	if (r < 0)
		goto out;

	snprintf(desc, sizeof(desc),
		 "NVMe Discovery Controller %s @ %s:%s",
		 subsysnqn, traddr, trsvcid ? trsvcid : "none");

	is_fc = streq0(transport, "fc");

	r = build_start_transient(mgr, unit_name, devid_path, desc, is_fc,
				   scratch.argv, &m);
	if (r < 0)
		goto out;

	r = do_start_transient(mgr, m, unit_name);
	sd_bus_message_unref(m);
out:
	free(unit_name);
	return r;
}

int unit_start_ioc(struct unit_mgr *mgr, const struct libnvmf_tid *t,
		   const struct libnvmf_params *params, bool is_nbft)
{
	struct connect_scratch scratch = { };
	char desc[320];
	char devid_path[128];
	char *unit_name;
	sd_bus_message *m = NULL;
	const char *subsysnqn = libnvmf_tid_get_subsysnqn(t);
	const char *transport = libnvmf_tid_get_transport(t);
	const char *traddr = libnvmf_tid_get_traddr(t);
	const char *trsvcid = libnvmf_tid_get_trsvcid(t);
	bool is_fc;
	int r;

	unit_name = tid_unit_name(t);
	if (!unit_name)
		return -ENOMEM;

	unit_devid_path(devid_path, sizeof(devid_path), unit_name);

	r = build_connect_argv(mgr->nvme_path, devid_path, t, params, is_nbft,
			       &scratch);
	if (r < 0)
		goto out;

	snprintf(desc, sizeof(desc),
		 "NVMe I/O Controller %s @ %s:%s",
		 subsysnqn, traddr, trsvcid ? trsvcid : "none");

	is_fc = streq0(transport, "fc");

	r = build_start_transient(mgr, unit_name, devid_path, desc, is_fc,
				   scratch.argv, &m);
	if (r < 0)
		goto out;

	r = do_start_transient(mgr, m, unit_name);
	sd_bus_message_unref(m);
out:
	free(unit_name);
	return r;
}

int unit_restart(struct unit_mgr *mgr, const char *unit_name)
{
	sd_bus_error err = SD_BUS_ERROR_NULL;
	sd_bus_message *reply = NULL;
	const char *job_path;
	int r;

	r = sd_bus_call_method(mgr->bus,
			       SYSTEMD_BUS_NAME, SYSTEMD_OBJ_PATH,
			       SYSTEMD_MGR_IFACE, "RestartUnit",
			       &err, &reply, "ss", unit_name, "replace");
	if (r < 0) {
		disc_err("RestartUnit(%s): %s",
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

	r = sd_bus_call_method(mgr->bus,
			       SYSTEMD_BUS_NAME, SYSTEMD_OBJ_PATH,
			       SYSTEMD_MGR_IFACE, "StopUnit",
			       &err, NULL, "ss", unit_name, "replace");
	if (r < 0) {
		disc_err("StopUnit(%s): %s",
			 unit_name, err.message ?: strerror(-r));
		sd_bus_error_free(&err);
	}
	return r;
}

int unit_reset_failed(struct unit_mgr *mgr, const char *unit_name)
{
	sd_bus_error err = SD_BUS_ERROR_NULL;
	int r;

	r = sd_bus_call_method(mgr->bus,
			       SYSTEMD_BUS_NAME, SYSTEMD_OBJ_PATH,
			       SYSTEMD_MGR_IFACE, "ResetFailedUnit",
			       &err, NULL, "s", unit_name);
	if (r < 0) {
		disc_err("ResetFailedUnit(%s): %s",
			 unit_name, err.message ?: strerror(-r));
		sd_bus_error_free(&err);
	}
	return r;
}
