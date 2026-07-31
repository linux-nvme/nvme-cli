// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2016 Intel Corporation. All rights reserved.
 * Copyright (c) 2016 HGST, a Western Digital Company.
 * Copyright (c) 2016 Samsung Electronics Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This file implements the discovery controller feature of NVMe over
 * Fabrics specification standard.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#ifdef NVME_HAVE_NETDB
#include <netdb.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#include <ccan/str/str.h>

#include <libnvme.h>

#ifdef NVME_HAVE_LIBKMOD
#include <libkmod.h>
#endif

#include "common.h"
#include "config-convert.h"
#include "nvme.h"
#include "nvme-print.h"
#include "fabrics.h"
#include "util/cleanup.h"
#include "logging.h"
#include "util/sighdl.h"

#define MAX_DISC_ARGS		32
#define MAX_DISC_RETRIES	10

#define NVMF_DEF_DISC_TMO	30

/* Name of file to output log pages in their raw format */
static char *raw;
static bool persistent;

static const char *nvmf_config_file	= "Use specified INI configuration file (auto-converts a legacy .json) or 'none' to disable";
static const char *nvmf_config_file_ro	= "INI configuration file (default: " PATH_NVMF_INI ")";

void nvmf_default_args(struct nvmf_args *fa)
{
	fa->tos = -1;
	fa->ctrl_loss_tmo = NVMF_DEF_CTRL_LOSS_TMO;
}

void nvmf_args_to_params(struct libnvmf_params *params,
		const struct nvmf_args *fa)
{
	char buf[32];

	if (fa->nr_io_queues) {
		snprintf(buf, sizeof(buf), "%d", fa->nr_io_queues);
		libnvmf_params_set(params, "nr-io-queues", buf);
	}
	if (fa->nr_write_queues) {
		snprintf(buf, sizeof(buf), "%d", fa->nr_write_queues);
		libnvmf_params_set(params, "nr-write-queues", buf);
	}
	if (fa->nr_poll_queues) {
		snprintf(buf, sizeof(buf), "%d", fa->nr_poll_queues);
		libnvmf_params_set(params, "nr-poll-queues", buf);
	}
	if (fa->queue_size) {
		snprintf(buf, sizeof(buf), "%d", fa->queue_size);
		libnvmf_params_set(params, "queue-size", buf);
	}
	if (fa->keep_alive_tmo) {
		snprintf(buf, sizeof(buf), "%d", fa->keep_alive_tmo);
		libnvmf_params_set(params, "keep-alive-tmo", buf);
	}
	if (fa->reconnect_delay) {
		snprintf(buf, sizeof(buf), "%d", fa->reconnect_delay);
		libnvmf_params_set(params, "reconnect-delay", buf);
	}
	if (fa->ctrl_loss_tmo != NVMF_DEF_CTRL_LOSS_TMO) {
		snprintf(buf, sizeof(buf), "%d", fa->ctrl_loss_tmo);
		libnvmf_params_set(params, "ctrl-loss-tmo", buf);
	}
	if (fa->fast_io_fail_tmo) {
		snprintf(buf, sizeof(buf), "%d", fa->fast_io_fail_tmo);
		libnvmf_params_set(params, "fast-io-fail-tmo", buf);
	}
	if (fa->tos != -1) {
		snprintf(buf, sizeof(buf), "%d", fa->tos);
		libnvmf_params_set(params, "tos", buf);
	}
	if (fa->duplicate_connect)
		libnvmf_params_set(params, "duplicate-connect", "true");
	if (fa->disable_sqflow)
		libnvmf_params_set(params, "disable-sqflow", "true");
	if (fa->hdr_digest)
		libnvmf_params_set(params, "hdr-digest", "true");
	if (fa->data_digest)
		libnvmf_params_set(params, "data-digest", "true");
	if (fa->tls)
		libnvmf_params_set(params, "tls", "true");
	if (fa->concat)
		libnvmf_params_set(params, "concat", "true");
	if (fa->hostkey)
		libnvmf_params_set(params, "dhchap-secret", fa->hostkey);
	if (fa->ctrlkey)
		libnvmf_params_set(params, "dhchap-ctrl-secret", fa->ctrlkey);
	if (fa->keyring)
		libnvmf_params_set(params, "keyring", fa->keyring);
	if (fa->tls_key)
		libnvmf_params_set(params, "tls-key", fa->tls_key);
	if (fa->tls_key_identity)
		libnvmf_params_set(params, "tls-key-identity",
				   fa->tls_key_identity);
}

static void save_discovery_log(char *raw, struct nvmf_discovery_log *log)
{
	uint64_t numrec = le64_to_cpu(log->numrec);
	int fd, len, ret;

	fd = open(raw, O_CREAT | O_RDWR | O_TRUNC, 0600);
	if (fd < 0) {
		nvme_show_error("failed to open %s: %s", raw, libnvme_strerror(errno));
		return;
	}

	len = sizeof(struct nvmf_discovery_log) + numrec * sizeof(struct nvmf_disc_log_entry);

	ret = write(fd, log, len);
	if (ret < 0)
		nvme_show_error("failed to write to %s: %s",
			raw, libnvme_strerror(errno));
	else
		nvme_show_verbose_info("Discovery log is saved to %s", raw);

	close(fd);
}

static int setup_common_context(struct libnvmf_context *fctx,
		struct nvmf_args *fa);

struct hook_fabrics_data {
	nvme_print_flags_t flags;
	char *raw;
	bool idempotent;
};

static bool hook_decide_retry(struct libnvmf_context *fctx, int err,
		void *user_data)
{
	if (err == -EAGAIN || (err == -EINTR && !nvme_sigint_received)) {
		print_debug("libnvmf_add_ctrl returned '%s'\n", libnvme_strerror(-err));
		return true;
	}

	return false;
}

static void hook_connected(struct libnvmf_context *fctx,
		struct libnvme_ctrl *c, void *user_data)
{
	struct hook_fabrics_data *hfd = user_data;

	if (hfd->flags == NORMAL) {
		nvme_show_verbose_info("connecting to device: %s", libnvme_ctrl_get_name(c));
		return;
	}

#ifdef CONFIG_JSONC
	if (hfd->flags == JSON) {
		struct json_object *root;

		root = json_create_object();

		json_object_add_value_string(root, "device",
			libnvme_ctrl_get_name(c));

		json_print_object(root, NULL);
		printf("\n");
		json_free_object(root);
	}
#endif
}

static void hook_already_connected(struct libnvmf_context *fctx,
		struct libnvme_host *host, const char *subsysnqn,
		const char *transport, const char *traddr,
		const char *trsvcid, void *user_data)
{
	struct hook_fabrics_data *hfd = user_data;

	if (nvme_args.quiet)
		return;

	if (hfd->idempotent) {
		nvme_show_verbose_info(
			"already connected to hostnqn=%s,nqn=%s,transport=%s,traddr=%s,trsvcid=%s",
			libnvme_host_get_hostnqn(host), subsysnqn,
			transport, traddr, trsvcid);
		return;
	}

	nvme_show_error("already connected to hostnqn=%s,nqn=%s,transport=%s,traddr=%s,trsvcid=%s",
		libnvme_host_get_hostnqn(host), subsysnqn,
		transport, traddr, trsvcid);
}

static void hook_discovery_log(struct libnvmf_context *fctx,
		bool connect, struct nvmf_discovery_log *log,
		uint64_t numrec, void *user_data)
{
	struct hook_fabrics_data *hfd = user_data;

	if (hfd->raw)
		save_discovery_log(hfd->raw, log);
	else if (!connect)
		nvme_show_discovery_log(log, numrec, hfd->flags);
}

/*
 * Resolve *addr in place if it names a tcp/rdma hostname; left untouched for
 * any other transport, a NULL/"none" address, or one that is already
 * numeric. Resolution is the caller's job, not libnvme's -- this is where
 * that happens.
 *
 * Deliberately crude and sequential: one blocking getaddrinfo() call at a
 * time, no threads. nvme-cli is a one-shot tool, so multiple discovery.conf
 * lines simply resolve one after another.
 */
static int nvmf_resolve_addr(const char *transport, const char **addr)
{
#ifdef NVME_HAVE_NETDB
	struct addrinfo hints = { .ai_family = AF_UNSPEC };
	struct addrinfo *host_info = NULL;
	char addrstr[NVMF_TRADDR_SIZE];
	const char *p = NULL;
	char *resolved;
	int ret;
#endif

	if (!*addr || !transport)
		return 0;
	if (strcmp(transport, "tcp") && strcmp(transport, "rdma"))
		return 0;
	if (!strcmp(*addr, "none"))
		return 0;
	if (libnvmf_traddr_is_numeric(*addr))
		return 0;

#ifdef NVME_HAVE_NETDB
	ret = getaddrinfo(*addr, NULL, &hints, &host_info);
	if (ret) {
		nvme_show_error("failed to resolve host '%s': %s",
			*addr, gai_strerror(ret));
		return -EINVAL;
	}

	switch (host_info->ai_family) {
	case AF_INET:
		p = inet_ntop(host_info->ai_family,
			&(((struct sockaddr_in *)host_info->ai_addr)->sin_addr),
			addrstr, NVMF_TRADDR_SIZE);
		break;
	case AF_INET6:
		p = inet_ntop(host_info->ai_family,
			&(((struct sockaddr_in6 *)
				host_info->ai_addr)->sin6_addr),
			addrstr, NVMF_TRADDR_SIZE);
		break;
	default:
		break;
	}

	if (!p) {
		nvme_show_error(
			"failed to resolve host '%s': unrecognized address family",
			*addr);
		freeaddrinfo(host_info);
		return -EINVAL;
	}

	freeaddrinfo(host_info);

	resolved = strdup(addrstr);
	if (!resolved)
		return -ENOMEM;

	*addr = resolved;

	return 0;
#else /* NVME_HAVE_NETDB */
	nvme_show_error(
		"hostname resolution is not available in this build; use a numeric address");
	return -ENOTSUP;
#endif /* NVME_HAVE_NETDB */
}

static int set_fabrics_options(struct libnvmf_context *fctx,
		struct nvmf_args *fa)
{
	libnvmf_context_set_io_queues(fctx, fa->nr_io_queues,
			fa->nr_write_queues, fa->nr_poll_queues,
			fa->queue_size, fa->disable_sqflow);
	libnvmf_context_set_reconnect_policy(fctx, fa->ctrl_loss_tmo,
			fa->reconnect_delay, fa->fast_io_fail_tmo);
	libnvmf_context_set_keep_alive_tmo(fctx, fa->keep_alive_tmo);
	libnvmf_context_set_tos(fctx, fa->tos);
	libnvmf_context_set_keyring_id(fctx, fa->keyring_id);
	libnvmf_context_set_tls_key_id(fctx, fa->tls_key_id);
	libnvmf_context_set_tls_configured_key_id(fctx,
			fa->tls_configured_key_id);
	libnvmf_context_set_duplicate_connect(fctx, fa->duplicate_connect);
	libnvmf_context_set_hdr_digest(fctx, fa->hdr_digest);
	libnvmf_context_set_data_digest(fctx, fa->data_digest);
	libnvmf_context_set_tls(fctx, fa->tls);
	libnvmf_context_set_concat(fctx, fa->concat);

	return 0;
}

enum consume_mode {
	/* connect-all/discover: DC entries discover; IOC entries connect,
	 * but only for connect-all.
	 */
	CONSUME_ROLE_BASED,
	/* nvme connect -J: every entry connects directly, no discovery. */
	CONSUME_CONNECT_ONLY,
};

struct consume_state {
	struct libnvme_global_ctx *ctx;
	enum consume_mode mode;
	bool connect;
	bool force;
	nvme_print_flags_t flags;
	char *raw;
	const char *hostnqn;
	const char *hostid;
	int err;
};

/*
 * Resolve traddr (if it's a hostname), settle host identity (falling back
 * to @default_hostnqn/@default_hostid when @conn's own persona doesn't set
 * one), then build the TID -- which doubles as validator/sanitizer:
 * rejects a non-numeric traddr or host_traddr on tcp/rdma, canonicalizes a
 * numeric one.
 */
static int build_conn_tid(const struct libnvmf_config_conn *conn,
		const char *default_hostnqn, const char *default_hostid,
		struct libnvmf_tid **tid)
{
	const char *transport, *traddr, *hostnqn, *hostid;
	int err;

	transport = libnvmf_config_conn_get_transport(conn);
	traddr = libnvmf_config_conn_get_traddr(conn);

	/* Only traddr (remote target) may be a hostname (not host_traddr) */
	err = nvmf_resolve_addr(transport, &traddr);
	if (err)
		return err;

	hostnqn = libnvmf_config_conn_get_hostnqn(conn);
	if (!hostnqn)
		hostnqn = default_hostnqn;
	hostid = libnvmf_config_conn_get_hostid(conn);
	if (!hostid)
		hostid = default_hostid;

	return libnvmf_tid_from_fields(transport, traddr,
			libnvmf_config_conn_get_trsvcid(conn),
			libnvmf_config_conn_get_subsysnqn(conn),
			libnvmf_config_conn_get_host_traddr(conn),
			libnvmf_config_conn_get_host_iface(conn),
			hostnqn, hostid, tid);
}

/* libnvmf_config_conn_for_each() callback: settle addressing/identity,
 * check exclusion, then discover or connect.
 */
static void consume_conn(const struct libnvmf_config_conn *conn,
		void *user_data)
{
	struct consume_state *st = user_data;
	bool is_dc = libnvmf_config_conn_is_dc(conn);
	struct hook_fabrics_data hfd = { .flags = st->flags, .raw = st->raw };
	__cleanup_nvmf_context struct libnvmf_context *fctx = NULL;
	__cleanup_nvmf_tid struct libnvmf_tid *tid = NULL;
	int err;

	if (st->mode == CONSUME_ROLE_BASED && !is_dc && !st->connect)
		return;

	err = build_conn_tid(conn, st->hostnqn, st->hostid, &tid);
	if (err)
		goto record_err;

	/* Auto-connect (both modes) enforces exclusion, unlike a single
	 * explicit "nvme connect" (see fabrics_connect()'s exempt-with-note
	 * case).
	 */
	if (libnvmf_exclusion_match(st->ctx, tid)) {
		nvme_show_verbose_info("%s: on the exclusion list, skipping",
				libnvmf_config_conn_get_source(conn));
		return;
	}

	err = libnvmf_context_create(st->ctx, hook_decide_retry, hook_connected,
			hook_already_connected, &hfd, &fctx);
	if (err)
		goto record_err;

	err = libnvmf_context_set_connection_from_tid(fctx, tid);
	if (!err)
		err = libnvmf_context_apply_params(fctx,
				libnvmf_config_conn_get_params(conn));
	if (err)
		goto record_err;

	if (st->mode == CONSUME_CONNECT_ONLY) {
		err = libnvmf_connect(st->ctx, fctx);
	} else if (is_dc) {
		libnvmf_context_set_discovery_hooks(fctx, hook_discovery_log);
		libnvmf_context_set_default_max_discovery_retries(fctx,
				MAX_DISC_RETRIES);
		libnvmf_context_set_default_keep_alive_timeout(fctx,
				NVMF_DEF_DISC_TMO);
		err = libnvmf_discovery(st->ctx, fctx, st->connect, st->force);
	} else {
		err = libnvmf_connect(st->ctx, fctx);
	}
	if (err == -ENVME_CONNECT_ALREADY)
		err = 0;

record_err:
	if (err) {
		nvme_show_error("%s: %s", libnvmf_config_conn_get_source(conn),
				libnvme_strerror(-err));
		if (!st->err)
			st->err = err;
	}
}

/*
 * Parse one discovery.conf line -- the same argv-style syntax 'nvme
 * discover'/'connect-all' accept, reusing NVMF_ARGS so every short and long
 * form works identically to real usage -- and hand the parsed arguments to
 * nvme_config_convert_discovery_args(). @line is modified in place (strsep()).
 *
 * A blank line, a comment, or one with neither transport nor traddr is
 * silently skipped (0, nothing added), tolerating a discovery.conf that
 * mixes real entries with commentary.
 */
int nvmf_convert_discovery_line(struct libnvmf_config_emitter *emitter,
		char *line)
{
	struct nvmf_args fa = { 0 };
	char *argv[MAX_DISC_ARGS] = { "discovery.conf" };
	char *ptr, *p = line;
	int argc = 1;
	bool line_persistent = false, line_force = false;

	NVMF_ARGS(opts, fa,
		  OPT_FLAG("persistent", 'p', &line_persistent,
			   "persistent discovery connection"),
		  OPT_FLAG("force",        0, &line_force,
			   "Force persistent discovery controller creation"));

	if (line[0] == '#' || line[0] == '\n' || line[0] == '\0')
		return 0;

	fa.tos = -1;
	fa.ctrl_loss_tmo = NVMF_DEF_CTRL_LOSS_TMO;

	while ((ptr = strsep(&p, " =\n")) != NULL && argc < MAX_DISC_ARGS - 1)
		argv[argc++] = ptr;
	argv[argc] = NULL;

	fa.subsysnqn = NVME_DISC_SUBSYS_NAME;
	if (argconfig_parse(argc, argv, "discovery.conf", opts))
		return 0;

	if (!fa.transport && !fa.traddr)
		return 0;

	return nvme_config_convert_discovery_args(emitter, &fa);
}

static int setup_common_context(struct libnvmf_context *fctx,
		struct nvmf_args *fa)
{
	int err;

	err = libnvmf_context_set_connection(fctx,
		fa->subsysnqn, fa->transport,
		fa->traddr, fa->trsvcid,
		fa->host_traddr, fa->host_iface);
	if (err)
		return err;

	err = libnvmf_context_set_hostnqn(fctx,
		fa->hostnqn, fa->hostid);
	if (err)
		return err;

	err = libnvmf_context_set_crypto(fctx,
		fa->hostkey, fa->ctrlkey,
		fa->keyring, fa->tls_key,
		fa->tls_key_identity);
	if (err)
		return err;

	return set_fabrics_options(fctx, fa);
}

static int create_common_context(struct libnvme_global_ctx *ctx,
		bool persistent, struct nvmf_args *fa,
		void *user_data, struct libnvmf_context **fctxp)
{
	struct libnvmf_context *fctx;
	int err;

	err = libnvmf_context_create(ctx, hook_decide_retry, hook_connected,
		hook_already_connected, user_data, &fctx);
	if (err)
		return err;

	err = setup_common_context(fctx, fa);
	if (err)
		goto err;

	libnvmf_context_set_persistent(fctx, persistent);

	*fctxp = fctx;

	return 0;

err:
	libnvmf_context_free(fctx);
	return err;
}

static int create_discovery_context(struct libnvme_global_ctx *ctx,
		bool persistent, const char *device,
		struct nvmf_args *fa,
		void *user_data, struct libnvmf_context **fctxp)
{
	struct libnvmf_context *fctx;
	int err;

	err = create_common_context(ctx, persistent, fa, user_data,
		&fctx);
	if (err)
		return err;

	err = libnvmf_context_set_discovery_hooks(fctx, hook_discovery_log);
	if (err)
		goto err;

	libnvmf_context_set_default_max_discovery_retries(fctx,
			MAX_DISC_RETRIES);
	libnvmf_context_set_default_keep_alive_timeout(fctx, NVMF_DEF_DISC_TMO);

	err = libnvmf_context_set_device(fctx, device);
	if (err)
		goto err;

	*fctxp = fctx;
	return 0;

err:
	libnvmf_context_free(fctx);
	return err;
}

static void load_nvme_fabrics_module(void)
{
#ifdef NVME_HAVE_LIBKMOD
	struct kmod_ctx *ctx;
	struct kmod_module *mod;
	int err, state;
	int timeout = 20; /* 2 seconds */

	ctx = kmod_new(NULL, NULL);
	if (!ctx)
		return;

	err = kmod_module_new_from_name(ctx, "nvme-fabrics", &mod);
	if (err)
		goto unref;

	state = kmod_module_get_initstate(mod);
	if (state != KMOD_MODULE_LIVE && state != KMOD_MODULE_BUILTIN) {
		err = kmod_module_probe_insert_module(mod,
			KMOD_PROBE_APPLY_BLACKLIST, NULL, NULL, NULL, NULL);
		if (err)
			goto mod_unref;

		while (timeout--) {
			state = kmod_module_get_initstate(mod);
			if (state == KMOD_MODULE_LIVE)
				goto mod_unref;

			/* 100 ms */
			usleep(100 * 1000);
		}
		err = -ENOENT;
	}

mod_unref:
	kmod_module_unref(mod);
unref:
	kmod_unref(ctx);

	if (err)
		nvme_show_error("Couldn't load the nvme-fabrics module");
#endif
}

/*
 * The config-driven half of a bare "connect-all"/"discover": auto-convert
 * a legacy file if needed, settle host identity once, then discover or
 * connect every resolved connection in @config_file.
 */
static int fabrics_discovery_config(struct libnvme_global_ctx *ctx,
		char *config_file, const char *hostnqn_arg,
		const char *hostid_arg, bool connect, bool force,
		nvme_print_flags_t flags)
{
	__cleanup_free char *ini_path = NULL;
	__cleanup_free char *hostnqn = NULL;
	__cleanup_free char *hostid = NULL;
	struct libnvmf_config *cfg;
	struct consume_state st;
	bool is_default_config;
	int ret;

	/* Custom --config failing is fatal (explicit ask). Default path
	 * failing isn't: boot-time connect-all must keep going.
	 */
	is_default_config = !strcmp(config_file, PATH_NVMF_INI);

	ret = nvme_config_convert_auto(ctx, config_file, &ini_path);
	if (ret) {
		nvme_show_error("auto-conversion failed: %s",
			libnvme_strerror(-ret));
		if (!is_default_config)
			return ret;
	}
	config_file = ini_path;

	ret = libnvmf_host_get_ids(ctx, hostnqn_arg, hostid_arg,
		&hostnqn, &hostid);
	if (ret) {
		nvme_show_error("failed to determine host identity: %s",
			libnvme_strerror(-ret));
		return ret;
	}

	ret = libnvmf_config_read(ctx, config_file, &cfg);
	if (ret) {
		nvme_show_error("failed to read %s: %s", config_file,
			libnvme_strerror(-ret));
		return ret;
	}

	st = (struct consume_state){
		.ctx = ctx,
		.mode = CONSUME_ROLE_BASED,
		.connect = connect,
		.force = force,
		.flags = flags,
		.raw = raw,
		.hostnqn = hostnqn,
		.hostid = hostid,
	};
	libnvmf_config_conn_for_each(cfg, consume_conn, &st);
	libnvmf_config_free(cfg);

	return st.err;
}

#define NBFT_SYSFS_PATH		"/sys/firmware/acpi/tables"

/*
 * A controller's ownership extends to everything done through it, so the
 * caller's operation may not proceed unless the invoking owner matches
 * (mirrors disconnect_all_match()'s registry check). No ownerless
 * exemption -- a mismatched or missing --owner is skipped the same way;
 * the escape hatch is passing the owner's own identity.
 *
 * --force skips the check entirely: it means the caller will never reuse
 * an existing controller, so there is nothing to check ownership against.
 *
 * Returns 0 to proceed, 1 to skip, or a negative errno on a registry
 * read failure.
 */
static int check_ctrl_owner(struct libnvme_global_ctx *ctx,
			     struct libnvmf_context *fctx,
			     const char *owner, bool force)
{
	__cleanup_free char *reg_owner = NULL;
	int ret;

	if (force)
		return 0;

	ret = libnvmf_get_owner_from_fctx(ctx, fctx, &reg_owner);
	if (ret)
		return ret;
	if (!reg_owner)   /* no owner in registry */
		return 0;

	if (owner && streq(reg_owner, owner))
		return 0;

	nvme_show_error("owned by '%s'; skipping -- owner handles discovery",
			 reg_owner);
	return 1;
}

int fabrics_discovery(const char *desc, int argc, char **argv, bool connect)
{
	__cleanup_free char *hnqn = NULL;
	__cleanup_free char *hid = NULL;
	char *config_file = PATH_NVMF_INI;
	nvme_print_flags_t flags;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	int ret;
	struct nvmf_args fa = { .subsysnqn = NVME_DISC_SUBSYS_NAME };
	char *device = NULL;
	bool force = false;
	bool nbft = false, nonbft = false;
	char *nbft_path = NBFT_SYSFS_PATH;
	char *owner = NULL;

	NVMF_ARGS(opts, fa,
		  OPT_STRING("device",     'd', "DEV", &device,       "use existing discovery controller device"),
		  OPT_FILE("raw",          'r', &raw,                 "save raw output to file"),
		  OPT_FLAG("persistent",   'p', &persistent,          "persistent discovery connection"),
		  OPT_STRING("config",     'J', "FILE", &config_file, nvmf_config_file),
		  OPT_FLAG("force",          0, &force,               "Force persistent discovery controller creation"),
		  OPT_FLAG("nbft",           0, &nbft,                "Only look at NBFT tables"),
		  OPT_FLAG("no-nbft",        0, &nonbft,              "Do not look at NBFT tables"),
		  OPT_STRING("owner",        0, "NAME", &owner,       "record this owner in the registry"),
		  OPT_STRING("nbft-path",    0, "STR", &nbft_path,    "user-defined path for NBFT tables"));

	nvmf_default_args(&fa);

	ret = parse_args(argc, argv, desc, opts);
	if (ret)
		return ret;

	load_nvme_fabrics_module();

	ret = validate_output_format(nvme_args.output_format, &flags);
	if (ret < 0) {
		nvme_show_error("Invalid output format");
		return ret;
	}

	if (!strcmp(config_file, "none"))
		config_file = NULL;

	ret = nvme_create_global_ctx_hostnqn(&ctx,
		fa.hostnqn, fa.hostid, &hnqn, &hid);
	if (ret)
		return ret;
	fa.hostnqn = hnqn;
	fa.hostid = hid;

	/*
	 * --nbft defaults the owner to "nbft" so legacy boot scripts that
	 * call "connect-all --nbft" record ownership unchanged.  An explicit
	 * --owner overrides that default.
	 */
	if (owner || nbft) {
		ret = libnvme_set_owner(ctx, owner ? owner : "nbft");
		if (ret) {
			nvme_show_error("failed to set owner: %s",
				libnvme_strerror(-ret));
			return ret;
		}
	}

	libnvme_skip_namespaces(ctx);
	ret = libnvme_scan_topology(ctx, NULL, NULL);
	if (ret < 0) {
		nvme_show_error("Failed to scan topology: %s",
			libnvme_strerror(-ret));
		return ret;
	}

	if (device) {
		if (!strcmp(device, "none"))
			device = NULL;
		else if (!strncmp(device, "/dev/", 5))
			device += 5;
	}

	/* Only traddr may be a hostname; host_traddr never is. */
	ret = nvmf_resolve_addr(fa.transport, &fa.traddr);
	if (ret)
		return ret;

	struct hook_fabrics_data dld = {
		.flags = flags,
		.raw = raw,
	};

	if (!device && !fa.transport && !fa.traddr) {
		if (!nonbft) {
			__cleanup_nvmf_context
				struct libnvmf_context *fctx = NULL;

			ret = create_discovery_context(ctx, persistent, NULL,
				&fa, &dld, &fctx);
			if (ret)
				return ret;
			ret = libnvmf_discovery_nbft(ctx, fctx, connect,
				nbft_path);
		}
		if (!nbft && config_file)
			ret = fabrics_discovery_config(ctx, config_file,
				fa.hostnqn, fa.hostid, connect, force, flags);
	} else {
		__cleanup_nvmf_context struct libnvmf_context *fctx = NULL;

		ret = create_discovery_context(ctx, persistent, device, &fa,
			&dld, &fctx);
		if (ret)
			return ret;

		ret = check_ctrl_owner(ctx, fctx,
				owner ? owner : (nbft ? "nbft" : NULL), force);
		if (ret < 0) {
			nvme_show_error("failed to check owner: %s",
					libnvme_strerror(-ret));
			return ret;
		}
		if (ret)
			return 0;

		ret = libnvmf_discovery(ctx, fctx, connect, force);
	}

	return ret;
}

/*
 * The config-driven half of "nvme connect -J": auto-convert a legacy file
 * if needed, settle host identity once, then connect every resolved
 * connection in @config_file.
 */
static int fabrics_connect_config(struct libnvme_global_ctx *ctx,
		char *config_file, const char *hostnqn_arg,
		const char *hostid_arg, nvme_print_flags_t flags)
{
	__cleanup_free char *ini_path = NULL;
	__cleanup_free char *hostnqn = NULL;
	__cleanup_free char *hostid = NULL;
	struct libnvmf_config *cfg;
	struct consume_state st;
	int ret;

	/* Always explicit here (no implicit default read), so a
	 * conversion failure is always fatal.
	 */
	ret = nvme_config_convert_auto(ctx, config_file, &ini_path);
	if (ret) {
		nvme_show_error("auto-conversion failed: %s",
			libnvme_strerror(-ret));
		return ret;
	}
	config_file = ini_path;

	ret = libnvmf_host_get_ids(ctx, hostnqn_arg, hostid_arg,
		&hostnqn, &hostid);
	if (ret) {
		nvme_show_error("failed to determine host identity: %s",
			libnvme_strerror(-ret));
		return ret;
	}

	ret = libnvmf_config_read(ctx, config_file, &cfg);
	if (ret) {
		nvme_show_error("failed to read %s: %s", config_file,
			libnvme_strerror(-ret));
		return ret;
	}

	st = (struct consume_state){
		.ctx = ctx,
		.mode = CONSUME_CONNECT_ONLY,
		.flags = flags,
		.raw = raw,
		.hostnqn = hostnqn,
		.hostid = hostid,
	};
	libnvmf_config_conn_for_each(cfg, consume_conn, &st);
	libnvmf_config_free(cfg);

	return st.err;
}

int fabrics_connect(const char *desc, int argc, char **argv)
{
	__cleanup_free char *hnqn = NULL;
	__cleanup_free char *hid = NULL;
	char *config_file = NULL;
	char *owner = NULL;
	char *devid_file = NULL;
	bool idempotent = false;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvmf_context struct libnvmf_context *fctx = NULL;
	__cleanup_nvme_ctrl libnvme_ctrl_t c = NULL;
	int ret;
	nvme_print_flags_t flags;
	struct nvmf_args fa = { 0 };

	NVMF_ARGS(opts, fa,
		  OPT_STRING("config",             'J', "FILE", &config_file, nvmf_config_file),
		  OPT_STRING("owner",                0, "NAME", &owner,           "record this owner in the registry"),
		  OPT_STRING("devid-file", 0, "FILE", &devid_file,
			     "write connected device name to FILE"),
		  OPT_FLAG("idempotent", 0, &idempotent,
			   "exit 0 if already connected"));

	nvmf_default_args(&fa);

	ret = parse_args(argc, argv, desc, opts);
	if (ret)
		return ret;

	load_nvme_fabrics_module();

	ret = validate_output_format(nvme_args.output_format, &flags);
	if (ret < 0) {
		nvme_show_error("Invalid output format");
		return ret;
	}

	if (config_file && !strcmp(config_file, "none"))
		config_file = NULL;

	if (config_file)
		goto do_connect;

	if (!fa.subsysnqn) {
		nvme_show_error(
			"required argument [--nqn | -n] not specified\n");
		return -EINVAL;
	}

	if (!fa.transport) {
		nvme_show_error(
			"required argument [--transport | -t] not specified\n");
		return -EINVAL;
	}

	if (strcmp(fa.transport, "loop")) {
		if (!fa.traddr) {
			nvme_show_error(
				"required argument [--traddr | -a] not specified for transport %s\n",
				fa.transport);
			return -EINVAL;
		}
	}

	/* Only traddr may be a hostname; host_traddr never is. */
	ret = nvmf_resolve_addr(fa.transport, &fa.traddr);
	if (ret)
		return ret;

do_connect:
	ret = nvme_create_global_ctx_hostnqn(&ctx,
		fa.hostnqn, fa.hostid, &hnqn, &hid);
	if (ret)
		return ret;
	fa.hostnqn = hnqn;
	fa.hostid = hid;

	if (owner) {
		ret = libnvme_set_owner(ctx, owner);
		if (ret) {
			nvme_show_error("failed to set owner: %s",
				libnvme_strerror(-ret));
			return ret;
		}
	}

	libnvme_skip_namespaces(ctx);
	ret = libnvme_scan_topology(ctx, NULL, NULL);
	if (ret < 0) {
		nvme_show_error("Failed to scan topology: %s",
			libnvme_strerror(-ret));
		return ret;
	}

	if (config_file)
		return fabrics_connect_config(ctx, config_file, fa.hostnqn,
			fa.hostid, flags);

	struct hook_fabrics_data hfd = {
		.flags = flags,
		.raw = raw,
		.idempotent = idempotent,
	};
	ret = create_common_context(ctx, persistent, &fa, &hfd, &fctx);
	if (ret)
		return ret;

	if (devid_file)
		libnvmf_context_set_devid_file(fctx, devid_file);

	/*
	 * The exclusion list governs auto-connecting orchestrators, not an
	 * explicit "nvme connect", so we never block it here. But under
	 * --verbose, note when the target matches an exclusion entry so the
	 * operator knows they are overriding their own opt-out.
	 */
	if (nvme_args.verbose) {
		struct libnvmf_tid *tid;

		libnvmf_tid_from_fields(fa.transport, fa.traddr,
					fa.trsvcid, fa.subsysnqn,
					fa.host_traddr, fa.host_iface,
					fa.hostnqn, fa.hostid, &tid);
		if (tid && libnvmf_exclusion_match(ctx, tid))
			nvme_show_error(
				"Note: %s is on the exclusion list; connecting anyway\n",
				fa.subsysnqn ? fa.subsysnqn : "this controller");
		libnvmf_tid_free(tid);
	}

	ret = libnvmf_connect(ctx, fctx);
	if (idempotent && (ret == -EALREADY || ret == -ENVME_CONNECT_ALREADY))
		ret = 0;
	if (ret) {
		nvme_show_error("failed to connect: %s",
			libnvme_strerror(-ret));
		return ret;
	}

	return 0;
}

static libnvme_ctrl_t lookup_nvme_ctrl(struct libnvme_global_ctx *ctx,
				    const char *name)
{
	libnvme_host_t h;
	libnvme_subsystem_t s;
	libnvme_ctrl_t c;

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			libnvme_subsystem_for_each_ctrl(s, c) {
				if (!strcmp(libnvme_ctrl_get_name(c), name))
					return c;
			}
		}
	}
	return NULL;
}

static bool opt_matches(const char *want, const char *have)
{
	return !want || (have && !strcmp(want, have));
}

static bool nvmf_ctrl_matches_args(libnvme_host_t h, libnvme_ctrl_t c,
				    const struct nvmf_args *fa)
{
	return opt_matches(fa->transport, libnvme_ctrl_get_transport(c)) &&
	       opt_matches(fa->subsysnqn, libnvme_ctrl_get_subsysnqn(c)) &&
	       opt_matches(fa->traddr, libnvme_ctrl_get_traddr(c)) &&
	       opt_matches(fa->trsvcid, libnvme_ctrl_get_trsvcid(c)) &&
	       opt_matches(fa->host_traddr, libnvme_ctrl_get_host_traddr(c)) &&
	       opt_matches(fa->host_iface, libnvme_ctrl_get_host_iface(c)) &&
	       opt_matches(fa->hostnqn, libnvme_host_get_hostnqn(h)) &&
	       opt_matches(fa->hostid, libnvme_host_get_hostid(h));
}

static int nvmf_disconnect_nqn(struct libnvme_global_ctx *ctx, char *nqn)
{
	int i = 0;
	char *n = nqn;
	char *p;
	libnvme_host_t h;
	libnvme_subsystem_t s;
	libnvme_ctrl_t c;

	while ((p = strsep(&n, ",")) != NULL) {
		if (!strlen(p))
			continue;
		libnvme_for_each_host(ctx, h) {
			libnvme_for_each_subsystem(h, s) {
				if (strcmp(libnvme_subsystem_get_subsysnqn(s), p))
					continue;
				libnvme_subsystem_for_each_ctrl(s, c) {
					if (!libnvmf_disconnect_ctrl(c))
						i++;
				}
			}
		}
	}
	nvme_show_verbose_result("NQN:%s disconnected %d controller(s)", nqn, i);

	return 0;
}

static int disconnect_validate_args(bool has_device, bool has_subsysnqn,
		bool match_args)
{
	if (has_device && (has_subsysnqn || match_args)) {
		nvme_show_error(
			"Device name [--device | -d] cannot be combined with other identifying options\n");
		return -EINVAL;
	}

	if (!has_device && !has_subsysnqn && match_args) {
		nvme_show_error(
			"Fabrics identifying options require an NQN [--nqn | -n]\n");
		return -EINVAL;
	}

	if (!has_device && !has_subsysnqn) {
		 nvme_show_error(
			"Neither device name [--device | -d] nor NQN [--nqn | -n] provided\n");
		 return -EINVAL;
	}

	return 0;
}

static int add_exclusion_ctrl(struct libnvme_global_ctx *ctx,
		struct libnvme_ctrl *c)
{
	int err;

	/*
	 * Write exclusion entry before disconnecting so that
	 * orchestrators see the exclusion in place before the
	 * device removal event fires.
	 */
	err = libnvmf_exclusion_add_ctrl(ctx, NULL, c);
	if (!err)
		return 0;

	nvme_show_error("Warning: failed to write exclusion entry: %s\n",
		libnvme_strerror(-err));

	return err;
}

static int add_exclusion_subsysnqn(struct libnvme_global_ctx *ctx,
		const char *subsysnqn)
{
	int err;

	/*
	 * Write exclusion entry before disconnecting so that
	 * orchestrators see the exclusion in place before the
	 * device removal event fires.
	 */
	err = libnvmf_exclusion_add_subsysnqn(ctx, NULL, subsysnqn);
	if (!err)
		return 0;

	nvme_show_error("Warning: failed to write exclusion entry: %s\n",
		libnvme_strerror(-err));

	return err;
}

static int disconnect_by_device(struct libnvme_global_ctx *ctx,
		char *device,  bool exclude)
{
	libnvme_ctrl_t c;
	char *p;
	int err;

	while ((p = strsep(&device, ",")) != NULL) {
		if (!strncmp(p, "/dev/", 5))
			p += 5;

		c = lookup_nvme_ctrl(ctx, p);
		if (!c) {
			nvme_show_error("Did not find device %s\n", p);
			return -ENODEV;
		}

		if (exclude)
			add_exclusion_ctrl(ctx, c);

		err = libnvmf_disconnect_ctrl(c);
		if (err)
			nvme_show_error("Failed to disconnect %s: %s\n",
				p, libnvme_strerror(-err));
	}

	return 0;
}

static int disconnect_by_args(struct libnvme_global_ctx *ctx,
		const struct nvmf_args *fa, bool exclude)
{
	libnvme_host_t h;
	libnvme_subsystem_t s;
	libnvme_ctrl_t c;
	int err, i = 0;

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			libnvme_subsystem_for_each_ctrl(s, c) {
				if (!nvmf_ctrl_matches_args(h, c, fa))
					continue;

				if (exclude)
					add_exclusion_ctrl(ctx, c);

				err = libnvmf_disconnect_ctrl(c);
				if (err)
					nvme_show_error("Failed to disconnect %s: %s\n",
						libnvme_ctrl_get_name(c),
						libnvme_strerror(-err));
				else
					i++;
			}
		}
	}

	if (!i)
		nvme_show_error("Did not find a matching controller\n");

	nvme_show_verbose_result("disconnected %d controller(s)", i);

	return 0;
}

static int disconnect_by_nqn(struct libnvme_global_ctx *ctx, const char *nqn,
		bool exclude)
{
	__cleanup_free char *n = NULL;

	n = strdup(nqn);
	if (!n)
		return -ENOMEM;

	if (exclude) {
		__cleanup_free char *excl = strdup(nqn);
		char *t, *p;

		if (!excl)
			return -ENOMEM;

		t = excl;
		while ((p = strsep(&t, ",")) != NULL) {
			if (!*p)
				continue;

			add_exclusion_subsysnqn(ctx, p);
		}
	}

	return nvmf_disconnect_nqn(ctx, n);
}

int fabrics_disconnect(const char *desc, int argc, char **argv)
{
	const char *device = "nvme device handle";
	const char *exclude_help = "write exclusion entry before disconnecting";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct nvmf_args fa = { 0 };
	bool match_args;
	int err;

	struct config {
		char *device;
		bool  exclude;
	};

	struct config cfg = { 0 };

	NVMF_ARGS(opts, fa,
		OPT_STRING("device",     'd', "DEV",  &cfg.device,  device),
		OPT_FLAG("exclude", 'x', &cfg.exclude, exclude_help));

	nvmf_default_args(&fa);

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	/*
	 * Any of the "connect"-style options beyond bare --nqn narrow the
	 * lookup to a specific controller instead of a whole subsystem.
	 */
	match_args = fa.transport || fa.traddr || fa.trsvcid ||
		     fa.host_traddr || fa.host_iface || fa.hostnqn || fa.hostid;

	err = disconnect_validate_args(!!cfg.device,
		!!fa.subsysnqn, match_args);
	if (err)
		return err;

	err = nvmf_resolve_addr(fa.transport, &fa.traddr);
	if (err)
		return err;

	err = nvme_create_global_ctx_hostnqn(&ctx,
		fa.hostnqn, fa.hostid, NULL, NULL);
	if (err)
		return err;

	libnvme_skip_namespaces(ctx);
	err = libnvme_scan_topology(ctx, NULL, NULL);
	if (err < 0) {
		/*
		 * Do not report an error when the modules are not
		 * loaded, this allows the user to unconditionally call
		 * disconnect.
		 */
		if (err == -ENOENT)
			return 0;

		nvme_show_error("Failed to scan topology: %s",
			libnvme_strerror(-err));
		return err;
	}

	if (cfg.device)
		return disconnect_by_device(ctx, cfg.device, cfg.exclude);

	if (match_args)
		return disconnect_by_args(ctx, &fa, cfg.exclude);

	return disconnect_by_nqn(ctx, fa.subsysnqn, cfg.exclude);
}

/* disconnect-all policy: should controller @c be torn down? */
static bool disconnect_all_match(struct libnvme_global_ctx *ctx,
				 libnvme_ctrl_t c, const char *transport,
				 const char *owner, bool force)
{
	if (transport && strcmp(transport, libnvme_ctrl_get_transport(c)))
		return false;
	if (!libnvme_ctrl_is_transport_fabric(c))
		return false;
	if (force)
		return true;

	/*
	 * attr_equal() returns 0 only on an exact match; a read error (<0)
	 * compares as "not a match", so we never disconnect on error.
	 */
	return libnvmf_registry_attr_equal(ctx, libnvme_ctrl_get_name(c),
					   "owner", owner) == 0;
}

int fabrics_disconnect_all(const char *desc, int argc, char **argv)
{
	const char *owner_help = "disconnect only controllers owned by NAME";
	const char *force_help = "disconnect all controllers regardless of ownership";
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	libnvme_host_t h;
	libnvme_subsystem_t s;
	libnvme_ctrl_t c;
	int ret;

	struct config {
		char *transport;
		char *owner;
		bool force;
	};

	struct config cfg = { 0 };

	NVME_ARGS(opts,
		OPT_STRING("transport", 't', "STR", &cfg.transport, DESC_NVMF_TPORT),
		OPT_STRING("owner", 0, "NAME", &cfg.owner, owner_help),
		OPT_FLAG("force", 0, &cfg.force, force_help));

	ret = parse_args(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (cfg.force && cfg.owner) {
		nvme_show_error("--force and --owner are mutually exclusive");
		return -EINVAL;
	}

	if ((cfg.force || cfg.owner) && isatty(STDIN_FILENO)) {
		char ans[8] = { 0 };

		if (cfg.force)
			fprintf(stderr,
				"WARNING: --force disconnects all NVMeoF controllers\n"
				"regardless of ownership. Type 'yes' to confirm: ");
		else
			fprintf(stderr,
				"WARNING: --owner disconnects all NVMeoF controllers\n"
				"owned by '%s'. Type 'yes' to confirm: ",
				cfg.owner);
		if (!fgets(ans, sizeof(ans), stdin)) {
			nvme_show_error("Aborted.");
			return -EINVAL;
		}
		ans[strcspn(ans, "\n")] = '\0';
		if (strcmp(ans, "yes") != 0) {
			nvme_show_error("Aborted.");
			return -EINVAL;
		}
	}

	ret = nvme_create_global_ctx(&ctx);
	if (ret)
		return ret;

	libnvme_skip_namespaces(ctx);
	ret = libnvme_scan_topology(ctx, NULL, NULL);
	if (ret < 0) {
		/*
		 * Do not report an error when the modules are not
		 * loaded, this allows the user to unconditionally call
		 * disconnect.
		 */
		if (ret == -ENOENT)
			return 0;

		nvme_show_error("Failed to scan topology: %s",
			libnvme_strerror(-ret));
		return ret;
	}

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			libnvme_subsystem_for_each_ctrl(s, c) {
				if (!disconnect_all_match(ctx, c, cfg.transport,
							  cfg.owner, cfg.force))
					continue;
				if (libnvmf_disconnect_ctrl(c))
					nvme_show_error(
						"failed to disconnect %s\n",
						libnvme_ctrl_get_name(c));
			}
		}
	}

	return 0;
}

int fabrics_config_validate(const char *desc, int argc, char **argv)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	char *config_file = PATH_NVMF_INI;
	int ret;

	OPT_ARGS(opts) = {
		OPT_STRING("config", 'J', "FILE", &config_file, nvmf_config_file_ro),
		OPT_END()
	};

	ret = parse_args(argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = nvme_create_global_ctx(&ctx);
	if (ret)
		return ret;

	if (access(config_file, F_OK)) {
		nvme_show_error("%s: no such file", config_file);
		return -ENOENT;
	}

	ret = libnvmf_config_validate(ctx, config_file);
	if (ret)
		nvme_show_error("%s: invalid configuration", config_file);
	else
		nvme_show_result("%s: OK", config_file);

	return ret;
}

int fabrics_config_show(const char *desc, int argc, char **argv)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvmf_config *cfg;
	char *config_file = PATH_NVMF_INI;
	nvme_print_flags_t flags;
	int ret;

	NVME_ARGS(opts,
		OPT_STRING("config", 'J', "FILE", &config_file,
			   nvmf_config_file_ro));

	ret = parse_args(argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = validate_output_format(nvme_args.output_format, &flags);
	if (ret < 0) {
		nvme_show_error("Invalid output format");
		return ret;
	}

	ret = nvme_create_global_ctx(&ctx);
	if (ret)
		return ret;

	ret = libnvmf_config_read(ctx, config_file, &cfg);
	if (ret) {
		nvme_show_error("failed to read %s: %s", config_file,
			libnvme_strerror(-ret));
		return ret;
	}

	nvme_show_config_conn_list(cfg, flags);
	libnvmf_config_free(cfg);

	return 0;
}

static int dim_operation(libnvme_ctrl_t c, enum nvmf_dim_tas tas, const char *name)
{
	static const char * const task[] = {
		[NVMF_DIM_TAS_REGISTER]   = "register",
		[NVMF_DIM_TAS_DEREGISTER] = "deregister",
	};
	const char *t;
	int status;
	__u32 result;

	t = (tas > NVMF_DIM_TAS_DEREGISTER || !task[tas]) ? "reserved" : task[tas];
	status = libnvmf_register_ctrl(c, tas, &result);
	if (status == NVME_SC_SUCCESS) {
		nvme_show_verbose_result("%s DIM %s command success", name, t);
	} else if (status < NVME_SC_SUCCESS) {
		nvme_show_error("%s DIM %s command error. Status:0x%04x - %s",
			name, t, status, libnvme_status_to_string(status, false));
	} else {
		nvme_show_error("%s DIM %s command error. Result:0x%04x, Status:0x%04x - %s",
			name, t, result, status, libnvme_status_to_string(status, false));
	}

	return libnvme_status_to_errno(status, true);
}

int fabrics_dim(const char *desc, int argc, char **argv)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	enum nvmf_dim_tas tas;
	libnvme_ctrl_t c;
	char *p;
	int ret;

	struct {
		char *nqn;
		char *device;
		char *tas;
	} cfg = { 0 };

	NVME_ARGS(opts,
		OPT_STRING("nqn",    'n', "NAME", &cfg.nqn,    "Comma-separated list of DC nqn"),
		OPT_STRING("device", 'd', "DEV",  &cfg.device, "Comma-separated list of DC nvme device handle."),
		OPT_STRING("task",   't', "TASK", &cfg.tas,    "[register|deregister]"));

	ret = parse_args(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (!cfg.nqn && !cfg.device) {
		nvme_show_error(
			"Neither device name [--device | -d] nor NQN [--nqn | -n] provided\n");
		return -EINVAL;
	}

	if (!cfg.tas) {
		nvme_show_error(
			"Task [--task | -t] must be specified\n");
		return -EINVAL;
	}

	/* Allow partial name (e.g. "reg" for "register" */
	if (strstarts("register", cfg.tas)) {
		tas = NVMF_DIM_TAS_REGISTER;
	} else if (strstarts("deregister", cfg.tas)) {
		tas = NVMF_DIM_TAS_DEREGISTER;
	} else {
		nvme_show_error("Invalid --task: %s", cfg.tas);
		return -EINVAL;
	}

	ret = nvme_create_global_ctx(&ctx);
	if (ret)
		return ret;

	libnvme_skip_namespaces(ctx);
	ret = libnvme_scan_topology(ctx, NULL, NULL);
	if (ret < 0) {
		nvme_show_error("Failed to scan topology: %s",
			libnvme_strerror(-ret));
		return ret;
	}

	if (cfg.nqn) {
		libnvme_host_t h;
		libnvme_subsystem_t s;
		char *n = cfg.nqn;

		while ((p = strsep(&n, ",")) != NULL) {
			if (!strlen(p))
				continue;
			libnvme_for_each_host(ctx, h) {
				libnvme_for_each_subsystem(h, s) {
					if (strcmp(libnvme_subsystem_get_subsysnqn(s), p))
						continue;
					libnvme_subsystem_for_each_ctrl(s, c)
						ret = dim_operation(c, tas, p);
				}
			}
		}
	}

	if (cfg.device) {
		char *d = cfg.device;

		while ((p = strsep(&d, ",")) != NULL) {
			if (!strncmp(p, "/dev/", 5))
				p += 5;
			ret = libnvme_scan_ctrl(ctx, p, &c);
			if (ret) {
				nvme_show_error(
					"Did not find device %s: %s\n",
					p, libnvme_strerror(ret));
				return ret;
			}
			ret = dim_operation(c, tas, p);
		}
	}

	return ret;
}
