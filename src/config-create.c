// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>

#include <libnvme.h>

#include <shared/compiler-attributes-util.h>

#include "argconfig.h"
#include "cleanup.h"
#include "config-create.h"
#include "fabrics.h"
#include "global-ctx.h"
#include "nvme-print.h"

struct reload_ctx {
	struct libnvmf_config_emitter *emitter;
	const struct nvmf_args *fa;
	const struct libnvmf_params *params;
	bool discovery;
	bool duplicate;
	bool replaced;
	int err;
};

static bool same_str(const char *a, const char *b)
{
	if (!a || !b)
		return a == b;
	return !strcmp(a, b);
}

static bool same_connection(const struct libnvmf_config_conn *conn,
		bool discovery, const struct nvmf_args *fa)
{
	const char *subsysnqn;

	if (libnvmf_config_conn_is_dc(conn) != discovery)
		return false;

	/* A DC with no explicit --nqn defaults to the well-known discovery
	 * NQN once read back, even though @fa->subsysnqn is still NULL.
	 */
	subsysnqn = fa->subsysnqn;
	if (!subsysnqn && discovery)
		subsysnqn = NVME_DISC_SUBSYS_NAME;

	return same_str(libnvmf_config_conn_get_transport(conn), fa->transport) &&
	       same_str(libnvmf_config_conn_get_traddr(conn), fa->traddr) &&
	       same_str(libnvmf_config_conn_get_trsvcid(conn), fa->trsvcid) &&
	       same_str(libnvmf_config_conn_get_subsysnqn(conn), subsysnqn) &&
	       same_str(libnvmf_config_conn_get_host_traddr(conn), fa->host_traddr) &&
	       same_str(libnvmf_config_conn_get_host_iface(conn), fa->host_iface) &&
	       same_str(libnvmf_config_conn_get_hostnqn(conn), fa->hostnqn) &&
	       same_str(libnvmf_config_conn_get_hostid(conn), fa->hostid);
}

static void count_param(__shr_unused const char *key,
		__shr_unused const char *value, void *user_data)
{
	int *count = user_data;

	(*count)++;
}

static int params_count(const struct libnvmf_params *params)
{
	int count = 0;

	libnvmf_params_for_each(params, count_param, &count);

	return count;
}

struct params_cmp_ctx {
	const struct libnvmf_params *other;
	bool equal;
};

static void cmp_param(const char *key, const char *value, void *user_data)
{
	struct params_cmp_ctx *ctx = user_data;

	if (!same_str(libnvmf_params_get(ctx->other, key), value))
		ctx->equal = false;
}

static bool same_params(const struct libnvmf_params *a,
		const struct libnvmf_params *b)
{
	struct params_cmp_ctx ctx = { .other = b, .equal = true };

	if (params_count(a) != params_count(b))
		return false;

	libnvmf_params_for_each(a, cmp_param, &ctx);

	return ctx.equal;
}

static void reload_conn(const struct libnvmf_config_conn *conn, void *user_data)
{
	struct reload_ctx *rc = user_data;

	if (rc->err)
		return;

	if (same_connection(conn, rc->discovery, rc->fa)) {
		if (same_params(libnvmf_config_conn_get_params(conn), rc->params)) {
			rc->duplicate = true;
		} else {
			rc->replaced = true;
			return;
		}
	}

	rc->err = libnvmf_config_emit_add(rc->emitter,
			libnvmf_config_conn_is_dc(conn),
			libnvmf_config_conn_get_transport(conn),
			libnvmf_config_conn_get_traddr(conn),
			libnvmf_config_conn_get_trsvcid(conn),
			libnvmf_config_conn_get_subsysnqn(conn),
			libnvmf_config_conn_get_host_traddr(conn),
			libnvmf_config_conn_get_host_iface(conn),
			libnvmf_config_conn_get_hostnqn(conn),
			libnvmf_config_conn_get_hostid(conn),
			libnvmf_config_conn_get_params(conn),
			libnvmf_config_conn_get_hostsymname(conn));
}

static int reload_existing(struct libnvmf_config_emitter *emitter,
		struct libnvme_global_ctx *ctx, const char *file,
		bool discovery, const struct nvmf_args *fa,
		const struct libnvmf_params *params,
		bool *duplicate, bool *replaced)
{
	struct libnvmf_config *config;
	struct reload_ctx rc = {
		.emitter = emitter,
		.discovery = discovery,
		.fa = fa,
		.params = params,
	};
	int err;

	err = libnvmf_config_read(ctx, file, &config);
	if (err)
		return err;

	libnvmf_config_conn_for_each(config, reload_conn, &rc);
	err = rc.err;
	*duplicate = rc.duplicate;
	*replaced = rc.replaced;

	libnvmf_config_free(config);

	return err;
}

int nvme_config_create(const char *desc, int argc, char **argv)
{
	const char *desc_discovery = "create a discovery controller entry "
		"instead of an I/O controller (subsystem) entry; an I/O "
		"controller entry requires --nqn";
	const char *desc_symname = "name this host persona, so it gets its "
		"own configuration drop-in";
	const char *desc_output = "add the entry to this INI configuration "
		"file (default: " PATH_NVMF_INI ")";
	const char *desc_persistent = "keep the discovery controller connected "
		"to receive Asynchronous Event Notifications instead of "
		"disconnecting after the discovery log page fetch; \"auto\" "
		"(the default when given bare) persists only where the "
		"target's own EPCSD flag supports it, \"force\" persists "
		"regardless, \"no\" explicitly records non-persistence; "
		"requires --discovery";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvmf_config_emitter *emitter = NULL;
	struct libnvmf_params *params = NULL;
	struct nvmf_args fa = { 0 };
	char *output_file = NULL;
	char *hostsymname = NULL;
	bool discovery = false;
	char *persistent_arg = NULL;
	const char *persistent;
	bool duplicate = false;
	bool replaced = false;
	const char *target;
	int err;

	NVMF_ARGS(opts, fa,
		OPT_FLAG("discovery", 0, &discovery, desc_discovery),
		OPT_STRING_OPTIONAL("persistent", 0, "no|auto|force",
			&persistent_arg, desc_persistent),
		OPT_STRING("host-symname", 0, "STR", &hostsymname, desc_symname),
		OPT_STRING("output", 0, "FILE", &output_file, desc_output));

	nvmf_default_args(&fa);

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	persistent = nvmf_resolve_persistent_arg(opts, persistent_arg);

	if (persistent && !discovery) {
		nvme_show_error("--persistent requires --discovery");
		return -EINVAL;
	}

	err = nvme_create_global_ctx(&ctx);
	if (err)
		return err;

	target = output_file ? output_file : PATH_NVMF_INI;

	emitter = libnvmf_config_emit_new(ctx);
	if (!emitter)
		return -ENOMEM;

	params = libnvmf_params_new();
	if (!params) {
		err = -ENOMEM;
		goto out;
	}
	nvmf_args_to_params(params, &fa);
	if (persistent &&
	    libnvmf_params_set(params, "persistent", persistent)) {
		nvme_show_error(
			"invalid --persistent value '%s' (expected no, auto, or force)",
			persistent);
		err = -EINVAL;
		goto out;
	}

	err = reload_existing(emitter, ctx, target, discovery, &fa, params,
			&duplicate, &replaced);
	if (err) {
		nvme_show_error("failed to read existing %s: %s", target,
				 libnvme_strerror(-err));
		goto out;
	}
	if (duplicate) {
		nvme_show_result("this connection is already in %s; nothing to do",
				  target);
		goto out;
	}

	err = libnvmf_config_emit_add(emitter, discovery, fa.transport,
			fa.traddr, fa.trsvcid, fa.subsysnqn, fa.host_traddr,
			fa.host_iface, fa.hostnqn, fa.hostid, params,
			hostsymname);
	if (err) {
		nvme_show_error("failed to add connection: %s",
				 libnvme_strerror(-err));
		goto out;
	}

	err = libnvmf_config_emit_install(emitter, target, true);
	if (err) {
		nvme_show_error("failed to write %s: %s", target,
				 libnvme_strerror(-err));
		goto out;
	}

	nvme_show_result("%s a %s controller entry in %s",
			  replaced ? "updated" : "added",
			  discovery ? "discovery" : "I/O", target);

out:
	libnvmf_params_free(params);
	libnvmf_config_emit_free(emitter);

	return err;
}
