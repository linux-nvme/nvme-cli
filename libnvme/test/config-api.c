// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <martin.belanger@dell.com>
 *
 * Tests for the public connection-config API (<nvme/config.h>).  Linked
 * against the real shared library, so it also proves every symbol is
 * exported by the version script.
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <unistd.h>

#include <ccan/array_size/array_size.h>

#include <nvme/lib.h>
#include <nvme/config.h>
#include <nvme/nvme-types-fabrics.h>
#include <nvme/tid.h>

static void write_file(const char *dir, const char *name, const char *text)
{
	char path[512];
	FILE *fp;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	fp = fopen(path, "w");
	assert(fp);
	assert(fputs(text, fp) >= 0);
	fclose(fp);
}

static void rm_file(const char *dir, const char *name)
{
	char path[512];

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	unlink(path);
}

/*
 * The shared fixture: a main file with per-type defaults, one DC and one
 * subsystem, plus a second-persona drop-in.
 */
static const char main_text[] =
	"[Discovery Controller Defaults]\n"
	"ctrl-loss-tmo = 600\n"
	"keep-alive-tmo = 30\n"
	"[I/O Controller Defaults]\n"
	"ctrl-loss-tmo = 600\n"
	"keep-alive-tmo = 5\n"
	"[Discovery Controller]\n"
	"controller = transport=tcp;traddr=10.0.0.5;trsvcid=8009\n"
	"[Subsystem]\n"
	"nqn = nqn.2014-08.org.nvmexpress:main-vol\n"
	"tls = true\n"
	"data-digest = no\n"
	"controller = transport=tcp;traddr=10.0.0.9;trsvcid=4420\n";

static const char prod_text[] =
	"[Host]\n"
	"hostnqn = nqn.2014-08.org.nvmexpress:prod-host\n"
	"hostid = 46ba5037-7ce5-41fa-9452-48477bf00080\n"
	"hostsymname = prod\n"
	"[Subsystem]\n"
	"nqn = nqn.2014-08.org.nvmexpress:prod-vol\n"
	"reconnect-delay =\n"
	"controller = transport=tcp;traddr=10.0.0.7;trsvcid=4420;ctrl-loss-tmo=1800\n";

struct fixture {
	char dir[32];
	char main_path[288];
	char dropin_dir[288];
};

static void fixture_create(struct fixture *fx)
{
	snprintf(fx->dir, sizeof(fx->dir), "/tmp/nvme-config-api-XXXXXX");
	assert(mkdtemp(fx->dir));
	snprintf(fx->main_path, sizeof(fx->main_path), "%s/nvme-fabrics.conf",
		 fx->dir);
	snprintf(fx->dropin_dir, sizeof(fx->dropin_dir),
		 "%s/nvme-fabrics.conf.d", fx->dir);
	assert(mkdir(fx->dropin_dir, 0755) == 0);
	write_file(fx->dir, "nvme-fabrics.conf", main_text);
	write_file(fx->dropin_dir, "10-prod.conf", prod_text);
}

static void fixture_destroy(struct fixture *fx)
{
	rm_file(fx->dropin_dir, "10-prod.conf");
	rmdir(fx->dropin_dir);
	rm_file(fx->dir, "nvme-fabrics.conf");
	rmdir(fx->dir);
}

struct conn_list {
	const struct libnvmf_config_conn *conn[8];
	size_t n;
};

static void collect(const struct libnvmf_config_conn *conn, void *user_data)
{
	struct conn_list *list = user_data;

	assert(list->n < 8);
	list->conn[list->n++] = conn;
}

static bool test_read(struct libnvme_global_ctx *ctx, const struct fixture *fx)
{
	const struct libnvmf_config_conn *dc, *mv, *pv;
	struct conn_list list = { 0 };
	const struct libnvmf_params *params;
	struct libnvmf_config *config;
	bool pass = true;

	printf("test_read:\n");

	if (libnvmf_config_read(ctx, fx->main_path, &config)) {
		printf(" - read failed [FAIL]\n");
		return false;
	}

	libnvmf_config_conn_for_each(config, collect, &list);
	if (list.n != 3) {
		printf(" - expected 3 connections, got %zu [FAIL]\n", list.n);
		libnvmf_config_free(config);
		return false;
	}
	printf(" - 3 connections resolved [PASS]\n");

	/* Main file first (DC, then subsystem), then the drop-in. */
	dc = list.conn[0];
	mv = list.conn[1];
	pv = list.conn[2];

	if (!libnvmf_config_conn_is_dc(dc) || libnvmf_config_conn_is_dc(mv) ||
	    libnvmf_config_conn_is_dc(pv)) {
		printf(" - connection roles [FAIL]\n");
		pass = false;
	} else {
		printf(" - roles: DC + two subsystems [PASS]\n");
	}

	if (strcmp(libnvmf_config_conn_get_transport(dc), "tcp") ||
	    strcmp(libnvmf_config_conn_get_traddr(dc), "10.0.0.5") ||
	    strcmp(libnvmf_config_conn_get_subsysnqn(dc),
		   NVME_DISC_SUBSYS_NAME)) {
		printf(" - DC addressing + well-known NQN [FAIL]\n");
		pass = false;
	} else {
		printf(" - DC addressing + well-known NQN [PASS]\n");
	}

	if (strcmp(libnvmf_config_conn_get_subsysnqn(pv), "nqn.2014-08.org.nvmexpress:prod-vol") ||
	    strcmp(libnvmf_config_conn_get_hostnqn(pv), "nqn.2014-08.org.nvmexpress:prod-host") ||
	    strcmp(libnvmf_config_conn_get_hostid(pv),
		   "46ba5037-7ce5-41fa-9452-48477bf00080")) {
		printf(" - drop-in persona identity [FAIL]\n");
		pass = false;
	} else {
		printf(" - drop-in persona identity raw [PASS]\n");
	}

	if (libnvmf_config_conn_get_hostnqn(mv) ||
	    libnvmf_config_conn_get_hostsymname(mv)) {
		printf(" - main persona left to system default [FAIL]\n");
		pass = false;
	} else {
		printf(" - main persona left to system default [PASS]\n");
	}

	if (!libnvmf_config_conn_get_hostsymname(pv) ||
	    strcmp(libnvmf_config_conn_get_hostsymname(pv), "prod")) {
		printf(" - hostsymname [FAIL]\n");
		pass = false;
	} else {
		printf(" - hostsymname carried on the drop-in persona [PASS]\n");
	}

	params = libnvmf_config_conn_get_params(mv);
	if (!params || strcmp(libnvmf_params_get(params, "ctrl-loss-tmo"), "600") ||
	    strcmp(libnvmf_params_get(params, "keep-alive-tmo"), "5") ||
	    strcmp(libnvmf_params_get(params, "tls"), "true") ||
	    libnvmf_params_get(params, "reconnect-delay")) {
		printf(" - main subsystem cascade [FAIL]\n");
		pass = false;
	} else {
		printf(" - main cascade: defaults + section [PASS]\n");
	}

	params = libnvmf_config_conn_get_params(pv);
	if (!params ||
	    strcmp(libnvmf_params_get(params, "ctrl-loss-tmo"), "1800") ||
	    strcmp(libnvmf_params_get(params, "keep-alive-tmo"), "5")) {
		printf(" - per-path override [FAIL]\n");
		pass = false;
	} else {
		printf(" - per-path override beats the type default [PASS]\n");
	}

	if (!strstr(libnvmf_config_conn_get_source(dc), "nvme-fabrics.conf") ||
	    !strstr(libnvmf_config_conn_get_source(pv), "10-prod.conf")) {
		printf(" - source provenance [FAIL]\n");
		pass = false;
	} else {
		printf(" - source names the originating file [PASS]\n");
	}

	libnvmf_config_free(config);

	return pass;
}

static bool test_resolve_discovered(struct libnvme_global_ctx *ctx,
				    const struct fixture *fx)
{
	const struct libnvmf_params *params;
	struct conn_list list = { 0 };
	struct libnvmf_config *config;
	bool pass = true;

	printf("test_resolve_discovered:\n");

	assert(!libnvmf_config_read(ctx, fx->main_path, &config));
	libnvmf_config_conn_for_each(config, collect, &list);
	assert(list.n == 3 && libnvmf_config_conn_is_dc(list.conn[0]));

	/* A DLP IOC discovered via the configured DC: that DC's file scope. */
	params = libnvmf_config_resolve_discovered(config, list.conn[0], false);
	if (!params || strcmp(libnvmf_params_get(params, "keep-alive-tmo"), "5") ||
	    strcmp(libnvmf_params_get(params, "ctrl-loss-tmo"), "600") ||
	    libnvmf_params_get(params, "tls")) {
		printf(" - DLP IOC scope via DC [FAIL]\n");
		pass = false;
	} else {
		printf(" - DLP IOC draws the DC's file scope [PASS]\n");
	}

	/* A referral DC discovered via the configured DC. */
	params = libnvmf_config_resolve_discovered(config, list.conn[0], true);
	if (!params ||
	    strcmp(libnvmf_params_get(params, "keep-alive-tmo"), "30")) {
		printf(" - referral DC scope via DC [FAIL]\n");
		pass = false;
	} else {
		printf(" - referral DC draws the DC-defaults scope [PASS]\n");
	}

	/* No configured origin (an mDNS-found DC): the top-level scope. */
	params = libnvmf_config_resolve_discovered(config, NULL, true);
	if (!params ||
	    strcmp(libnvmf_params_get(params, "keep-alive-tmo"), "30") ||
	    strcmp(libnvmf_params_get(params, "ctrl-loss-tmo"), "600")) {
		printf(" - top-level scope [FAIL]\n");
		pass = false;
	} else {
		printf(" - no origin falls back to the top-level scope [PASS]\n");
	}

	/* An IOC is not a discovery origin. */
	if (libnvmf_config_resolve_discovered(config, list.conn[1], false)) {
		printf(" - IOC as origin rejected [FAIL]\n");
		pass = false;
	} else {
		printf(" - an IOC connection is not a discovery origin [PASS]\n");
	}

	libnvmf_config_free(config);

	return pass;
}

static bool test_validate(struct libnvme_global_ctx *ctx,
			  const struct fixture *fx)
{
	struct libnvmf_config *config;
	char missing[320];
	bool pass = true;

	printf("test_validate:\n");

	if (libnvmf_config_validate(ctx, fx->main_path)) {
		printf(" - valid tree [FAIL]\n");
		pass = false;
	} else {
		printf(" - valid tree validates clean [PASS]\n");
	}

	/* An absent configuration is a valid (empty) configuration. */
	snprintf(missing, sizeof(missing), "%s/no-such.conf", fx->dir);
	if (libnvmf_config_validate(ctx, missing)) {
		printf(" - absent config [FAIL]\n");
		pass = false;
	} else {
		printf(" - absent config is valid and empty [PASS]\n");
	}

	/* A Tier 1 problem in any file fails the tree as a unit. */
	write_file(fx->dropin_dir, "99-bad.conf", "not a key value line\n");
	if (libnvmf_config_validate(ctx, fx->main_path) >= 0) {
		printf(" - Tier 1 error detected [FAIL]\n");
		pass = false;
	} else {
		printf(" - Tier 1 error fails the tree as a unit [PASS]\n");
	}
	if (!libnvmf_config_read(ctx, fx->main_path, &config)) {
		printf(" - read refuses a broken tree [FAIL]\n");
		pass = false;
		libnvmf_config_free(config);
	} else {
		printf(" - read refuses a broken tree [PASS]\n");
	}
	rm_file(fx->dropin_dir, "99-bad.conf");

	return pass;
}

struct arg_list {
	char args[16][96];
	size_t n;
};

static void collect_arg(const char *arg, void *user_data)
{
	struct arg_list *list = user_data;

	assert(list->n < 16);
	snprintf(list->args[list->n++], sizeof(list->args[0]), "%s", arg);
}

static bool args_match(const struct arg_list *list,
		       const char * const *expect, size_t n)
{
	size_t i;

	if (list->n != n)
		return false;
	for (i = 0; i < n; i++) {
		if (strcmp(list->args[i], expect[i]))
			return false;
	}

	return true;
}

/*
 * A connection's addressing is raw strings, not a TID (see config.h) -- an
 * emitter caller resolves (traddr here is already numeric) and builds the
 * TID itself, exactly like this.
 */
static struct libnvmf_tid *build_tid(const struct libnvmf_config_conn *conn)
{
	return libnvmf_tid_from_fields(
			libnvmf_config_conn_get_transport(conn),
			libnvmf_config_conn_get_traddr(conn),
			libnvmf_config_conn_get_trsvcid(conn),
			libnvmf_config_conn_get_subsysnqn(conn),
			libnvmf_config_conn_get_host_traddr(conn),
			libnvmf_config_conn_get_host_iface(conn),
			libnvmf_config_conn_get_hostnqn(conn),
			libnvmf_config_conn_get_hostid(conn));
}

static bool test_emit(struct libnvme_global_ctx *ctx, const struct fixture *fx)
{
	static const char * const mv_expect[] = {
		"--transport=tcp",
		"--traddr=10.0.0.9",
		"--trsvcid=4420",
		"--nqn=nqn.2014-08.org.nvmexpress:main-vol",
		"--ctrl-loss-tmo=600",
		"--keep-alive-tmo=5",
		"--tls",
	};
	static const char * const pv_expect[] = {
		"--transport=tcp",
		"--traddr=10.0.0.7",
		"--trsvcid=4420",
		"--nqn=nqn.2014-08.org.nvmexpress:prod-vol",
		"--hostnqn=nqn.2014-08.org.nvmexpress:prod-host",
		"--hostid=46ba5037-7ce5-41fa-9452-48477bf00080",
		"--ctrl-loss-tmo=1800",
		"--keep-alive-tmo=5",
	};
	const struct libnvmf_config_conn *mv, *pv;
	struct conn_list conns = { 0 };
	struct arg_list args = { 0 };
	struct libnvmf_config *config;
	struct libnvmf_tid *mv_tid, *pv_tid;
	bool pass = true;

	printf("test_emit:\n");

	assert(!libnvmf_config_read(ctx, fx->main_path, &config));
	libnvmf_config_conn_for_each(config, collect, &conns);
	assert(conns.n == 3);
	mv = conns.conn[1];
	pv = conns.conn[2];

	mv_tid = build_tid(mv);
	pv_tid = build_tid(pv);
	assert(mv_tid && pv_tid);

	/* TID fields in fixed order, then params; true bool = bare flag. */
	if (libnvmf_connect_args_emit(mv_tid,
				      libnvmf_config_conn_get_params(mv),
				      collect_arg, &args) ||
	    !args_match(&args, mv_expect, ARRAY_SIZE(mv_expect))) {
		printf(" - main subsystem args [FAIL]\n");
		pass = false;
	} else {
		printf(" - TID first, params after; bool flags bare [PASS]\n");
	}

	/* Persona identity emitted; per-path override wins; reset skipped. */
	memset(&args, 0, sizeof(args));
	if (libnvmf_connect_args_emit(pv_tid,
				      libnvmf_config_conn_get_params(pv),
				      collect_arg, &args) ||
	    !args_match(&args, pv_expect, ARRAY_SIZE(pv_expect))) {
		printf(" - drop-in subsystem args [FAIL]\n");
		pass = false;
	} else {
		printf(" - persona identity kept, reset skipped [PASS]\n");
	}

	/* Each half is optional. */
	memset(&args, 0, sizeof(args));
	if (libnvmf_connect_args_emit(NULL,
				      libnvmf_config_conn_get_params(pv),
				      collect_arg, &args) ||
	    !args_match(&args, &pv_expect[6], 2)) {
		printf(" - params-only emission [FAIL]\n");
		pass = false;
	} else {
		printf(" - params-only emission (NULL TID) [PASS]\n");
	}

	memset(&args, 0, sizeof(args));
	if (libnvmf_connect_args_emit(mv_tid, NULL, collect_arg, &args) ||
	    !args_match(&args, mv_expect, 4)) {
		printf(" - TID-only emission [FAIL]\n");
		pass = false;
	} else {
		printf(" - TID-only emission (NULL params) [PASS]\n");
	}

	if (libnvmf_connect_args_emit(NULL, NULL, NULL, NULL) != -EINVAL) {
		printf(" - NULL callback [FAIL]\n");
		pass = false;
	} else {
		printf(" - NULL callback rejected [PASS]\n");
	}

	libnvmf_tid_free(mv_tid);
	libnvmf_tid_free(pv_tid);
	libnvmf_config_free(config);

	return pass;
}

static bool test_edge_cases(struct libnvme_global_ctx *ctx,
			    const struct fixture *fx)
{
	struct conn_list list = { 0 };
	struct libnvmf_config *config;
	char missing[320];
	bool pass = true;

	printf("test_edge_cases:\n");

	if (!libnvmf_config_read(NULL, fx->main_path, &config) ||
	    libnvmf_config_validate(NULL, fx->main_path) != -EINVAL) {
		printf(" - NULL ctx [FAIL]\n");
		pass = false;
	} else {
		printf(" - NULL ctx rejected [PASS]\n");
	}

	/* Reading an absent configuration yields an empty connection list. */
	snprintf(missing, sizeof(missing), "%s/no-such.conf", fx->dir);
	if (libnvmf_config_read(ctx, missing, &config)) {
		printf(" - absent config read [FAIL]\n");
		pass = false;
	} else {
		libnvmf_config_conn_for_each(config, collect, &list);
		if (list.n) {
			printf(" - absent config not empty [FAIL]\n");
			pass = false;
		} else {
			printf(" - absent config reads as empty [PASS]\n");
		}
	}
	libnvmf_config_free(config);

	/* Everything is NULL-tolerant on the way out. */
	if (libnvmf_config_conn_is_dc(NULL) ||
	    libnvmf_config_conn_get_transport(NULL) ||
	    libnvmf_config_conn_get_traddr(NULL) ||
	    libnvmf_config_conn_get_trsvcid(NULL) ||
	    libnvmf_config_conn_get_subsysnqn(NULL) ||
	    libnvmf_config_conn_get_host_traddr(NULL) ||
	    libnvmf_config_conn_get_host_iface(NULL) ||
	    libnvmf_config_conn_get_hostnqn(NULL) ||
	    libnvmf_config_conn_get_hostid(NULL) ||
	    libnvmf_config_conn_get_params(NULL) ||
	    libnvmf_config_conn_get_hostsymname(NULL) ||
	    libnvmf_config_conn_get_source(NULL) ||
	    libnvmf_config_resolve_discovered(NULL, NULL, true) ||
	    libnvmf_params_get(NULL, "tos")) {
		printf(" - NULL tolerance [FAIL]\n");
		pass = false;
	} else {
		printf(" - NULL-tolerant getters [PASS]\n");
	}
	libnvmf_config_conn_for_each(NULL, collect, NULL);
	libnvmf_params_for_each(NULL, NULL, NULL);
	libnvmf_config_free(NULL);
	printf(" - NULL iteration and free are no-ops [PASS]\n");

	return pass;
}

int main(void)
{
	struct libnvme_global_ctx *ctx;
	struct fixture fx;
	bool pass = true;

	ctx = libnvme_create_global_ctx();
	assert(ctx);
	fixture_create(&fx);

	pass &= test_read(ctx, &fx);
	pass &= test_resolve_discovered(ctx, &fx);
	pass &= test_validate(ctx, &fx);
	pass &= test_emit(ctx, &fx);
	pass &= test_edge_cases(ctx, &fx);

	fixture_destroy(&fx);
	libnvme_free_global_ctx(ctx);

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
