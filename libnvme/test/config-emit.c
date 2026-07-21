// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <martin.belanger@dell.com>
 *
 * Tests for the configuration write side (<nvme/config.h>): build a set of
 * connections, install them, and read the result back through the public
 * API.  Linked against the real shared library, so it also proves the
 * emitter symbols are exported.
 */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <unistd.h>

#include <nvme/lib.h>
#include <nvme/config.h>
#include <nvme/nvme-types-fabrics.h>
#include <nvme/accessors-fabrics.h>

static const char *g_hostid = "46ba5037-7ce5-41fa-9452-48477bf00080";

struct fixture {
	char dir[32];
	char main_path[288];
	char dropin_dir[288];
};

static void fixture_create(struct fixture *fx)
{
	snprintf(fx->dir, sizeof(fx->dir), "/tmp/nvme-config-emit-XXXXXX");
	assert(mkdtemp(fx->dir));
	snprintf(fx->main_path, sizeof(fx->main_path), "%s/nvme-fabrics.conf",
		 fx->dir);
	snprintf(fx->dropin_dir, sizeof(fx->dropin_dir),
		 "%s/nvme-fabrics.conf.d", fx->dir);
}

/* Recursively remove the fixture tree between subtests. */
static void fixture_wipe(struct fixture *fx)
{
	char path[600];
	struct dirent **e;
	int n;

	n = scandir(fx->dropin_dir, &e, NULL, alphasort);
	while (n > 0) {
		if (strcmp(e[--n]->d_name, ".") && strcmp(e[n]->d_name, "..")) {
			snprintf(path, sizeof(path), "%s/%s", fx->dropin_dir,
				 e[n]->d_name);
			unlink(path);
		}
		free(e[n]);
	}
	if (n == 0)
		free(e);
	rmdir(fx->dropin_dir);
	unlink(fx->main_path);
}

static void fixture_destroy(struct fixture *fx)
{
	fixture_wipe(fx);
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

/* Add one connection, params from key/value pairs. */
static int add(struct libnvmf_config_emitter *e, bool is_dc,
	       const char *traddr, const char *nqn, const char *hostnqn,
	       const char *hostid, const char *hostsymname,
	       const char *pkey, const char *pval)
{
	struct libnvmf_params *params = NULL;
	int ret;

	if (pkey) {
		params = libnvmf_params_new();
		assert(params);
		assert(libnvmf_params_set(params, pkey, pval) == 0);
	}
	ret = libnvmf_config_emit_add(e, is_dc, "tcp", traddr, "4420", nqn,
				      NULL, NULL, hostnqn, hostid, params,
				      hostsymname);
	libnvmf_params_free(params);

	return ret;
}

static bool test_roundtrip(struct libnvme_global_ctx *ctx, struct fixture *fx)
{
	const struct libnvmf_config_conn *dc, *mv, *pv;
	struct libnvmf_config_emitter *e;
	struct conn_list list = { 0 };
	struct libnvmf_config *config;
	const struct libnvmf_params *params;
	bool pass = true;

	printf("test_roundtrip:\n");

	e = libnvmf_config_emit_new(ctx);
	assert(e);

	/* Default persona: a DC and an I/O controller in the main file. */
	assert(add(e, true, "10.0.0.5", NULL, NULL, NULL, NULL,
		   NULL, NULL) == 0);
	assert(add(e, false, "10.0.0.9",
		   "nqn.2014-08.org.nvmexpress:main-vol", NULL, NULL, NULL,
		   "ctrl-loss-tmo", "600") == 0);
	/* A named persona: goes to its own drop-in. */
	assert(add(e, false, "10.0.0.7",
		   "nqn.2014-08.org.nvmexpress:prod-vol",
		   "nqn.2014-08.org.nvmexpress:prod-host",
		   g_hostid, "prod", "tls", "true") == 0);

	if (libnvmf_config_emit_install(e, fx->main_path, false)) {
		printf(" - install failed [FAIL]\n");
		libnvmf_config_emit_free(e);
		return false;
	}
	libnvmf_config_emit_free(e);
	printf(" - install succeeded [PASS]\n");

	/* The main file and one drop-in exist. */
	if (access(fx->main_path, F_OK) || access(fx->dropin_dir, F_OK)) {
		printf(" - expected tree not created [FAIL]\n");
		return false;
	}
	printf(" - main file + drop-in directory created [PASS]\n");

	if (libnvmf_config_read(ctx, fx->main_path, &config)) {
		printf(" - read-back failed [FAIL]\n");
		return false;
	}

	libnvmf_config_conn_for_each(config, collect, &list);
	if (list.n != 3) {
		printf(" - expected 3 connections, got %zu [FAIL]\n", list.n);
		libnvmf_config_free(config);
		return false;
	}
	printf(" - three connections read back [PASS]\n");

	/* Main file first: the DC, then the I/O controller. */
	dc = list.conn[0];
	mv = list.conn[1];
	pv = list.conn[2];

	if (!libnvmf_config_conn_is_dc(dc) ||
	    strcmp(libnvmf_config_conn_get_traddr(dc), "10.0.0.5") ||
	    strcmp(libnvmf_config_conn_get_subsysnqn(dc), NVME_DISC_SUBSYS_NAME)) {
		printf(" - DC round-trip [FAIL]\n");
		pass = false;
	} else {
		printf(" - DC kept its address and default NQN [PASS]\n");
	}

	params = libnvmf_config_conn_get_params(mv);
	if (libnvmf_config_conn_get_hostnqn(mv) ||
	    strcmp(libnvmf_config_conn_get_subsysnqn(mv),
		   "nqn.2014-08.org.nvmexpress:main-vol") ||
	    strcmp(libnvmf_params_get(params, "ctrl-loss-tmo"), "600")) {
		printf(" - default-persona subsystem round-trip [FAIL]\n");
		pass = false;
	} else {
		printf(" - default persona in the main file, param kept [PASS]\n");
	}

	params = libnvmf_config_conn_get_params(pv);
	if (strcmp(libnvmf_config_conn_get_hostnqn(pv),
		   "nqn.2014-08.org.nvmexpress:prod-host") ||
	    strcmp(libnvmf_config_conn_get_hostid(pv), g_hostid) ||
	    strcmp(libnvmf_config_conn_get_hostsymname(pv), "prod") ||
	    strcmp(libnvmf_params_get(params, "tls"), "true")) {
		printf(" - named-persona drop-in round-trip [FAIL]\n");
		pass = false;
	} else {
		printf(" - named persona in its drop-in, identity kept [PASS]\n");
	}

	if (!strstr(libnvmf_config_conn_get_source(pv), ".conf.d/")) {
		printf(" - drop-in provenance [FAIL]\n");
		pass = false;
	} else {
		printf(" - named persona's source is the drop-in [PASS]\n");
	}

	libnvmf_config_free(config);

	return pass;
}

/*
 * A hostname traddr must survive unresolved -- an INI file is a human
 * interface, and resolution happens at connect time, not emit time.
 */
static bool test_hostname_traddr_verbatim(struct libnvme_global_ctx *ctx,
					  struct fixture *fx)
{
	struct conn_list list = { 0 };
	struct libnvmf_config_emitter *e;
	struct libnvmf_config *config;
	bool pass = true;

	printf("test_hostname_traddr_verbatim:\n");

	e = libnvmf_config_emit_new(ctx);
	assert(e);

	if (libnvmf_config_emit_add(e, false, "tcp", "nas.example.com", "4420",
				    "nqn.2014-08.org.nvmexpress:main-vol",
				    NULL, NULL, NULL, NULL, NULL, NULL)) {
		printf(" - hostname traddr rejected [FAIL]\n");
		libnvmf_config_emit_free(e);
		return false;
	}

	if (libnvmf_config_emit_install(e, fx->main_path, false)) {
		printf(" - install failed [FAIL]\n");
		libnvmf_config_emit_free(e);
		return false;
	}
	libnvmf_config_emit_free(e);
	printf(" - hostname traddr accepted and installed [PASS]\n");

	assert(libnvmf_config_read(ctx, fx->main_path, &config) == 0);
	libnvmf_config_conn_for_each(config, collect, &list);
	if (list.n != 1 ||
	    strcmp(libnvmf_config_conn_get_traddr(list.conn[0]),
		   "nas.example.com")) {
		printf(" - hostname not preserved verbatim [FAIL]\n");
		pass = false;
	} else {
		printf(" - hostname preserved verbatim on read-back [PASS]\n");
	}
	libnvmf_config_free(config);

	return pass;
}

static bool test_refuse_existing(struct libnvme_global_ctx *ctx,
				 struct fixture *fx)
{
	struct libnvmf_config_emitter *e;
	char path[600];
	int ret;
	FILE *f;

	printf("test_refuse_existing:\n");

	/* An empty main file alone is enough to occupy the target. */
	f = fopen(fx->main_path, "w");
	assert(f);
	assert(fclose(f) == 0);

	e = libnvmf_config_emit_new(ctx);
	assert(e);
	assert(add(e, false, "10.0.0.9", "nqn.vol", NULL, NULL, NULL,
		   NULL, NULL) == 0);
	ret = libnvmf_config_emit_install(e, fx->main_path, false);
	libnvmf_config_emit_free(e);

	if (ret != -EEXIST) {
		printf(" - expected -EEXIST, got %d [FAIL]\n", ret);
		return false;
	}
	printf(" - refuses when the main file exists [PASS]\n");

	fixture_wipe(fx);

	/* A lone .conf drop-in also counts as an existing configuration. */
	assert(mkdir(fx->dropin_dir, 0755) == 0);
	snprintf(path, sizeof(path), "%s/10-x.conf", fx->dropin_dir);
	f = fopen(path, "w");
	assert(f);
	assert(fclose(f) == 0);

	e = libnvmf_config_emit_new(ctx);
	assert(e);
	assert(add(e, false, "10.0.0.9", "nqn.vol", NULL, NULL, NULL,
		   NULL, NULL) == 0);
	ret = libnvmf_config_emit_install(e, fx->main_path, false);
	libnvmf_config_emit_free(e);

	if (ret != -EEXIST) {
		printf(" - expected -EEXIST for drop-in, got %d [FAIL]\n", ret);
		return false;
	}
	printf(" - refuses when a drop-in exists [PASS]\n");

	return true;
}

static bool test_force_overwrite(struct libnvme_global_ctx *ctx,
				 struct fixture *fx)
{
	const struct libnvmf_config_conn *conn;
	struct libnvmf_config_emitter *e;
	struct conn_list list = { 0 };
	struct libnvmf_config *config;
	bool pass = true;
	FILE *f;

	printf("test_force_overwrite:\n");

	/* A stale configuration occupies the target. */
	f = fopen(fx->main_path, "w");
	assert(f);
	assert(fclose(f) == 0);

	e = libnvmf_config_emit_new(ctx);
	assert(e);
	assert(add(e, false, "10.0.0.9",
		   "nqn.2014-08.org.nvmexpress:force-vol", NULL, NULL, NULL,
		   NULL, NULL) == 0);

	if (libnvmf_config_emit_install(e, fx->main_path, true)) {
		printf(" - force install failed [FAIL]\n");
		libnvmf_config_emit_free(e);
		return false;
	}
	libnvmf_config_emit_free(e);
	printf(" - force overwrites an existing target [PASS]\n");

	if (libnvmf_config_read(ctx, fx->main_path, &config)) {
		printf(" - read-back failed [FAIL]\n");
		return false;
	}

	libnvmf_config_conn_for_each(config, collect, &list);
	if (list.n != 1) {
		printf(" - expected 1 connection, got %zu [FAIL]\n", list.n);
		libnvmf_config_free(config);
		return false;
	}

	conn = list.conn[0];
	if (strcmp(libnvmf_config_conn_get_subsysnqn(conn),
		   "nqn.2014-08.org.nvmexpress:force-vol")) {
		printf(" - overwritten content [FAIL]\n");
		pass = false;
	} else {
		printf(" - target holds the new configuration [PASS]\n");
	}

	libnvmf_config_free(config);

	return pass;
}

static bool test_all_dropins(struct libnvme_global_ctx *ctx, struct fixture *fx)
{
	struct libnvmf_config_emitter *e;
	struct conn_list list = { 0 };
	struct libnvmf_config *config;
	bool pass = true;

	printf("test_all_dropins:\n");

	/* No default persona: every connection is a named persona. */
	e = libnvmf_config_emit_new(ctx);
	assert(e);
	assert(add(e, false, "10.0.0.9", "nqn.2014-08.org.nvmexpress:a",
		   "nqn.2014-08.org.nvmexpress:host-a", NULL, "a",
		   NULL, NULL) == 0);
	assert(add(e, false, "10.0.0.10", "nqn.2014-08.org.nvmexpress:b",
		   "nqn.2014-08.org.nvmexpress:host-b", NULL, "b",
		   NULL, NULL) == 0);

	if (libnvmf_config_emit_install(e, fx->main_path, false)) {
		printf(" - install failed [FAIL]\n");
		libnvmf_config_emit_free(e);
		return false;
	}
	libnvmf_config_emit_free(e);

	/* The anchor main file is written even with no default persona. */
	if (access(fx->main_path, F_OK)) {
		printf(" - anchor main file missing [FAIL]\n");
		return false;
	}
	printf(" - empty anchor main file written [PASS]\n");

	assert(libnvmf_config_read(ctx, fx->main_path, &config) == 0);
	libnvmf_config_conn_for_each(config, collect, &list);
	if (list.n != 2) {
		printf(" - expected 2 connections, got %zu [FAIL]\n", list.n);
		pass = false;
	} else {
		printf(" - two personas, two drop-ins, read back [PASS]\n");
	}
	libnvmf_config_free(config);

	return pass;
}

static bool test_add_validation(struct libnvme_global_ctx *ctx)
{
	struct libnvmf_config_emitter *e;
	bool pass = true;

	printf("test_add_validation:\n");

	e = libnvmf_config_emit_new(ctx);
	assert(e);

	/* An I/O controller with no subsysnqn is rejected. */
	if (libnvmf_config_emit_add(e, false, "tcp", "10.0.0.9", "4420",
				    NULL, NULL, NULL, NULL, NULL, NULL,
				    NULL) != -EINVAL) {
		printf(" - IOC without nqn accepted [FAIL]\n");
		pass = false;
	} else {
		printf(" - IOC without a subsysnqn rejected [PASS]\n");
	}

	/* Transport is required. */
	if (libnvmf_config_emit_add(e, false, NULL, "10.0.0.9", "4420",
				    "nqn.v", NULL, NULL, NULL, NULL, NULL,
				    NULL) != -EINVAL) {
		printf(" - missing transport accepted [FAIL]\n");
		pass = false;
	} else {
		printf(" - missing transport rejected [PASS]\n");
	}

	/* Conflicting hostsymname for the same persona is rejected. */
	assert(add(e, false, "10.0.0.9", "nqn.a", "nqn.host", g_hostid, "one",
		   NULL, NULL) == 0);
	if (add(e, false, "10.0.0.10", "nqn.b", "nqn.host", g_hostid, "two",
		NULL, NULL) != -EINVAL) {
		printf(" - conflicting hostsymname accepted [FAIL]\n");
		pass = false;
	} else {
		printf(" - conflicting hostsymname rejected [PASS]\n");
	}
	libnvmf_config_emit_free(e);

	/* A hostid without a hostnqn cannot become a valid drop-in. */
	e = libnvmf_config_emit_new(ctx);
	assert(e);
	if (add(e, false, "10.0.0.9", "nqn.v", NULL, g_hostid, NULL,
		NULL, NULL) != -EINVAL) {
		printf(" - hostid without hostnqn accepted [FAIL]\n");
		pass = false;
	} else {
		printf(" - hostid without hostnqn rejected [PASS]\n");
	}
	libnvmf_config_emit_free(e);

	/* One hostnqn must not appear with two different hostids. */
	e = libnvmf_config_emit_new(ctx);
	assert(e);
	assert(add(e, false, "10.0.0.9", "nqn.a", "nqn.host", g_hostid, NULL,
		   NULL, NULL) == 0);
	if (add(e, false, "10.0.0.10", "nqn.b", "nqn.host",
		"00000000-0000-0000-0000-000000000002", NULL, NULL, NULL)
	    != -EINVAL) {
		printf(" - one hostnqn with two hostids accepted [FAIL]\n");
		pass = false;
	} else {
		printf(" - one hostnqn with two hostids rejected [PASS]\n");
	}
	libnvmf_config_emit_free(e);

	return pass;
}

static bool test_params_set_validation(void)
{
	struct libnvmf_params *p = libnvmf_params_new();
	bool pass = true;

	printf("test_params_set_validation:\n");
	assert(p);

	if (libnvmf_params_set(p, "ctrl-loss-tmo", "600") ||
	    libnvmf_params_set(p, "tls", "true") ||
	    libnvmf_params_set(p, "reconnect-delay", "")) {
		printf(" - valid keys rejected [FAIL]\n");
		pass = false;
	} else {
		printf(" - valid tunable/security/reset keys accepted [PASS]\n");
	}

	/* Unknown key, an identity key (belongs to the TID), and a bad int. */
	if (libnvmf_params_set(p, "no-such-key", "x") != -EINVAL ||
	    libnvmf_params_set(p, "hostnqn", "nqn.x") != -EINVAL ||
	    libnvmf_params_set(p, "ctrl-loss-tmo", "notanint") != -EINVAL) {
		printf(" - invalid set accepted [FAIL]\n");
		pass = false;
	} else {
		printf(" - unknown/identity/bad-value keys rejected [PASS]\n");
	}

	/* A value with an embedded newline can't survive an INI round trip. */
	if (libnvmf_params_set(p, "dhchap-secret", "abc\ndef") != -EINVAL) {
		printf(" - value with newline accepted [FAIL]\n");
		pass = false;
	} else {
		printf(" - value with embedded newline rejected [PASS]\n");
	}

	libnvmf_params_free(p);

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

	pass &= test_roundtrip(ctx, &fx);
	fixture_wipe(&fx);
	pass &= test_hostname_traddr_verbatim(ctx, &fx);
	fixture_wipe(&fx);
	pass &= test_refuse_existing(ctx, &fx);
	fixture_wipe(&fx);
	pass &= test_force_overwrite(ctx, &fx);
	fixture_wipe(&fx);
	pass &= test_all_dropins(ctx, &fx);
	fixture_wipe(&fx);
	pass &= test_add_validation(ctx);
	pass &= test_params_set_validation();

	fixture_destroy(&fx);
	libnvme_free_global_ctx(ctx);

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
