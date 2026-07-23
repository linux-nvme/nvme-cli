// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <martin.belanger@dell.com>
 *
 * Unit tests for the INI connection-config building blocks (config-ini.c):
 * the three-state parameter bag, the key table, and the typed value
 * validators.
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
#include <nvme/nvme-types-fabrics.h>

#include "nvme/config-ini.h"

static bool test_params_tristate(void)
{
	struct libnvmf_params *p = libnvmf_params_new();
	bool pass = true;

	printf("test_params_tristate:\n");
	assert(p);

	/* Absent key -> unset (NULL). */
	if (libnvmf_params_get(p, "ctrl-loss-tmo")) {
		printf(" - absent key reads as NULL [FAIL]\n");
		pass = false;
	} else {
		printf(" - absent key reads as NULL (unset) [PASS]\n");
	}

	/* Set, overwrite, reset. */
	assert(libnvmf_params_set(p, "ctrl-loss-tmo", "600") == 0);
	assert(libnvmf_params_set(p, "keep-alive-tmo", "30") == 0);
	assert(libnvmf_params_set(p, "ctrl-loss-tmo", "1800") == 0);
	if (strcmp(libnvmf_params_get(p, "ctrl-loss-tmo"), "1800")) {
		printf(" - set + overwrite [FAIL]\n");
		pass = false;
	} else {
		printf(" - set + overwrite (last wins) [PASS]\n");
	}

	assert(libnvmf_params_set(p, "keep-alive-tmo", "") == 0);
	if (strcmp(libnvmf_params_get(p, "keep-alive-tmo"), "")) {
		printf(" - reset reads as \"\" [FAIL]\n");
		pass = false;
	} else {
		printf(" - reset (\"\") is distinct from unset (NULL) [PASS]\n");
	}

	libnvmf_params_free(p);
	return pass;
}

struct order {
	char seen[256];
};

static void record_order(const char *key, const char *value, void *user_data)
{
	struct order *o = user_data;

	snprintf(o->seen + strlen(o->seen), sizeof(o->seen) - strlen(o->seen),
		 "%s=%s;", key, value);
}

static bool test_params_merge(void)
{
	struct libnvmf_params *base = libnvmf_params_new();
	struct libnvmf_params *over = libnvmf_params_new();
	struct libnvmf_params *copy;
	struct order o = { "" };
	bool pass = true;

	printf("test_params_merge:\n");
	assert(base && over);

	/* base: the outer cascade level; over: the more-specific one. */
	assert(libnvmf_params_set(base, "ctrl-loss-tmo", "600") == 0);
	assert(libnvmf_params_set(base, "tls", "true") == 0);
	assert(libnvmf_params_set(over, "ctrl-loss-tmo", "1800") == 0);
	assert(libnvmf_params_set(over, "keep-alive-tmo", "") == 0);

	assert(libnvmf_params_merge(base, over) == 0);
	if (strcmp(libnvmf_params_get(base, "ctrl-loss-tmo"), "1800") ||
	    strcmp(libnvmf_params_get(base, "tls"), "true") ||
	    strcmp(libnvmf_params_get(base, "keep-alive-tmo"), "")) {
		printf(" - merge precedence [FAIL]\n");
		pass = false;
	} else {
		printf(" - merge: src wins, dst-only keys survive, reset carries [PASS]\n");
	}

	/* Iteration preserves first-insertion order. */
	libnvmf_params_for_each(base, record_order, &o);
	if (strcmp(o.seen, "ctrl-loss-tmo=1800;tls=true;keep-alive-tmo=;")) {
		printf(" - iteration order: %s [FAIL]\n", o.seen);
		pass = false;
	} else {
		printf(" - iteration preserves insertion order [PASS]\n");
	}

	/* dup produces an equal, independent bag. */
	copy = libnvmf_params_dup(base);
	assert(copy);
	assert(libnvmf_params_set(copy, "tls", "false") == 0);
	if (strcmp(libnvmf_params_get(base, "tls"), "true") ||
	    strcmp(libnvmf_params_get(copy, "tls"), "false")) {
		printf(" - dup independence [FAIL]\n");
		pass = false;
	} else {
		printf(" - dup is deep (independent copies) [PASS]\n");
	}

	libnvmf_params_free(base);
	libnvmf_params_free(over);
	libnvmf_params_free(copy);
	return pass;
}

static bool test_key_table(void)
{
	static const struct {
		const char *name;
		enum libnvmf_key_class class;
	} expect[] = {
		{ "ctrl-loss-tmo",	LIBNVMF_KEY_TUNABLE },
		{ "hdr-digest",		LIBNVMF_KEY_TUNABLE },
		{ "tls-key",		LIBNVMF_KEY_SECURITY },
		{ "dhchap-secret",	LIBNVMF_KEY_SECURITY },
		{ "hostnqn",		LIBNVMF_KEY_IDENTITY },
		{ "hostsymname",	LIBNVMF_KEY_IDENTITY },
		{ "nqn",		LIBNVMF_KEY_NQN },
		{ "controller",		LIBNVMF_KEY_CONTROLLER },
	};
	bool pass = true;
	size_t i;

	printf("test_key_table:\n");

	for (i = 0; i < ARRAY_SIZE(expect); i++) {
		const struct libnvmf_key *k = libnvmf_key_lookup(expect[i].name);

		if (!k || k->class != expect[i].class) {
			printf(" - key %s [FAIL]\n", expect[i].name);
			pass = false;
		}
	}
	if (pass)
		printf(" - classes for a sample of every kind [PASS]\n");

	/* One spelling per key: no aliases, no underscore variants. */
	if (libnvmf_key_lookup("fast_io_fail_tmo") ||
	    libnvmf_key_lookup("subsysnqn") ||
	    libnvmf_key_lookup("bogus")) {
		printf(" - unknown/alias spellings rejected [FAIL]\n");
		pass = false;
	} else {
		printf(" - unknown keys and alias spellings -> NULL [PASS]\n");
	}
	if (!libnvmf_key_lookup("fast-io-fail-tmo")) {
		printf(" - fast-io-fail-tmo (hyphenated) known [FAIL]\n");
		pass = false;
	} else {
		printf(" - fast-io-fail-tmo uses the hyphenated spelling [PASS]\n");
	}

	return pass;
}

static bool test_value_check(void)
{
	const struct libnvmf_key *i = libnvmf_key_lookup("ctrl-loss-tmo");
	const struct libnvmf_key *b = libnvmf_key_lookup("tls");
	const struct libnvmf_key *s = libnvmf_key_lookup("tls-key");
	static const char * const good_bools[] = {
		"1", "yes", "Y", "TRUE", "t", "On", "0", "no", "N", "False",
		"f", "OFF",
	};
	bool pass = true;
	size_t n;

	printf("test_value_check:\n");
	assert(i && b && s);

	/* Integers: decimals including -1; garbage rejected. */
	if (libnvmf_key_check_value(i, "600") || libnvmf_key_check_value(i, "-1") ||
	    !libnvmf_key_check_value(i, "12x") || !libnvmf_key_check_value(i, "1.5") ||
	    !libnvmf_key_check_value(i, "tomorrow")) {
		printf(" - int validation [FAIL]\n");
		pass = false;
	} else {
		printf(" - int values (incl. -1) accepted, garbage rejected [PASS]\n");
	}

	/* Hex/octal accepted too -- base 0, matching the kernel's match_int()
	 * and nvme-cli's own argconfig.c parsing of the same options.
	 */
	if (libnvmf_key_check_value(i, "0x1E") ||
	    libnvmf_key_check_value(i, "030")) {
		printf(" - hex/octal int values [FAIL]\n");
		pass = false;
	} else {
		printf(" - hex/octal int values accepted (base 0) [PASS]\n");
	}

	/* Booleans: the systemd spellings, case-insensitive. */
	for (n = 0; n < ARRAY_SIZE(good_bools); n++) {
		if (libnvmf_key_check_value(b, good_bools[n])) {
			printf(" - bool %s rejected [FAIL]\n", good_bools[n]);
			pass = false;
		}
	}
	if (!libnvmf_key_check_value(b, "maybe") ||
	    !libnvmf_key_check_value(b, "2")) {
		printf(" - bad bool accepted [FAIL]\n");
		pass = false;
	} else if (pass) {
		printf(" - boolean spellings (case-insensitive) [PASS]\n");
	}

	/* The reset form is valid for every type. */
	if (libnvmf_key_check_value(i, "") || libnvmf_key_check_value(b, "") ||
	    libnvmf_key_check_value(s, "")) {
		printf(" - reset (\"\") accepted everywhere [FAIL]\n");
		pass = false;
	} else {
		printf(" - reset (\"\") accepted for every type [PASS]\n");
	}

	return pass;
}


/* Write @text to a temp file and parse it into the raw model. */
static struct libnvmf_conf_file *parse_text(struct libnvme_global_ctx *ctx,
					    const char *text, int *err)
{
	char path[] = "/tmp/nvme-config-ini-XXXXXX";
	struct libnvmf_conf_file *f;
	size_t len = strlen(text);
	int fd;

	fd = mkstemp(path);
	assert(fd >= 0);
	assert(write(fd, text, len) == (ssize_t)len);
	close(fd);
	*err = libnvmf_conf_file_parse(ctx, path, &f);
	unlink(path);

	return f;
}

static bool test_parse_model(struct libnvme_global_ctx *ctx)
{
	static const char text[] =
		"# a complete single-persona file\n"
		"[Discovery Controller Defaults]\n"
		"keep-alive-tmo = 30\n"
		"ctrl-loss-tmo = 600\n"
		"\n"
		"[I/O Controller Defaults]\n"
		"keep-alive-tmo = 5\n"
		"ctrl-loss-tmo = 600\n"
		"\n"
		"[Host]\n"
		"hostnqn = nqn.2014-08.org.nvmexpress:host\n"
		"hostid = 46ba5037-7ce5-41fa-9452-48477bf00080\n"
		"dhchap-secret = DHHC-1:00:abc\n"
		"\n"
		"[Discovery Controller]\n"
		"controller = transport=tcp;traddr=10.0.0.5;trsvcid=8009\n"
		"\n"
		"[Subsystem]\n"
		"nqn           = nqn.2014-08.org.nvmexpress:vol1\n"
		"tls           = true\n"
		"ctrl-loss-tmo = 1800\n"
		"controller    = transport=tcp;traddr=10.0.0.9;trsvcid=4420;host-iface=eth0\n"
		"controller    = transport=tcp;traddr=10.0.0.10;trsvcid=4420;keep-alive-tmo=10\n";
	struct libnvmf_conf_file *f;
	struct libnvmf_conf_endpoint *dc, *ss;
	struct libnvmf_conf_path *p1, *p2;
	bool pass = true;
	int err;

	printf("test_parse_model:\n");

	f = parse_text(ctx, text, &err);
	if (!f) {
		printf(" - parse failed: %d [FAIL]\n", err);
		return false;
	}

	if (strcmp(libnvmf_params_get(f->dc_defaults, "keep-alive-tmo"),
		   "30") ||
	    strcmp(libnvmf_params_get(f->dc_defaults, "ctrl-loss-tmo"),
		   "600") ||
	    strcmp(libnvmf_params_get(f->ioc_defaults, "keep-alive-tmo"),
		   "5") ||
	    strcmp(libnvmf_params_get(f->ioc_defaults, "ctrl-loss-tmo"),
		   "600")) {
		printf(" - defaults sections [FAIL]\n");
		pass = false;
	} else {
		printf(" - per-type defaults recorded, in both [PASS]\n");
	}

	if (!f->has_host || strcmp(f->hostnqn, "nqn.2014-08.org.nvmexpress:host") ||
	    strcmp(f->hostid, "46ba5037-7ce5-41fa-9452-48477bf00080") ||
	    strcmp(libnvmf_params_get(f->host_params, "dhchap-secret"),
		   "DHHC-1:00:abc")) {
		printf(" - [Host] identity + params [FAIL]\n");
		pass = false;
	} else {
		printf(" - [Host] identity and host-level params [PASS]\n");
	}

	dc = list_top(&f->endpoints, struct libnvmf_conf_endpoint, entry);
	ss = dc ? list_next(&f->endpoints, dc, entry) : NULL;
	if (!dc || !ss || list_next(&f->endpoints, ss, entry) || !dc->is_dc ||
	    dc->nqn || ss->is_dc ||
	    strcmp(ss->nqn, "nqn.2014-08.org.nvmexpress:vol1")) {
		printf(" - endpoint list [FAIL]\n");
		pass = false;
	} else {
		printf(" - one DC (default NQN) + one [Subsystem] [PASS]\n");
	}

	if (!ss || !ss->params ||
	    strcmp(libnvmf_params_get(ss->params, "tls"), "true") ||
	    strcmp(libnvmf_params_get(ss->params, "ctrl-loss-tmo"), "1800")) {
		printf(" - endpoint section params [FAIL]\n");
		pass = false;
	} else {
		printf(" - endpoint params (security + tunable) [PASS]\n");
	}

	p1 = ss ? list_top(&ss->paths, struct libnvmf_conf_path, entry) : NULL;
	p2 = p1 ? list_next(&ss->paths, p1, entry) : NULL;
	if (!p1 || !p2 || list_next(&ss->paths, p2, entry) ||
	    strcmp(p1->traddr, "10.0.0.9") ||
	    strcmp(p1->host_iface, "eth0") ||
	    libnvmf_params_get(p1->overrides, "keep-alive-tmo") ||
	    strcmp(p2->traddr, "10.0.0.10") ||
	    strcmp(libnvmf_params_get(p2->overrides, "keep-alive-tmo"),
		   "10")) {
		printf(" - multipath + per-path override [FAIL]\n");
		pass = false;
	} else {
		printf(" - 2 paths: raw addressing + per-path override [PASS]\n");
	}

	libnvmf_conf_file_free(f);
	return pass;
}

/*
 * A config file is a human interface: a hostname traddr is legitimate
 * (libnvme/design/INTEGRATION.md's worked example) even though TID
 * construction rejects one.  The raw model must not resolve or reject it --
 * that is the consumer's job.
 */
static bool test_parse_hostname(struct libnvme_global_ctx *ctx)
{
	static const char text[] =
		"[Subsystem]\n"
		"nqn = nqn.2014-08.org.nvmexpress:vol1\n"
		"controller = transport=tcp;traddr=storage.example.com;trsvcid=4420\n";
	struct libnvmf_conf_file *f;
	struct libnvmf_conf_endpoint *ep;
	struct libnvmf_conf_path *p;
	bool pass = true;
	int err;

	printf("test_parse_hostname:\n");

	f = parse_text(ctx, text, &err);
	if (!f) {
		printf(" - hostname traddr rejected: %d [FAIL]\n", err);
		return false;
	}

	ep = list_top(&f->endpoints, struct libnvmf_conf_endpoint, entry);
	p = ep ? list_top(&ep->paths, struct libnvmf_conf_path, entry) : NULL;
	if (!p || strcmp(p->traddr, "storage.example.com")) {
		printf(" - hostname traddr not stored verbatim [FAIL]\n");
		pass = false;
	} else {
		printf(" - hostname traddr parses, stored raw [PASS]\n");
	}

	libnvmf_conf_file_free(f);
	return pass;
}

static bool test_parse_errors(struct libnvme_global_ctx *ctx)
{
	static const struct {
		const char *name;
		const char *text;
	} cases[] = {
		{ "second [Host]", "[Host]\n[Host]\n" },
		{ "key before any section", "ctrl-loss-tmo = 5\n" },
		{ "identity key in [Discovery Controller Defaults]",
		  "[Discovery Controller Defaults]\nhostnqn = x\n" },
		{ "security key per-path",
		  "[Subsystem]\nnqn = nqn.2014-08.org.nvmexpress:test\ncontroller = transport=tcp;traddr=1.2.3.4;tls-key=k\n" },
		{ "unknown key on a controller line",
		  "[Subsystem]\nnqn = nqn.2014-08.org.nvmexpress:test\ncontroller = transport=tcp;traddr=1.2.3.4;bogus=1\n" },
		{ "controller line without traddr",
		  "[Subsystem]\nnqn = nqn.2014-08.org.nvmexpress:test\ncontroller = transport=tcp\n" },
		{ "repeated addressing key on a controller line",
		  "[Subsystem]\nnqn = nqn.2014-08.org.nvmexpress:test\n"
		  "controller = transport=tcp;traddr=1.2.3.4;traddr=5.6.7.8\n" },
		{ "empty nqn", "[Subsystem]\nnqn =\n" },
		{ "junk line",
		  "[Discovery Controller Defaults]\nwhat is this\n" },
		{ "[Subsystem] without an nqn",
		  "[Subsystem]\ncontroller = transport=tcp;traddr=1.2.3.4\n" },
		{ "bad integer value",
		  "[Discovery Controller Defaults]\nctrl-loss-tmo = ten\n" },
		{ "bad boolean value", "[Subsystem]\nnqn = nqn.2014-08.org.nvmexpress:test\ntls = maybe\n" },
		{ "malformed nqn (no date component)",
		  "[Subsystem]\nnqn = not-an-nqn\n" },
		{ "malformed nqn (bad month)",
		  "[Subsystem]\nnqn = nqn.2014-13.org.nvmexpress:test\n" },
		{ "malformed hostnqn",
		  "[Host]\nhostnqn = not-an-nqn\n" },
		{ "zero hostid",
		  "[Host]\nhostnqn = nqn.2014-08.org.nvmexpress:h\n"
		  "hostid = 00000000-0000-0000-0000-000000000000\n" },
		{ "malformed hostid",
		  "[Host]\nhostnqn = nqn.2014-08.org.nvmexpress:h\n"
		  "hostid = not-a-uuid\n" },
	};
	bool pass = true;
	size_t i;

	printf("test_parse_errors:\n");

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct libnvmf_conf_file *f;
		int err = 0;

		f = parse_text(ctx, cases[i].text, &err);
		if (f || err != -EINVAL) {
			printf(" - %s: not rejected (err=%d) [FAIL]\n",
			       cases[i].name, err);
			libnvmf_conf_file_free(f);
			pass = false;
		}
	}
	if (pass)
		printf(" - every Tier 1 case rejected with -EINVAL [PASS]\n");

	return pass;
}

static bool test_parse_hygiene(struct libnvme_global_ctx *ctx)
{
	static const char text[] =
		"[Discovery Controller Defaults]\n"
		"unknown-knob = 7\n"		/* Tier 2: warn, ignore */
		"[SomeFutureSection]\n"	/* Tier 2: warn, ignore content */
		"whatever = x\n"
		"[Discovery Controller Defaults]\n"	/* Tier 2: warn+merge */
		"reconnect-delay = 20\n"
		"[Host]\n"
		"hostid =\n";			/* explicit reset, recorded as "" */
	struct libnvmf_conf_file *f;
	bool pass = true;
	int err;

	printf("test_parse_hygiene:\n");

	f = parse_text(ctx, text, &err);
	if (!f) {
		printf(" - hygiene file rejected: %d [FAIL]\n", err);
		return false;
	}

	if (libnvmf_params_get(f->dc_defaults, "unknown-knob")) {
		printf(" - unknown key ignored [FAIL]\n");
		pass = false;
	} else {
		printf(" - unknown key warned + ignored [PASS]\n");
	}
	if (strcmp(libnvmf_params_get(f->dc_defaults, "reconnect-delay"),
		   "20")) {
		printf(" - repeated [DC Defaults] section merged [FAIL]\n");
		pass = false;
	} else {
		printf(" - repeated section merges into one bag [PASS]\n");
	}
	if (!f->hostid || strcmp(f->hostid, "")) {
		printf(" - hostid reset [FAIL]\n");
		pass = false;
	} else {
		printf(" - \"hostid =\" recorded as an explicit reset [PASS]\n");
	}

	libnvmf_conf_file_free(f);
	return pass;
}


/* --- resolver fixtures: a config tree under a throwaway directory --- */

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

static void rm_tree(const char *dir)
{
	char cmd[600];

	snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
	assert(system(cmd) == 0);
}

static bool test_resolve_empty(struct libnvme_global_ctx *ctx)
{
	char dir[] = "/tmp/nvme-conf-XXXXXX";
	char main_path[512];
	struct libnvmf_config *conf;
	bool pass = true;
	int err;

	printf("test_resolve_empty:\n");
	assert(mkdtemp(dir));
	snprintf(main_path, sizeof(main_path), "%s/nvme-fabrics.conf", dir);

	/* Nothing on disk: an empty configuration, not an error. */
	err = libnvmf_config_load(ctx, main_path, &conf);
	if (!conf || err || !list_empty(&conf->conns)) {
		printf(" - absent config err=%d [FAIL]\n", err);
		pass = false;
	} else {
		printf(" - absent main + absent .d/ -> empty config [PASS]\n");
	}

	libnvmf_config_free(conf);
	rm_tree(dir);
	return pass;
}

/*
 * A hostname traddr must resolve into the connection list verbatim: the
 * resolver builds no TID (which would reject it), it only merges the
 * cascade -- resolving the name is the consumer's job.
 */
static bool test_resolve_hostname(struct libnvme_global_ctx *ctx)
{
	char dir[] = "/tmp/nvme-conf-XXXXXX";
	char main_path[512];
	struct libnvmf_config *conf;
	struct libnvmf_config_conn *conn;
	bool pass = true;
	int err;

	printf("test_resolve_hostname:\n");
	assert(mkdtemp(dir));
	snprintf(main_path, sizeof(main_path), "%s/nvme-fabrics.conf", dir);
	write_file(dir, "nvme-fabrics.conf",
		   "[Subsystem]\nnqn = nqn.2014-08.org.nvmexpress:vol1\n"
		   "controller = transport=tcp;traddr=storage.example.com\n");

	err = libnvmf_config_load(ctx, main_path, &conf);
	conn = conf ?
	       list_top(&conf->conns, struct libnvmf_config_conn, entry) :
	       NULL;
	if (!conf || !conn || list_next(&conf->conns, conn, entry) ||
	    strcmp(conn->traddr, "storage.example.com")) {
		printf(" - hostname traddr resolved err=%d [FAIL]\n", err);
		pass = false;
	} else {
		printf(" - hostname traddr survives the cascade raw [PASS]\n");
	}

	libnvmf_config_free(conf);
	rm_tree(dir);
	return pass;
}

static bool test_resolve_cascade(struct libnvme_global_ctx *ctx)
{
	static const char main_text[] =
		"[Discovery Controller Defaults]\n"
		"keep-alive-tmo = 30\n"
		"ctrl-loss-tmo = 600\n"
		"reconnect-delay = 10\n"
		"tos = 1\n"
		"[I/O Controller Defaults]\n"
		"keep-alive-tmo = 5\n"
		"ctrl-loss-tmo = 600\n"
		"reconnect-delay = 10\n"
		"tos = 1\n"
		"[Host]\n"
		"hostnqn = nqn.2014-08.org.nvmexpress:main-host\n"
		"[Subsystem]\n"
		"nqn = nqn.2014-08.org.nvmexpress:main-vol\n"
		"controller = transport=tcp;traddr=192.0.2.1;trsvcid=4420\n";
	static const char prod_text[] =
		"[Discovery Controller Defaults]\n"
		"tos = 7\n"
		"[I/O Controller Defaults]\n"
		"tos = 7\n"
		"[Host]\n"
		"hostnqn = nqn.2014-08.org.nvmexpress:prod-host\n"
		"hostid = 46ba5037-7ce5-41fa-9452-48477bf00080\n"
		"dhchap-secret = DHHC-1:00:abc\n"
		"[Discovery Controller]\n"
		"controller = transport=tcp;traddr=10.0.0.5;trsvcid=8009\n"
		"[Subsystem]\n"
		"nqn = nqn.2014-08.org.nvmexpress:prod-vol\n"
		"ctrl-loss-tmo = 1800\n"
		"reconnect-delay =\n"
		"controller = transport=tcp;traddr=10.0.0.9;keep-alive-tmo=99\n"
		"controller = transport=tcp;traddr=10.0.0.10\n";
	char dir[] = "/tmp/nvme-conf-XXXXXX";
	char main_path[512], dropin_dir[512];
	struct libnvmf_config *conf;
	struct libnvmf_config_conn *mv, *dc, *p1, *p2;
	bool pass = true;
	int err;

	printf("test_resolve_cascade:\n");
	assert(mkdtemp(dir));
	snprintf(main_path, sizeof(main_path), "%s/nvme-fabrics.conf", dir);
	snprintf(dropin_dir, sizeof(dropin_dir), "%s/nvme-fabrics.conf.d",
		 dir);
	assert(mkdir(dropin_dir, 0755) == 0);
	write_file(dir, "nvme-fabrics.conf", main_text);
	write_file(dropin_dir, "10-prod.conf", prod_text);

	err = libnvmf_config_load(ctx, main_path, &conf);
	if (!conf) {
		printf(" - load failed: %d [FAIL]\n", err);
		rm_tree(dir);
		return false;
	}

	/* Order: main file first, then the drop-in; paths in file order. */
	mv = list_top(&conf->conns, struct libnvmf_config_conn, entry);
	dc = mv ? list_next(&conf->conns, mv, entry) : NULL;
	p1 = dc ? list_next(&conf->conns, dc, entry) : NULL;
	p2 = p1 ? list_next(&conf->conns, p1, entry) : NULL;
	if (!p2 || list_next(&conf->conns, p2, entry)) {
		printf(" - expected exactly 4 connections [FAIL]\n");
		libnvmf_config_free(conf);
		rm_tree(dir);
		return false;
	}
	printf(" - 4 connections, main first then sorted drop-ins [PASS]\n");

	/* Main-file subsystem: main scope only. */
	if (mv->is_dc ||
	    strcmp(mv->subsysnqn, "nqn.2014-08.org.nvmexpress:main-vol") ||
	    strcmp(mv->hostnqn, "nqn.2014-08.org.nvmexpress:main-host") ||
	    mv->hostid ||
	    strcmp(libnvmf_params_get(mv->params, "ctrl-loss-tmo"), "600") ||
	    strcmp(libnvmf_params_get(mv->params, "keep-alive-tmo"), "5") ||
	    strcmp(libnvmf_params_get(mv->params, "tos"), "1")) {
		printf(" - main-file subsystem [FAIL]\n");
		pass = false;
	} else {
		printf(" - main persona + IOC defaults [PASS]\n");
	}

	/* Drop-in DC: default NQN, prod persona, overlaid tos, DC kato. */
	if (!dc->is_dc ||
	    strcmp(dc->subsysnqn, NVME_DISC_SUBSYS_NAME) ||
	    strcmp(dc->hostnqn, "nqn.2014-08.org.nvmexpress:prod-host") ||
	    strcmp(dc->hostid,
		   "46ba5037-7ce5-41fa-9452-48477bf00080") ||
	    strcmp(libnvmf_params_get(dc->params, "keep-alive-tmo"), "30") ||
	    strcmp(libnvmf_params_get(dc->params, "tos"), "7") ||
	    strcmp(libnvmf_params_get(dc->params, "dhchap-secret"),
		   "DHHC-1:00:abc")) {
		printf(" - drop-in DC [FAIL]\n");
		pass = false;
	} else {
		printf(" - DC: well-known NQN, persona, defaults [PASS]\n");
	}

	/* DLP blocks: what a controller discovered via this DC would get. */
	if (!dc->dlp_ioc_params ||
	    strcmp(libnvmf_params_get(dc->dlp_ioc_params, "keep-alive-tmo"),
		   "5") ||
	    strcmp(libnvmf_params_get(dc->dlp_ioc_params, "tos"), "7") ||
	    strcmp(libnvmf_params_get(dc->dlp_dc_params, "keep-alive-tmo"),
		   "30")) {
		printf(" - DC discovered-defaults blocks [FAIL]\n");
		pass = false;
	} else {
		printf(" - discovered-controller defaults ride the DC [PASS]\n");
	}

	/* Paths: endpoint > defaults; per-path override; explicit reset. */
	if (strcmp(libnvmf_params_get(p1->params, "ctrl-loss-tmo"), "1800") ||
	    strcmp(libnvmf_params_get(p1->params, "keep-alive-tmo"), "99") ||
	    strcmp(libnvmf_params_get(p2->params, "keep-alive-tmo"), "5") ||
	    strcmp(libnvmf_params_get(p1->params, "reconnect-delay"), "") ||
	    strcmp(p1->subsysnqn, "nqn.2014-08.org.nvmexpress:prod-vol")) {
		printf(" - path cascade [FAIL]\n");
		pass = false;
	} else {
		printf(" - endpoint override, per-path override, reset [PASS]\n");
	}

	/* Top-level scope blocks: main file only, no drop-in leakage. */
	if (strcmp(libnvmf_params_get(conf->top_ioc_params, "tos"), "1") ||
	    strcmp(libnvmf_params_get(conf->top_dc_params, "keep-alive-tmo"),
		   "30")) {
		printf(" - top-level discovered defaults [FAIL]\n");
		pass = false;
	} else {
		printf(" - top-level scope stays main-file-only [PASS]\n");
	}

	/* Provenance. */
	if (!strstr(dc->source, "10-prod.conf") ||
	    !strstr(mv->source, "nvme-fabrics.conf")) {
		printf(" - provenance [FAIL]\n");
		pass = false;
	} else {
		printf(" - per-connection source file recorded [PASS]\n");
	}

	libnvmf_config_free(conf);
	rm_tree(dir);
	return pass;
}

static bool resolve_expect_fail(struct libnvme_global_ctx *ctx,
				const char *name, const char *dropin1,
				const char *dropin2)
{
	char dir[] = "/tmp/nvme-conf-XXXXXX";
	char main_path[512], dropin_dir[512];
	struct libnvmf_config *conf;
	int err = 0;

	assert(mkdtemp(dir));
	snprintf(main_path, sizeof(main_path), "%s/nvme-fabrics.conf", dir);
	snprintf(dropin_dir, sizeof(dropin_dir), "%s/nvme-fabrics.conf.d",
		 dir);
	assert(mkdir(dropin_dir, 0755) == 0);
	write_file(dropin_dir, "10-a.conf", dropin1);
	if (dropin2)
		write_file(dropin_dir, "20-b.conf", dropin2);

	err = libnvmf_config_load(ctx, main_path, &conf);
	libnvmf_config_free(conf);
	rm_tree(dir);
	if (conf || err != -EINVAL) {
		printf(" - %s: not rejected (err=%d) [FAIL]\n", name, err);
		return false;
	}

	return true;
}

static bool test_resolve_personas(struct libnvme_global_ctx *ctx)
{
	bool pass = true;
	char dir[] = "/tmp/nvme-conf-XXXXXX";
	char main_path[512], dropin_dir[512];
	struct libnvmf_config *conf;
	struct libnvmf_config_conn *conn;
	int err;

	printf("test_resolve_personas:\n");

	pass &= resolve_expect_fail(ctx, "drop-in [Host] without hostnqn",
		"[Host]\nhostid = 46ba5037-7ce5-41fa-9452-48477bf00080\n",
		NULL);
	pass &= resolve_expect_fail(ctx, "same hostid, two personas",
		"[Host]\nhostnqn = nqn.2014-08.org.nvmexpress:a\nhostid = 46ba5037-7ce5-41fa-9452-48477bf00080\n",
		"[Host]\nhostnqn = nqn.2014-08.org.nvmexpress:b\nhostid = 46ba5037-7ce5-41fa-9452-48477bf00080\n");
	pass &= resolve_expect_fail(ctx, "one hostnqn, two explicit hostids",
		"[Host]\nhostnqn = nqn.2014-08.org.nvmexpress:a\nhostid = 46ba5037-7ce5-41fa-9452-48477bf00080\n",
		"[Host]\nhostnqn = nqn.2014-08.org.nvmexpress:a\nhostid = ffffffff-7ce5-41fa-9452-48477bf00080\n");
	pass &= resolve_expect_fail(ctx, "one hostnqn, only one file sets a hostid",
		"[Host]\nhostnqn = nqn.2014-08.org.nvmexpress:a\nhostid = 46ba5037-7ce5-41fa-9452-48477bf00080\n",
		"[Host]\nhostnqn = nqn.2014-08.org.nvmexpress:a\n");
	if (pass)
		printf(" - relational Tier 1 rules rejected [PASS]\n");

	/* A hostnqn reused between the top-level file and a drop-in. */
	assert(mkdtemp(dir));
	snprintf(main_path, sizeof(main_path), "%s/nvme-fabrics.conf", dir);
	snprintf(dropin_dir, sizeof(dropin_dir), "%s/nvme-fabrics.conf.d",
		 dir);
	assert(mkdir(dropin_dir, 0755) == 0);
	write_file(dir, "nvme-fabrics.conf", "[Host]\nhostnqn = nqn.2014-08.org.nvmexpress:a\n");
	write_file(dropin_dir, "10-a.conf", "[Host]\nhostnqn = nqn.2014-08.org.nvmexpress:a\n");
	err = libnvmf_config_load(ctx, main_path, &conf);
	if (conf || err != -EINVAL) {
		printf(" - drop-in reuses top-level hostnqn err=%d [FAIL]\n",
		       err);
		pass = false;
	} else {
		printf(" - drop-in reusing the top-level hostnqn rejected [PASS]\n");
	}
	libnvmf_config_free(conf);
	rm_tree(dir);

	/* A drop-in with no [Host] is the default persona: legal. */
	strcpy(dir, "/tmp/nvme-conf-XXXXXX");
	assert(mkdtemp(dir));
	snprintf(main_path, sizeof(main_path), "%s/nvme-fabrics.conf", dir);
	snprintf(dropin_dir, sizeof(dropin_dir), "%s/nvme-fabrics.conf.d",
		 dir);
	assert(mkdir(dropin_dir, 0755) == 0);
	write_file(dropin_dir, "10-a.conf",
		   "[Subsystem]\nnqn = nqn.2014-08.org.nvmexpress:x\n"
		   "controller = transport=tcp;traddr=192.0.2.9\n");
	err = libnvmf_config_load(ctx, main_path, &conf);
	conn = conf ?
	       list_top(&conf->conns, struct libnvmf_config_conn, entry) :
	       NULL;
	if (!conf || !conn || list_next(&conf->conns, conn, entry) ||
	    conn->hostnqn) {
		printf(" - default-persona drop-in err=%d [FAIL]\n", err);
		pass = false;
	} else {
		printf(" - drop-in without [Host] = default persona [PASS]\n");
	}
	libnvmf_config_free(conf);
	rm_tree(dir);

	return pass;
}

int main(void)
{
	struct libnvme_global_ctx *ctx;
	bool pass = true;

	ctx = libnvme_create_global_ctx();
	assert(ctx);

	pass &= test_params_tristate();
	pass &= test_params_merge();
	pass &= test_key_table();
	pass &= test_value_check();
	pass &= test_parse_model(ctx);
	pass &= test_parse_hostname(ctx);
	pass &= test_parse_errors(ctx);
	pass &= test_parse_hygiene(ctx);
	pass &= test_resolve_empty(ctx);
	pass &= test_resolve_hostname(ctx);
	pass &= test_resolve_cascade(ctx);
	pass &= test_resolve_personas(ctx);

	libnvme_free_global_ctx(ctx);

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
