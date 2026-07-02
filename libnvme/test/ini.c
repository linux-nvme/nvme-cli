// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <martin.belanger@dell.com>
 *
 * Unit tests for the internal INI reader (ini.c): tokenizing, section
 * tracking, the empty-value / absent-key distinction, fail-safe junk
 * reporting, exact line numbers, and the parse-abort contract.
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nvme/lib.h>

#include "nvme/ini.h"

#define MAX_EVENTS 32

struct ev {
	enum libnvmf_ini_event event;
	char section[128];
	bool section_null;
	char key[256];
	char value[256];
	bool value_null;
	unsigned int line;
};

static struct ev got[MAX_EVENTS];
static int ngot;

static int record(enum libnvmf_ini_event event, const char *section,
		  const char *key, const char *value, unsigned int line,
		  void *user_data)
{
	struct ev *e = &got[ngot++];

	assert(ngot <= MAX_EVENTS);
	e->event = event;
	e->section_null = !section;
	if (section)
		snprintf(e->section, sizeof(e->section), "%s", section);
	snprintf(e->key, sizeof(e->key), "%s", key);
	e->value_null = !value;
	if (value)
		snprintf(e->value, sizeof(e->value), "%s", value);
	e->line = line;

	return 0;
}

struct expect {
	enum libnvmf_ini_event event;
	const char *section; /* NULL = expect no section */
	const char *key;
	const char *value;   /* NULL for SECTION / JUNK events */
	unsigned int line;
};

static bool check(struct libnvme_global_ctx *ctx, const char *name,
		  const char *text, const struct expect *want, int nwant)
{
	bool pass = true;
	int ret, i;

	ngot = 0;
	ret = libnvmf_ini_parse_buf(ctx, text, record, NULL);
	if (ret) {
		printf(" - %s: parse ret=%d [FAIL]\n", name, ret);
		return false;
	}
	if (ngot != nwant) {
		printf(" - %s: %d events (want %d) [FAIL]\n", name, ngot,
		       nwant);
		return false;
	}
	for (i = 0; i < nwant; i++) {
		const struct expect *w = &want[i];
		struct ev *g = &got[i];

		if (g->event != w->event || g->line != w->line ||
		    g->section_null != !w->section ||
		    (w->section && strcmp(g->section, w->section)) ||
		    strcmp(g->key, w->key) ||
		    g->value_null != !w->value ||
		    (w->value && strcmp(g->value, w->value))) {
			printf(" - %s: event %d mismatch (ev=%d sect=%s key=%s val=%s line=%u) [FAIL]\n",
			       name, i, g->event,
			       g->section_null ? "(null)" : g->section,
			       g->key, g->value_null ? "(null)" : g->value,
			       g->line);
			pass = false;
		}
	}
	if (pass)
		printf(" - %s [PASS]\n", name);

	return pass;
}

static bool test_golden(struct libnvme_global_ctx *ctx)
{
	static const char text[] =
		"# top comment\n"
		"\n"
		"[Global]\n"
		"ctrl-loss-tmo = 600\n"
		"empty =\n"
		"  [ Host ]  \n"
		"hostnqn=nqn.x\n"
		"controller = transport=tcp;traddr=1.2.3.4;trsvcid=8009\n";
	static const struct expect want[] = {
		{ LIBNVMF_INI_SECTION, "Global", "Global", NULL, 3 },
		{ LIBNVMF_INI_KV, "Global", "ctrl-loss-tmo", "600", 4 },
		{ LIBNVMF_INI_KV, "Global", "empty", "", 5 },
		{ LIBNVMF_INI_SECTION, "Host", "Host", NULL, 6 },
		{ LIBNVMF_INI_KV, "Host", "hostnqn", "nqn.x", 7 },
		{ LIBNVMF_INI_KV, "Host", "controller",
		  "transport=tcp;traddr=1.2.3.4;trsvcid=8009", 8 },
	};

	printf("test_golden:\n");

	return check(ctx, "sections, keys, empty value, '=' in value",
		     text, want, 6);
}

static bool test_junk(struct libnvme_global_ctx *ctx)
{
	static const char text[] =
		"before = any section\n"
		"[exclusions]\n"
		"noequals\n"
		"= value\n"
		"[broken\n"
		"key = lost\n"
		"[]\n"
		"[ok] trailing\n"
		"[ok]\n"
		"k = v\n";
	static const struct expect want[] = {
		{ LIBNVMF_INI_KV, NULL, "before", "any section", 1 },
		{ LIBNVMF_INI_SECTION, "exclusions", "exclusions", NULL, 2 },
		{ LIBNVMF_INI_JUNK, "exclusions", "noequals", NULL, 3 },
		{ LIBNVMF_INI_JUNK, "exclusions", "= value", NULL, 4 },
		{ LIBNVMF_INI_JUNK, NULL, "[broken", NULL, 5 },
		{ LIBNVMF_INI_KV, NULL, "key", "lost", 6 },
		{ LIBNVMF_INI_JUNK, NULL, "[]", NULL, 7 },
		{ LIBNVMF_INI_JUNK, NULL, "[ok] trailing", NULL, 8 },
		{ LIBNVMF_INI_SECTION, "ok", "ok", NULL, 9 },
		{ LIBNVMF_INI_KV, "ok", "k", "v", 10 },
	};

	printf("test_junk:\n");

	return check(ctx, "junk reporting and fail-safe section reset",
		     text, want, 10);
}

static bool test_crlf(struct libnvme_global_ctx *ctx)
{
	static const struct expect want[] = {
		{ LIBNVMF_INI_SECTION, "s", "s", NULL, 1 },
		{ LIBNVMF_INI_KV, "s", "k", "v", 2 },
	};

	printf("test_crlf:\n");

	return check(ctx, "CRLF line endings", "[s]\r\nk = v\r\n", want, 2);
}

static int abort_second(enum libnvmf_ini_event event, const char *section,
			const char *key, const char *value, unsigned int line,
			void *user_data)
{
	int *count = user_data;

	(*count)++;
	if (*count == 2)
		return -EPROTO;

	return 0;
}

static bool test_abort(struct libnvme_global_ctx *ctx)
{
	int count = 0;
	int ret;

	printf("test_abort:\n");

	ret = libnvmf_ini_parse_buf(ctx, "[a]\nk = v\nnever = seen\n",
				    abort_second, &count);
	if (ret != -EPROTO || count != 2) {
		printf(" - callback abort ret=%d count=%d [FAIL]\n",
		       ret, count);
		return false;
	}
	printf(" - callback abort stops the parse [PASS]\n");

	return true;
}

static bool test_file(struct libnvme_global_ctx *ctx)
{
	static const struct expect want[] = {
		{ LIBNVMF_INI_SECTION, "f", "f", NULL, 2 },
		{ LIBNVMF_INI_KV, "f", "key", "val", 3 },
	};
	char path[] = "/tmp/nvme-ini-test-XXXXXX";
	bool pass = true;
	int fd, ret, i;

	printf("test_file:\n");

	fd = mkstemp(path);
	assert(fd >= 0);
	assert(write(fd, "# file\n[f]\nkey = val\n", 21) == 21);
	close(fd);

	ngot = 0;
	ret = libnvmf_ini_parse_file(ctx, path, record, NULL);
	unlink(path);
	if (ret || ngot != 2) {
		printf(" - parse_file ret=%d events=%d [FAIL]\n", ret, ngot);
		return false;
	}
	for (i = 0; i < 2; i++) {
		if (got[i].event != want[i].event || got[i].line != want[i].line ||
		    strcmp(got[i].key, want[i].key)) {
			printf(" - parse_file event %d mismatch [FAIL]\n", i);
			pass = false;
		}
	}
	if (pass)
		printf(" - parse_file round-trip [PASS]\n");

	ret = libnvmf_ini_parse_file(ctx, "/nonexistent/ini", record, NULL);
	if (ret != -ENOENT) {
		printf(" - missing file ret=%d (want -ENOENT) [FAIL]\n", ret);
		pass = false;
	} else {
		printf(" - missing file -> -ENOENT [PASS]\n");
	}

	/* A directory must be rejected, not silently read as empty. */
	ret = libnvmf_ini_parse_file(ctx, "/tmp", record, NULL);
	if (ret != -EISDIR) {
		printf(" - directory path ret=%d (want -EISDIR) [FAIL]\n", ret);
		pass = false;
	} else {
		printf(" - directory path -> -EISDIR [PASS]\n");
	}

	return pass;
}

static bool test_null_args(struct libnvme_global_ctx *ctx)
{
	bool pass = true;

	printf("test_null_args:\n");

	if (libnvmf_ini_parse_buf(NULL, "", record, NULL) != -EINVAL ||
	    libnvmf_ini_parse_buf(ctx, NULL, record, NULL) != -EINVAL ||
	    libnvmf_ini_parse_buf(ctx, "", NULL, NULL) != -EINVAL ||
	    libnvmf_ini_parse_file(ctx, NULL, record, NULL) != -EINVAL) {
		printf(" - NULL arguments rejected [FAIL]\n");
		pass = false;
	} else {
		printf(" - NULL arguments rejected [PASS]\n");
	}

	return pass;
}

int main(void)
{
	struct libnvme_global_ctx *ctx;
	bool pass = true;

	ctx = libnvme_create_global_ctx();
	assert(ctx);

	pass &= test_golden(ctx);
	pass &= test_junk(ctx);
	pass &= test_crlf(ctx);
	pass &= test_abort(ctx);
	pass &= test_file(ctx);
	pass &= test_null_args(ctx);

	libnvme_free_global_ctx(ctx);

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
