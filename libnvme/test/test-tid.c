// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 *
 * Unit tests for the libnvmf_tid API — libnvmf_tid_parse() (valid input,
 * rejected aliases, garbage tokens, duplicate keys, whitespace), plus equal(),
 * dup(), get_canonical(), get_hash(), and setter cache invalidation.
 *
 * Note: garbage-input tests intentionally trigger error messages on stderr;
 * that output is expected and does not indicate a test failure.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nvme/lib.h>
#include <nvme/tid.h>

static int test_rc;

#define PASS "[PASS]\n"
#define FAIL "[FAIL]\n"

#define CHECK(cond, fmt, ...)						\
	do {								\
		if (cond) {						\
			printf("  " fmt " " PASS, ##__VA_ARGS__);	\
		} else {						\
			printf("  " fmt " " FAIL, ##__VA_ARGS__);	\
			test_rc = EXIT_FAILURE;				\
		}							\
	} while (0)

/* NULL-safe string equality helper */
static bool streq(const char *a, const char *b)
{
	if (a == b)
		return true;
	if (!a || !b)
		return false;
	return !strcmp(a, b);
}

/* -------------------------------------------------------------------------
 * NULL input
 * -------------------------------------------------------------------------
 */
static bool test_tid_parse_null(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvmf_tid *t;
	bool pass;

	ctx = libnvme_create_global_ctx();

	printf("\ntest_tid_parse_null:\n");
	t = libnvmf_tid_parse(ctx, NULL);
	pass = (t == NULL);
	CHECK(pass, "NULL input → NULL return");

	libnvme_free_global_ctx(ctx);

	return pass;
}

/* -------------------------------------------------------------------------
 * Valid input — all eight fields
 * -------------------------------------------------------------------------
 */
static bool test_tid_parse_valid(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvmf_tid *t;
	bool pass = true, p;

	ctx = libnvme_create_global_ctx();

	printf("\ntest_tid_parse_valid:\n");

	t = libnvmf_tid_parse(ctx,
			      "transport=tcp;traddr=192.168.1.1;trsvcid=4420;"
			      "nqn=nqn.test;host-traddr=10.0.0.1;"
			      "host-iface=eth0;hostnqn=nqn.host;"
			      "hostid=12345678-1234-1234-1234-123456789abc");
	p = (t != NULL);
	CHECK(p, "non-NULL result");
	pass &= p;
	if (!t) {
		libnvme_free_global_ctx(ctx);
		return false;
	}

	p = streq(libnvmf_tid_get_transport(t), "tcp");
	CHECK(p, "transport=tcp");
	pass &= p;

	p = streq(libnvmf_tid_get_traddr(t), "192.168.1.1");
	CHECK(p, "traddr=192.168.1.1");
	pass &= p;

	p = streq(libnvmf_tid_get_trsvcid(t), "4420");
	CHECK(p, "trsvcid=4420");
	pass &= p;

	p = streq(libnvmf_tid_get_subsysnqn(t), "nqn.test");
	CHECK(p, "nqn=nqn.test");
	pass &= p;

	p = streq(libnvmf_tid_get_host_traddr(t), "10.0.0.1");
	CHECK(p, "host-traddr=10.0.0.1");
	pass &= p;

	p = streq(libnvmf_tid_get_host_iface(t), "eth0");
	CHECK(p, "host-iface=eth0");
	pass &= p;

	p = streq(libnvmf_tid_get_hostnqn(t), "nqn.host");
	CHECK(p, "hostnqn=nqn.host");
	pass &= p;

	p = streq(libnvmf_tid_get_hostid(t),
		  "12345678-1234-1234-1234-123456789abc");
	CHECK(p, "hostid set");
	pass &= p;

	libnvmf_tid_free(t);
	libnvme_free_global_ctx(ctx);

	return pass;
}

/* -------------------------------------------------------------------------
 * The string keys are the "nvme connect" option names (nqn, host-traddr,
 * host-iface); the C-identifier spellings of the struct fields (subsysnqn,
 * host_traddr, host_iface) and any other variant (host_nqn) are not
 * recognized and must be ignored.
 * -------------------------------------------------------------------------
 */
static bool test_tid_parse_rejected_aliases(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvmf_tid *t;
	bool pass = true, p;

	ctx = libnvme_create_global_ctx();

	printf("\ntest_tid_parse_rejected_aliases:\n");
	printf("  (error messages on stderr below are expected)\n");

	t = libnvmf_tid_parse(ctx, "transport=rdma;subsysnqn=nqn.alias;"
			      "host_traddr=5.6.7.8;host_iface=ib0;"
			      "host_nqn=nqn.hostalias");
	p = (t != NULL);
	CHECK(p, "non-NULL result");
	pass &= p;
	if (!t) {
		libnvme_free_global_ctx(ctx);
		return false;
	}

	p = libnvmf_tid_get_subsysnqn(t) == NULL;
	CHECK(p, "subsysnqn= alias ignored (subsysnqn stays NULL)");
	pass &= p;

	p = libnvmf_tid_get_host_traddr(t) == NULL;
	CHECK(p, "host_traddr= alias ignored");
	pass &= p;

	p = libnvmf_tid_get_host_iface(t) == NULL;
	CHECK(p, "host_iface= alias ignored");
	pass &= p;

	p = libnvmf_tid_get_hostnqn(t) == NULL;
	CHECK(p, "host_nqn= alias ignored");
	pass &= p;

	libnvmf_tid_free(t);
	libnvme_free_global_ctx(ctx);

	return pass;
}

/* -------------------------------------------------------------------------
 * Garbage tokens — bare key (no '='), empty value (key=), unknown key.
 * These trigger error messages on stderr; the fields must remain NULL.
 * -------------------------------------------------------------------------
 */
static bool test_tid_parse_garbage(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvmf_tid *t;
	bool pass = true, p;

	ctx = libnvme_create_global_ctx();

	printf("\ntest_tid_parse_garbage:\n");
	printf("  (error messages on stderr below are expected)\n");

	/* Bare key — no '=' at all */
	t = libnvmf_tid_parse(ctx, "barekey;transport=tcp");
	p = t && streq(libnvmf_tid_get_transport(t), "tcp") &&
	    libnvmf_tid_get_traddr(t) == NULL;
	CHECK(p, "bare key ignored; valid field still parsed");
	pass &= p;
	libnvmf_tid_free(t);

	/* Empty value — key= with nothing after the '=' */
	t = libnvmf_tid_parse(ctx, "transport=;traddr=10.0.0.1");
	p = t && libnvmf_tid_get_transport(t) == NULL &&
	    streq(libnvmf_tid_get_traddr(t), "10.0.0.1");
	CHECK(p, "empty value ignored; field stays NULL");
	pass &= p;
	libnvmf_tid_free(t);

	/* Empty value after whitespace trimming — "key=   " */
	t = libnvmf_tid_parse(ctx, "transport=   ;traddr=10.0.0.2");
	p = t && libnvmf_tid_get_transport(t) == NULL &&
	    streq(libnvmf_tid_get_traddr(t), "10.0.0.2");
	CHECK(p, "whitespace-only value ignored; field stays NULL");
	pass &= p;
	libnvmf_tid_free(t);

	/* Unknown key */
	t = libnvmf_tid_parse(ctx, "nosuchkey=foo;transport=tcp");
	p = t && streq(libnvmf_tid_get_transport(t), "tcp");
	CHECK(p, "unknown key ignored; valid field still parsed");
	pass &= p;
	libnvmf_tid_free(t);

	/* Double separator ";;" — the empty token between is skipped */
	t = libnvmf_tid_parse(ctx, "transport=tcp;;traddr=10.0.0.3");
	p = t && streq(libnvmf_tid_get_transport(t), "tcp") &&
	    streq(libnvmf_tid_get_traddr(t), "10.0.0.3");
	CHECK(p, "\";;\" empty token skipped; both fields parsed");
	pass &= p;
	libnvmf_tid_free(t);

	/* All garbage — should return an empty (non-NULL) TID */
	t = libnvmf_tid_parse(ctx, "garbage;=nokey;unknown=val");
	p = t &&
	    libnvmf_tid_get_transport(t) == NULL &&
	    libnvmf_tid_get_traddr(t) == NULL &&
	    libnvmf_tid_get_subsysnqn(t) == NULL;
	CHECK(p, "all-garbage string → empty TID (non-NULL)");
	pass &= p;
	libnvmf_tid_free(t);
	libnvme_free_global_ctx(ctx);

	return pass;
}

/* -------------------------------------------------------------------------
 * Duplicate key — last value wins
 * -------------------------------------------------------------------------
 */
static bool test_tid_parse_duplicate_key(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvmf_tid *t;
	bool pass;

	ctx = libnvme_create_global_ctx();

	printf("\ntest_tid_parse_duplicate_key:\n");

	t = libnvmf_tid_parse(ctx, "transport=tcp;transport=rdma");
	pass = t && streq(libnvmf_tid_get_transport(t), "rdma");
	CHECK(pass, "duplicate key → last value wins (\"rdma\")");
	libnvmf_tid_free(t);
	libnvme_free_global_ctx(ctx);

	return pass;
}

/* -------------------------------------------------------------------------
 * Whitespace trimming around keys and values
 * -------------------------------------------------------------------------
 */
static bool test_tid_parse_whitespace(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvmf_tid *t;
	bool pass = true, p;

	ctx = libnvme_create_global_ctx();

	printf("\ntest_tid_parse_whitespace:\n");

	t = libnvmf_tid_parse(ctx, " transport = tcp ; traddr = 1.2.3.4 ");
	p = t && streq(libnvmf_tid_get_transport(t), "tcp") &&
	    streq(libnvmf_tid_get_traddr(t), "1.2.3.4");
	CHECK(p, "whitespace around key and value is trimmed");
	pass &= p;
	libnvmf_tid_free(t);
	libnvme_free_global_ctx(ctx);

	return pass;
}

/* -------------------------------------------------------------------------
 * libnvmf_tid_equal() — including NULL handling (regression for the NULL crash)
 * -------------------------------------------------------------------------
 */
static bool test_tid_equal(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvmf_tid *a, *b;
	bool pass = true, p;

	ctx = libnvme_create_global_ctx();

	printf("\ntest_tid_equal:\n");

	p = libnvmf_tid_equal(NULL, NULL);
	CHECK(p, "equal(NULL, NULL) → true");
	pass &= p;

	a = libnvmf_tid_parse(ctx,
			      "transport=tcp;traddr=1.2.3.4;trsvcid=4420");

	p = !libnvmf_tid_equal(a, NULL) && !libnvmf_tid_equal(NULL, a);
	CHECK(p, "equal(t, NULL) and equal(NULL, t) → false (no crash)");
	pass &= p;

	p = libnvmf_tid_equal(a, a);
	CHECK(p, "equal(t, t) → true");
	pass &= p;

	b = libnvmf_tid_parse(ctx,
			      "transport=tcp;traddr=1.2.3.4;trsvcid=4420");
	p = libnvmf_tid_equal(a, b);
	CHECK(p, "identical TIDs → equal");
	pass &= p;

	libnvmf_tid_set_traddr(b, "5.6.7.8");
	p = !libnvmf_tid_equal(a, b);
	CHECK(p, "differing field → not equal");
	pass &= p;

	libnvmf_tid_free(a);
	libnvmf_tid_free(b);
	libnvme_free_global_ctx(ctx);
	return pass;
}

/* -------------------------------------------------------------------------
 * libnvmf_tid_dup()
 * -------------------------------------------------------------------------
 */
static bool test_tid_dup(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvmf_tid *t, *d;
	bool pass = true, p;

	ctx = libnvme_create_global_ctx();

	printf("\ntest_tid_dup:\n");

	p = (libnvmf_tid_dup(NULL) == NULL);
	CHECK(p, "dup(NULL) → NULL");
	pass &= p;

	t = libnvmf_tid_parse(ctx,
			      "transport=tcp;traddr=1.2.3.4;nqn=nqn.test");
	d = libnvmf_tid_dup(t);
	p = d && libnvmf_tid_equal(t, d) && d != t;
	CHECK(p, "dup is a distinct but equal copy");
	pass &= p;

	libnvmf_tid_free(t);
	libnvmf_tid_free(d);
	libnvme_free_global_ctx(ctx);
	return pass;
}

/* -------------------------------------------------------------------------
 * libnvmf_tid_get_canonical() — fixed field order, NULL skipping, caching
 * -------------------------------------------------------------------------
 */
static bool test_tid_canonical(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvmf_tid *t;
	const char *c1, *c2;
	bool pass = true, p;

	ctx = libnvme_create_global_ctx();

	printf("\ntest_tid_canonical:\n");

	p = (libnvmf_tid_get_canonical(NULL) == NULL);
	CHECK(p, "canonical(NULL) → NULL");
	pass &= p;

	/* Input order differs from canonical order;
	 * unset fields are skipped.
	 */
	t = libnvmf_tid_parse(ctx,
			      "traddr=1.2.3.4;transport=tcp;trsvcid=4420");
	c1 = libnvmf_tid_get_canonical(t);
	p = streq(c1, "transport=tcp;traddr=1.2.3.4;trsvcid=4420");
	CHECK(p, "canonical uses fixed field order, skips NULL fields");
	pass &= p;

	c2 = libnvmf_tid_get_canonical(t);
	p = (c1 == c2);
	CHECK(p, "canonical is cached (same pointer on 2nd call)");
	pass &= p;

	libnvmf_tid_free(t);
	libnvme_free_global_ctx(ctx);
	return pass;
}

/* -------------------------------------------------------------------------
 * libnvmf_tid_get_hash() — format, stability, caching
 * -------------------------------------------------------------------------
 */
static bool test_tid_hash(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvmf_tid *a, *b, *c;
	const char *h1, *h2;
	bool pass = true, p;

	ctx = libnvme_create_global_ctx();

	printf("\ntest_tid_hash:\n");

	p = (libnvmf_tid_get_hash(NULL) == NULL);
	CHECK(p, "hash(NULL) → NULL");
	pass &= p;

	a = libnvmf_tid_parse(ctx,
			      "transport=tcp;traddr=1.2.3.4;trsvcid=4420");
	h1 = libnvmf_tid_get_hash(a);
	p = h1 && strlen(h1) == 12 && strspn(h1, "0123456789abcdef") == 12;
	CHECK(p, "hash is 12 lowercase hex chars");
	pass &= p;

	h2 = libnvmf_tid_get_hash(a);
	p = (h1 == h2);
	CHECK(p, "hash is cached (same pointer on 2nd call)");
	pass &= p;

	b = libnvmf_tid_parse(ctx,
			      "transport=tcp;traddr=1.2.3.4;trsvcid=4420");
	p = streq(libnvmf_tid_get_hash(a), libnvmf_tid_get_hash(b));
	CHECK(p, "equal TIDs → equal hash");
	pass &= p;

	c = libnvmf_tid_parse(ctx,
			      "transport=tcp;traddr=9.9.9.9;trsvcid=4420");
	p = !streq(libnvmf_tid_get_hash(a), libnvmf_tid_get_hash(c));
	CHECK(p, "different TIDs → different hash");
	pass &= p;

	libnvmf_tid_free(a);
	libnvmf_tid_free(b);
	libnvmf_tid_free(c);
	libnvme_free_global_ctx(ctx);
	return pass;
}

/* -------------------------------------------------------------------------
 * Setters invalidate the canonical/hash caches
 * -------------------------------------------------------------------------
 */
static bool test_tid_setter_invalidates_cache(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvmf_tid *t;
	char before[64], h_before[32];
	const char *after, *h_after;
	bool pass = true, p;

	ctx = libnvme_create_global_ctx();

	printf("\ntest_tid_setter_invalidates_cache:\n");

	t = libnvmf_tid_parse(ctx, "transport=tcp;traddr=1.2.3.4");

	/* Prime the caches, mutate, then confirm they were rebuilt. */
	snprintf(before, sizeof(before), "%s", libnvmf_tid_get_canonical(t));
	snprintf(h_before, sizeof(h_before), "%s", libnvmf_tid_get_hash(t));

	libnvmf_tid_set_traddr(t, "5.6.7.8");

	after = libnvmf_tid_get_canonical(t);
	p = after && !streq(before, after) && strstr(after, "traddr=5.6.7.8");
	CHECK(p, "setter invalidates canonical cache");
	pass &= p;

	h_after = libnvmf_tid_get_hash(t);
	p = h_after && !streq(h_before, h_after);
	CHECK(p, "setter invalidates hash cache");
	pass &= p;

	libnvmf_tid_free(t);
	libnvme_free_global_ctx(ctx);
	return pass;
}

/* -------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------
 */
/* -------------------------------------------------------------------------
 * libnvmf_tid_parse_strict() — a malformed token fails the whole parse
 * -------------------------------------------------------------------------
 */
static bool test_tid_parse_strict(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvmf_tid *t;
	bool pass = true, p;

	ctx = libnvme_create_global_ctx();

	printf("\ntest_tid_parse_strict:\n");
	printf("  (error messages on stderr below are expected)\n");

	/* Well-formed input still parses. */
	t = libnvmf_tid_parse_strict(ctx, "transport=tcp;traddr=1.2.3.4");
	p = t && streq(libnvmf_tid_get_transport(t), "tcp");
	CHECK(p, "valid input → non-NULL");
	pass &= p;
	libnvmf_tid_free(t);

	/* An unknown key fails the whole parse. */
	t = libnvmf_tid_parse_strict(ctx, "transport=tcp;bogus=x");
	p = (t == NULL);
	CHECK(p, "unknown key → NULL");
	pass &= p;

	/* The C-identifier spelling (subsysnqn) is not a valid key → NULL. */
	t = libnvmf_tid_parse_strict(ctx, "subsysnqn=nqn.a");
	p = (t == NULL);
	CHECK(p, "non-option key 'subsysnqn' → NULL");
	pass &= p;

	/* A non-empty bare token fails. */
	t = libnvmf_tid_parse_strict(ctx, "transport=tcp;garbage");
	p = (t == NULL);
	CHECK(p, "bare token → NULL");
	pass &= p;

	/* Empty tokens (";;") remain benign even under strict parsing. */
	t = libnvmf_tid_parse_strict(ctx, "transport=tcp;;traddr=1.2.3.4");
	p = t && streq(libnvmf_tid_get_traddr(t), "1.2.3.4");
	CHECK(p, "\";;\" still benign under strict");
	pass &= p;
	libnvmf_tid_free(t);

	libnvme_free_global_ctx(ctx);

	return pass;
}

/* -------------------------------------------------------------------------
 * libnvmf_tid_is_empty()
 * -------------------------------------------------------------------------
 */
static bool test_tid_is_empty(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvmf_tid *t;
	bool pass = true, p;

	ctx = libnvme_create_global_ctx();

	printf("\ntest_tid_is_empty:\n");

	p = libnvmf_tid_is_empty(NULL);
	CHECK(p, "is_empty(NULL) → true");
	pass &= p;

	t = libnvmf_tid_parse(ctx, "");
	p = libnvmf_tid_is_empty(t);
	CHECK(p, "TID with no fields → true");
	pass &= p;
	libnvmf_tid_free(t);

	t = libnvmf_tid_parse(ctx, "transport=tcp");
	p = !libnvmf_tid_is_empty(t);
	CHECK(p, "TID with a field → false");
	pass &= p;
	libnvmf_tid_free(t);

	libnvme_free_global_ctx(ctx);

	return pass;
}

int main(int argc, char *argv[])
{
	test_rc = EXIT_SUCCESS;

	test_tid_parse_null();
	test_tid_parse_valid();
	test_tid_parse_rejected_aliases();
	test_tid_parse_strict();
	test_tid_parse_garbage();
	test_tid_parse_duplicate_key();
	test_tid_parse_whitespace();
	test_tid_equal();
	test_tid_is_empty();
	test_tid_dup();
	test_tid_canonical();
	test_tid_hash();
	test_tid_setter_invalidates_cache();

	if (test_rc == EXIT_SUCCESS)
		printf("\nAll tests passed.\n");
	else
		printf("\nSOME TESTS FAILED.\n");

	return test_rc;
}
