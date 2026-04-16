// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2024 Dell Inc.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 *
 * Unit tests for static helper functions in src/nvme/fabrics.c.
 *
 * Accessing static functions requires including the source file directly
 * because static functions are not exported from the shared library.
 * Defining 'static' to nothing makes them visible in this translation
 * unit.  The duplicate non-static symbols that fabrics.c also defines
 * (e.g. trtypes[], arg_str()) are harmless: GNU ld does not report
 * multiple-definition errors between a .o file and a shared library,
 * and at run time the main-executable definition takes precedence.
 */
#define static	/* expose static functions for unit testing */
#include "../src/nvme/fabrics.c"

#include <stdlib.h>

/* -------------------------------------------------------------------------
 * Test infrastructure
 * -------------------------------------------------------------------------
 */
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

/* -------------------------------------------------------------------------
 * strchomp — strip trailing spaces
 * -------------------------------------------------------------------------
 */
static bool test_strchomp(void)
{
	bool pass = true;
	char s[32];

	printf("\ntest_strchomp:\n");

	strncpy(s, "hello   ", sizeof(s));
	strchomp(s, 8);
	pass = !strcmp(s, "hello");
	CHECK(pass, "trailing spaces removed: \"%s\"", s);

	strncpy(s, "hello", sizeof(s));
	strchomp(s, 5);
	pass = !strcmp(s, "hello");
	CHECK(pass, "no trailing spaces (unchanged): \"%s\"", s);

	strncpy(s, "   ", sizeof(s));
	strchomp(s, 3);
	pass = (s[0] == '\0');
	CHECK(pass, "all spaces → empty string");

	strncpy(s, "x", sizeof(s));
	strchomp(s, 0);
	pass = (s[0] == 'x');
	CHECK(pass, "max=0 → no change");

	return pass;
}

/* -------------------------------------------------------------------------
 * hostid_from_hostnqn — extract UUID from a hostnqn string
 * -------------------------------------------------------------------------
 */
static bool test_hostid_from_hostnqn(void)
{
	const char *id;
	bool pass = true;

	printf("\ntest_hostid_from_hostnqn:\n");

	id = hostid_from_hostnqn(NULL);
	pass = (id == NULL);
	CHECK(pass, "NULL input → NULL");

	id = hostid_from_hostnqn("nqn.2014-08.org.nvmexpress:no-uuid-here");
	pass = (id == NULL);
	CHECK(pass, "no uuid: tag → NULL");

	id = hostid_from_hostnqn(
		"nqn.2014-08.org.nvmexpress:uuid:9ba1651a-ed36-11f0-9858-6c1ff71ba506");
	pass = (id && !strcmp(id, "9ba1651a-ed36-11f0-9858-6c1ff71ba506"));
	CHECK(pass, "valid NQN → UUID \"%s\"", id ? id : "(null)");

	id = hostid_from_hostnqn("prefix:uuid:abc-123");
	pass = (id && !strcmp(id, "abc-123"));
	CHECK(pass, "arbitrary prefix → \"abc-123\"");

	return pass;
}

/* -------------------------------------------------------------------------
 * __add_bool_argument — append a boolean flag to an argument string
 * -------------------------------------------------------------------------
 */
static bool test_add_bool_argument(void)
{
	char *argstr;
	bool pass = true;
	int ret;

	printf("\ntest___add_bool_argument:\n");

	argstr = strdup("start");

	ret = __add_bool_argument(&argstr, "flag", false);
	pass = (ret == 0 && !strcmp(argstr, "start"));
	CHECK(pass, "arg=false → no change: \"%s\"", argstr);

	ret = __add_bool_argument(&argstr, "flag", true);
	pass = (ret == 0 && !strcmp(argstr, "start,flag"));
	CHECK(pass, "arg=true → appended: \"%s\"", argstr);

	free(argstr);
	return pass;
}

/* -------------------------------------------------------------------------
 * __add_hex_argument — append a hex-formatted integer argument
 * -------------------------------------------------------------------------
 */
static bool test_add_hex_argument(void)
{
	char *argstr;
	bool pass = true, p;
	int ret;

	printf("\ntest___add_hex_argument:\n");

	argstr = strdup("s");

	ret = __add_hex_argument(&argstr, "v", -1, false);
	p = (ret == 0 && !strcmp(argstr, "s"));
	CHECK(p, "arg<0 → no change");
	pass &= p;

	ret = __add_hex_argument(&argstr, "v", 0, false);
	p = (ret == 0 && !strcmp(argstr, "s"));
	CHECK(p, "arg=0 allow_zero=false → no change");
	pass &= p;

	ret = __add_hex_argument(&argstr, "v", 0, true);
	p = (ret == 0 && !strcmp(argstr, "s,v=0x00000000"));
	CHECK(p, "arg=0 allow_zero=true → \"%s\"", argstr);
	pass &= p;

	free(argstr);
	argstr = strdup("s");
	ret = __add_hex_argument(&argstr, "key", 0x1234abcd, false);
	p = (ret == 0 && !strcmp(argstr, "s,key=0x1234abcd"));
	CHECK(p, "arg=0x1234abcd → \"%s\"", argstr);
	pass &= p;

	free(argstr);
	return pass;
}

/* -------------------------------------------------------------------------
 * __add_int_argument — append a decimal integer argument
 * -------------------------------------------------------------------------
 */
static bool test_add_int_argument(void)
{
	char *argstr;
	bool pass = true, p;
	int ret;

	printf("\ntest___add_int_argument:\n");

	argstr = strdup("s");

	ret = __add_int_argument(&argstr, "n", -1, false);
	p = (ret == 0 && !strcmp(argstr, "s"));
	CHECK(p, "arg<0 → no change");
	pass &= p;

	ret = __add_int_argument(&argstr, "n", 0, false);
	p = (ret == 0 && !strcmp(argstr, "s"));
	CHECK(p, "arg=0 allow_zero=false → no change");
	pass &= p;

	ret = __add_int_argument(&argstr, "n", 0, true);
	p = (ret == 0 && !strcmp(argstr, "s,n=0"));
	CHECK(p, "arg=0 allow_zero=true → \"%s\"", argstr);
	pass &= p;

	free(argstr);
	argstr = strdup("s");
	ret = __add_int_argument(&argstr, "n", 42, false);
	p = (ret == 0 && !strcmp(argstr, "s,n=42"));
	CHECK(p, "arg=42 → \"%s\"", argstr);
	pass &= p;

	free(argstr);
	return pass;
}

/* -------------------------------------------------------------------------
 * __add_int_or_minus_one_argument — like _int but also allows -1
 * -------------------------------------------------------------------------
 */
static bool test_add_int_or_minus_one_argument(void)
{
	char *argstr;
	bool pass = true, p;
	int ret;

	printf("\ntest___add_int_or_minus_one_argument:\n");

	argstr = strdup("s");

	ret = __add_int_or_minus_one_argument(&argstr, "n", -2);
	p = (ret == 0 && !strcmp(argstr, "s"));
	CHECK(p, "arg=-2 → no change");
	pass &= p;

	ret = __add_int_or_minus_one_argument(&argstr, "n", -1);
	p = (ret == 0 && !strcmp(argstr, "s,n=-1"));
	CHECK(p, "arg=-1 → \"%s\"", argstr);
	pass &= p;

	free(argstr);
	argstr = strdup("s");
	ret = __add_int_or_minus_one_argument(&argstr, "n", 0);
	p = (ret == 0 && !strcmp(argstr, "s,n=0"));
	CHECK(p, "arg=0 → \"%s\"", argstr);
	pass &= p;

	free(argstr);
	argstr = strdup("s");
	ret = __add_int_or_minus_one_argument(&argstr, "n", 7);
	p = (ret == 0 && !strcmp(argstr, "s,n=7"));
	CHECK(p, "arg=7 → \"%s\"", argstr);
	pass &= p;

	free(argstr);
	return pass;
}

/* -------------------------------------------------------------------------
 * __add_argument — append a string argument; skip NULL/"none"/empty
 * -------------------------------------------------------------------------
 */
static bool test_add_argument(void)
{
	char *argstr;
	bool pass = true, p;
	int ret;

	printf("\ntest___add_argument:\n");

	argstr = strdup("s");

	ret = __add_argument(&argstr, "a", NULL);
	p = (ret == 0 && !strcmp(argstr, "s"));
	CHECK(p, "NULL → no change");
	pass &= p;

	ret = __add_argument(&argstr, "a", "");
	p = (ret == 0 && !strcmp(argstr, "s"));
	CHECK(p, "empty string → no change");
	pass &= p;

	ret = __add_argument(&argstr, "a", "none");
	p = (ret == 0 && !strcmp(argstr, "s"));
	CHECK(p, "\"none\" → no change");
	pass &= p;

	ret = __add_argument(&argstr, "transport", "tcp");
	p = (ret == 0 && !strcmp(argstr, "s,transport=tcp"));
	CHECK(p, "\"tcp\" → \"%s\"", argstr);
	pass &= p;

	free(argstr);
	return pass;
}

/* -------------------------------------------------------------------------
 * inet4_pton — parse an IPv4 address string into a sockaddr_storage
 * -------------------------------------------------------------------------
 */
static bool test_inet4_pton(void)
{
	struct sockaddr_storage addr;
	struct sockaddr_in *a4 = (struct sockaddr_in *)&addr;
	bool pass = true, p;
	int ret;

	printf("\ntest_inet4_pton:\n");

	memset(&addr, 0, sizeof(addr));
	ret = inet4_pton("192.168.1.1", 4420, &addr);
	p = (ret == 0 &&
	     a4->sin_family == AF_INET &&
	     ntohs(a4->sin_port) == 4420);
	CHECK(p, "\"192.168.1.1\":4420 → ret=%d family=%d port=%d",
	     ret, a4->sin_family, ntohs(a4->sin_port));
	pass &= p;

	memset(&addr, 0, sizeof(addr));
	ret = inet4_pton("0.0.0.0", 0, &addr);
	p = (ret == 0 && a4->sin_family == AF_INET);
	CHECK(p, "\"0.0.0.0\":0 → ret=%d", ret);
	pass &= p;

	ret = inet4_pton("not-an-ip", 4420, &addr);
	p = (ret == -EINVAL);
	CHECK(p, "invalid string → -EINVAL (got %d)", ret);
	pass &= p;

	ret = inet4_pton("999.999.999.999", 4420, &addr);
	p = (ret == -EINVAL);
	CHECK(p, "out-of-range octets → -EINVAL (got %d)", ret);
	pass &= p;

	/* string longer than INET_ADDRSTRLEN */
	ret = inet4_pton(
		"1234567890.1234567890.1234567890.1234567890",
		0, &addr);
	p = (ret == -EINVAL);
	CHECK(p, "too-long string → -EINVAL (got %d)", ret);
	pass &= p;

	return pass;
}

/* -------------------------------------------------------------------------
 * inet_pton_with_scope — parse IPv4 or IPv6 (with optional %iface scope)
 * -------------------------------------------------------------------------
 */
static bool test_inet_pton_with_scope(struct libnvme_global_ctx *ctx)
{
	struct sockaddr_storage addr;
	bool pass = true, p;
	int ret;

	printf("\ntest_inet_pton_with_scope:\n");

	/* IPv4 via AF_INET */
	ret = inet_pton_with_scope(ctx, AF_INET, "10.0.0.1", "4420", &addr);
	p = (ret == 0);
	CHECK(p, "AF_INET \"10.0.0.1\":4420 → ret=%d", ret);
	pass &= p;

	/* IPv4 rejected when asking for AF_INET6 */
	ret = inet_pton_with_scope(ctx, AF_INET6, "10.0.0.1", "4420", &addr);
	p = (ret != 0);
	CHECK(p, "AF_INET6 rejects IPv4 → ret=%d (non-zero expected)", ret);
	pass &= p;

	/* Plain IPv6 via AF_INET6 */
	ret = inet_pton_with_scope(ctx, AF_INET6, "2001:db8::1", "4420", &addr);
	p = (ret == 0);
	CHECK(p, "AF_INET6 \"2001:db8::1\" → ret=%d", ret);
	pass &= p;

	/* Plain IPv6 via AF_UNSPEC */
	ret = inet_pton_with_scope(ctx, AF_UNSPEC, "fe80::1", "4420", &addr);
	p = (ret == 0);
	CHECK(p, "AF_UNSPEC \"fe80::1\" → ret=%d", ret);
	pass &= p;

	/* Scoped link-local via lo (always present) */
	ret = inet_pton_with_scope(ctx, AF_UNSPEC, "fe80::1%lo", "4420", &addr);
	p = (ret == 0);
	CHECK(p, "AF_UNSPEC \"fe80::1%%lo\" (scoped): ret=%d", ret);
	pass &= p;

	/* Scoped address for non-link-local: scope is ignored by inet6_pton */
	ret = inet_pton_with_scope(ctx, AF_UNSPEC, "2001:db8::1", NULL, &addr);
	p = (ret == 0);
	CHECK(p, "AF_UNSPEC \"2001:db8::1\" trsvcid=NULL → ret=%d", ret);
	pass &= p;

	/* Port overflow */
	ret = inet_pton_with_scope(ctx, AF_INET, "10.0.0.1", "99999", &addr);
	p = (ret == -ERANGE);
	CHECK(p, "port overflow (99999) → -ERANGE (got %d)", ret);
	pass &= p;

	return pass;
}

/* -------------------------------------------------------------------------
 * traddr_is_hostname — decide whether traddr is a hostname (not an IP)
 *
 * This is the key regression test: scoped IPv6 addresses like
 * "fe80::1%eth0" must NOT be classified as hostnames.  Before this was
 * caught, a proposed change replaced inet_pton_with_scope() with plain
 * inet_pton(), which fails on scoped addresses and mis-classifies them
 * as hostnames.
 * -------------------------------------------------------------------------
 */
static bool test_traddr_is_hostname(struct libnvme_global_ctx *ctx)
{
	bool pass = true, p;

	printf("\ntest_traddr_is_hostname:\n");

#define TRADDR_TEST(transport_, traddr_, expected, label)		\
	do {								\
		p = (traddr_is_hostname(ctx, transport_,		\
					traddr_) == (expected));	\
		CHECK(p, "%-38s → %s", label,				\
		      expected ? "hostname" : "IP");			\
		pass &= p;						\
	} while (0)

	/* Plain IPv4 */
	TRADDR_TEST("tcp",  "192.168.1.10", false, "IPv4 address (tcp)");
	TRADDR_TEST("rdma", "192.168.1.10", false, "IPv4 address (rdma)");

	/* Plain IPv6 */
	TRADDR_TEST("tcp", "fe80::1",     false, "IPv6 link-local (no scope)");
	TRADDR_TEST("tcp", "2001:db8::1", false, "IPv6 global unicast");
	TRADDR_TEST("tcp", "::1",         false, "IPv6 loopback");

	/*
	 * Scoped IPv6 - the regression case.
	 * Must be classified as an IP address, not a hostname.
	 * Plain inet_pton() would fail here and wrongly return true.
	 */
	TRADDR_TEST("tcp",  "fe80::1%lo", false, "scoped IPv6 (lo, exists)");
	TRADDR_TEST("rdma", "fe80::1%lo", false, "scoped IPv6 (lo, rdma)");

	/* Hostnames */
	TRADDR_TEST("tcp",  "storage.example.com", true, "FQDN hostname");
	TRADDR_TEST("tcp",  "nvme-target",         true, "short hostname");
	TRADDR_TEST("rdma", "storage.example.com",
		    true, "FQDN hostname (rdma)");

	/* "none" - reserved keyword, must not be treated as a hostname */
	TRADDR_TEST("tcp", "none", false, "literal \"none\"");

	/* Transports where the check is skipped entirely */
	TRADDR_TEST("pcie", "192.168.1.10",        false, "IPv4 on pcie");
	TRADDR_TEST("fc",   "fe80::1%lo",          false, "scoped IPv6 (fc)");
	TRADDR_TEST("loop", "storage.example.com", false, "hostname on loop");

	/* NULL traddr */
	TRADDR_TEST("tcp", NULL, false, "NULL traddr");

#undef TRADDR_TEST

	return pass;
}

/* -------------------------------------------------------------------------
 * unescape_uri — decode percent-encoded characters in a URI fragment
 * -------------------------------------------------------------------------
 */
static bool test_unescape_uri(void)
{
	char *out;
	bool pass = true, p;

	printf("\ntest_unescape_uri:\n");

	out = unescape_uri("hello%20world", -1);
	p = out && !strcmp(out, "hello world");
	CHECK(p, "%%20 → space: \"%s\"", out ? out : "(null)");
	pass &= p;
	free(out);

	out = unescape_uri("path%2Fsegment", -1);
	p = out && !strcmp(out, "path/segment");
	CHECK(p, "%%2F → /: \"%s\"", out ? out : "(null)");
	pass &= p;
	free(out);

	out = unescape_uri("no-escapes", -1);
	p = out && !strcmp(out, "no-escapes");
	CHECK(p, "no escapes → unchanged: \"%s\"", out ? out : "(null)");
	pass &= p;
	free(out);

	/* Truncate via explicit length */
	out = unescape_uri("hello%20world", 5);
	p = out && !strcmp(out, "hello");
	CHECK(p, "len=5 → \"%s\"", out ? out : "(null)");
	pass &= p;
	free(out);

	/* Invalid percent sequence — passed through verbatim */
	out = unescape_uri("bad%xychars", -1);
	p = out && !strcmp(out, "bad%xychars");
	CHECK(p, "invalid %%xy → verbatim: \"%s\"", out ? out : "(null)");
	pass &= p;
	free(out);

	/* Truncated percent at end of string */
	out = unescape_uri("end%2", -1);
	p = out && !strcmp(out, "end%2");
	CHECK(p, "truncated %% at end -> verbatim: \"%s\"",
	      out ? out : "(null)");
	pass &= p;
	free(out);

	return pass;
}

/* -------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------
 */
int main(int argc, char *argv[])
{
	struct libnvme_global_ctx *ctx;

	test_rc = EXIT_SUCCESS;

	/*
	 * A real context is needed for functions that call libnvme_msg()
	 * on error paths (inet6_pton, traddr_is_hostname).  Use LOG_ERR
	 * so test output stays clean during normal runs.
	 */
	ctx = libnvme_create_global_ctx(stderr, LIBNVME_LOG_ERR);
	if (!ctx) {
		fprintf(stderr, "failed to create libnvme context\n");
		return EXIT_FAILURE;
	}

	test_strchomp();
	test_hostid_from_hostnqn();
	test_add_bool_argument();
	test_add_hex_argument();
	test_add_int_argument();
	test_add_int_or_minus_one_argument();
	test_add_argument();
	test_inet4_pton();
	test_inet_pton_with_scope(ctx);
	test_traddr_is_hostname(ctx);
	test_unescape_uri();

	libnvme_free_global_ctx(ctx);

	if (test_rc == EXIT_SUCCESS)
		printf("\nAll tests passed.\n");
	else
		printf("\nSOME TESTS FAILED.\n");
	return test_rc;
}
