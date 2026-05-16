// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 *
 * Unit tests for non-fabrics tree operations in libnvme/src/nvme/tree.c:
 * host/subsystem creation, deduplication, iteration, and attribute getters.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libnvme.h>
#include <nvme/private.h>

#define HOSTNQN_1 "nqn.2014-08.org.nvmexpress:uuid:aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
#define HOSTID_1  "aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
#define HOSTNQN_2 "nqn.2014-08.org.nvmexpress:uuid:bbbbbbbb-2222-2222-2222-bbbbbbbbbbbb"
#define HOSTID_2  "bbbbbbbb-2222-2222-2222-bbbbbbbbbbbb"
#define HOSTNQN_3 "nqn.2014-08.org.nvmexpress:uuid:cccccccc-3333-3333-3333-cccccccccccc"
#define HOSTID_3  "cccccccc-3333-3333-3333-cccccccccccc"

#define SUBSYSNAME_1 "subsys1"
#define SUBSYSNQN_1  "nqn.2022-01.com.example:subsys1"
#define SUBSYSNAME_2 "subsys2"
#define SUBSYSNQN_2  "nqn.2022-01.com.example:subsys2"

/**
 * test_host_dedup - libnvme_lookup_host() must return the same pointer for
 * the same hostnqn+hostid, and a different pointer for different credentials.
 */
static bool test_host_dedup(void)
{
	struct libnvme_global_ctx *ctx;
	libnvme_host_t h1, h2, h3;
	bool pass = true;

	printf("test_host_dedup:\n");

	ctx = libnvme_create_global_ctx(stdout, LIBNVME_LOG_ERR);
	assert(ctx);

	h1 = libnvme_lookup_host(ctx, HOSTNQN_1, HOSTID_1);
	assert(h1);

	h2 = libnvme_lookup_host(ctx, HOSTNQN_1, HOSTID_1);
	assert(h2);

	if (h1 != h2) {
		printf(" - same hostnqn+hostid must return same pointer [FAIL]\n");
		pass = false;
	} else {
		printf(" - same hostnqn+hostid returns same pointer [PASS]\n");
	}

	h3 = libnvme_lookup_host(ctx, HOSTNQN_2, HOSTID_2);
	assert(h3);

	if (h1 == h3) {
		printf(" - different hostnqn+hostid must return different pointer [FAIL]\n");
		pass = false;
	} else {
		printf(" - different hostnqn+hostid returns different pointer [PASS]\n");
	}

	libnvme_free_global_ctx(ctx);
	return pass;
}

/**
 * test_hostid_from_hostnqn - When hostid is NULL, libnvme_lookup_host()
 * must derive the hostid from the UUID embedded in the hostnqn.
 */
static bool test_hostid_from_hostnqn(void)
{
	struct libnvme_global_ctx *ctx;
	libnvme_host_t h;
	const char *hostid;
	bool pass = true;

	printf("test_hostid_from_hostnqn:\n");

	ctx = libnvme_create_global_ctx(stdout, LIBNVME_LOG_ERR);
	assert(ctx);

	h = libnvme_lookup_host(ctx, HOSTNQN_1, NULL);
	assert(h);

	hostid = libnvme_host_get_hostid(h);
	if (!hostid || strcmp(hostid, HOSTID_1)) {
		printf(" - hostid derived from hostnqn UUID [FAIL] (got: %s)\n",
		       hostid ? hostid : "(null)");
		pass = false;
	} else {
		printf(" - hostid derived from hostnqn UUID [PASS]\n");
	}

	libnvme_free_global_ctx(ctx);
	return pass;
}

/**
 * test_host_attrs - hostnqn and hostid getters must return the values used
 * at creation time.
 */
static bool test_host_attrs(void)
{
	struct libnvme_global_ctx *ctx;
	libnvme_host_t h;
	bool pass = true;

	printf("test_host_attrs:\n");

	ctx = libnvme_create_global_ctx(stdout, LIBNVME_LOG_ERR);
	assert(ctx);

	h = libnvme_lookup_host(ctx, HOSTNQN_1, HOSTID_1);
	assert(h);

	if (!libnvme_host_get_hostnqn(h) ||
	    strcmp(libnvme_host_get_hostnqn(h), HOSTNQN_1)) {
		printf(" - hostnqn getter [FAIL]\n");
		pass = false;
	} else {
		printf(" - hostnqn getter [PASS]\n");
	}

	if (!libnvme_host_get_hostid(h) ||
	    strcmp(libnvme_host_get_hostid(h), HOSTID_1)) {
		printf(" - hostid getter [FAIL]\n");
		pass = false;
	} else {
		printf(" - hostid getter [PASS]\n");
	}

	libnvme_free_global_ctx(ctx);
	return pass;
}

/**
 * test_host_iteration - libnvme_for_each_host() must visit every host
 * exactly once.
 */
static bool test_host_iteration(void)
{
	struct libnvme_global_ctx *ctx;
	libnvme_host_t h;
	unsigned int count = 0;
	bool pass = true;

	printf("test_host_iteration:\n");

	ctx = libnvme_create_global_ctx(stdout, LIBNVME_LOG_ERR);
	assert(ctx);

	libnvme_lookup_host(ctx, HOSTNQN_1, HOSTID_1);
	libnvme_lookup_host(ctx, HOSTNQN_2, HOSTID_2);
	libnvme_lookup_host(ctx, HOSTNQN_3, HOSTID_3);

	libnvme_for_each_host(ctx, h)
		count++;

	if (count != 3) {
		printf(" - expected 3 hosts, got %u [FAIL]\n", count);
		pass = false;
	} else {
		printf(" - 3 hosts found via for_each_host [PASS]\n");
	}

	libnvme_free_global_ctx(ctx);
	return pass;
}

/**
 * test_subsystem_dedup - libnvme_lookup_subsystem() must return the same
 * pointer for the same name+subsysnqn, and a different pointer for different
 * ones.
 */
static bool test_subsystem_dedup(void)
{
	struct libnvme_global_ctx *ctx;
	libnvme_host_t h;
	libnvme_subsystem_t s1, s2, s3;
	bool pass = true;

	printf("test_subsystem_dedup:\n");

	ctx = libnvme_create_global_ctx(stdout, LIBNVME_LOG_ERR);
	assert(ctx);

	h = libnvme_lookup_host(ctx, HOSTNQN_1, HOSTID_1);
	assert(h);

	s1 = libnvme_lookup_subsystem(h, SUBSYSNAME_1, SUBSYSNQN_1);
	assert(s1);

	s2 = libnvme_lookup_subsystem(h, SUBSYSNAME_1, SUBSYSNQN_1);
	assert(s2);

	if (s1 != s2) {
		printf(" - same name+subsysnqn must return same pointer [FAIL]\n");
		pass = false;
	} else {
		printf(" - same name+subsysnqn returns same pointer [PASS]\n");
	}

	s3 = libnvme_lookup_subsystem(h, SUBSYSNAME_2, SUBSYSNQN_2);
	assert(s3);

	if (s1 == s3) {
		printf(" - different name+subsysnqn must return different pointer [FAIL]\n");
		pass = false;
	} else {
		printf(" - different name+subsysnqn returns different pointer [PASS]\n");
	}

	libnvme_free_global_ctx(ctx);
	return pass;
}

/**
 * test_subsystem_attrs - subsysnqn and name getters must return the values
 * used at creation time.
 */
static bool test_subsystem_attrs(void)
{
	struct libnvme_global_ctx *ctx;
	libnvme_host_t h;
	libnvme_subsystem_t s;
	bool pass = true;

	printf("test_subsystem_attrs:\n");

	ctx = libnvme_create_global_ctx(stdout, LIBNVME_LOG_ERR);
	assert(ctx);

	h = libnvme_lookup_host(ctx, HOSTNQN_1, HOSTID_1);
	assert(h);

	s = libnvme_lookup_subsystem(h, SUBSYSNAME_1, SUBSYSNQN_1);
	assert(s);

	if (!libnvme_subsystem_get_name(s) ||
	    strcmp(libnvme_subsystem_get_name(s), SUBSYSNAME_1)) {
		printf(" - subsystem name getter [FAIL]\n");
		pass = false;
	} else {
		printf(" - subsystem name getter [PASS]\n");
	}

	if (!libnvme_subsystem_get_subsysnqn(s) ||
	    strcmp(libnvme_subsystem_get_subsysnqn(s), SUBSYSNQN_1)) {
		printf(" - subsysnqn getter [FAIL]\n");
		pass = false;
	} else {
		printf(" - subsysnqn getter [PASS]\n");
	}

	libnvme_free_global_ctx(ctx);
	return pass;
}

/**
 * test_subsystem_iteration - libnvme_for_each_subsystem() must visit every
 * subsystem exactly once.
 */
static bool test_subsystem_iteration(void)
{
	struct libnvme_global_ctx *ctx;
	libnvme_host_t h;
	libnvme_subsystem_t s;
	unsigned int count = 0;
	bool pass = true;

	printf("test_subsystem_iteration:\n");

	ctx = libnvme_create_global_ctx(stdout, LIBNVME_LOG_ERR);
	assert(ctx);

	h = libnvme_lookup_host(ctx, HOSTNQN_1, HOSTID_1);
	assert(h);

	libnvme_lookup_subsystem(h, SUBSYSNAME_1, SUBSYSNQN_1);
	libnvme_lookup_subsystem(h, SUBSYSNAME_2, SUBSYSNQN_2);

	libnvme_for_each_subsystem(h, s)
		count++;

	if (count != 2) {
		printf(" - expected 2 subsystems, got %u [FAIL]\n", count);
		pass = false;
	} else {
		printf(" - 2 subsystems found via for_each_subsystem [PASS]\n");
	}

	libnvme_free_global_ctx(ctx);
	return pass;
}

int main(int argc, char *argv[])
{
	bool pass = true;

	pass &= test_host_dedup();
	pass &= test_hostid_from_hostnqn();
	pass &= test_host_attrs();
	pass &= test_host_iteration();
	pass &= test_subsystem_dedup();
	pass &= test_subsystem_attrs();
	pass &= test_subsystem_iteration();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
