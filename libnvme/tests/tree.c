// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 *
 * Unit tests for non-fabrics tree operations in libnvme/src/nvme/tree.c:
 * host/subsystem creation, deduplication, iteration, and attribute getters.
 */

#include <shared/assert-util.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

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
 * test_host_dedup - libnvme_get_host() must return the same pointer for
 * the same hostnqn+hostid, and a different pointer for different credentials.
 */
static bool test_host_dedup(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvme_host *h1, *h2, *h3;
	bool pass = true;

	printf("test_host_dedup:\n");

	ctx = libnvme_create_global_ctx();
	shr_assert(ctx);

	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	shr_assert(!libnvme_get_host(ctx, HOSTNQN_1, HOSTID_1, &h1));
	shr_assert(h1);

	shr_assert(!libnvme_get_host(ctx, HOSTNQN_1, HOSTID_1, &h2));
	shr_assert(h2);

	if (h1 != h2) {
		printf(" - same hostnqn+hostid must return same pointer [FAIL]\n");
		pass = false;
	} else {
		printf(" - same hostnqn+hostid returns same pointer [PASS]\n");
	}

	shr_assert(!libnvme_get_host(ctx, HOSTNQN_2, HOSTID_2, &h3));
	shr_assert(h3);

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
 * test_hostid_from_hostnqn - When hostid is NULL, libnvme_create_host()
 * must derive the hostid from the UUID embedded in the hostnqn.
 */
static bool test_hostid_from_hostnqn(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvme_host *h;
	const char *hostid;
	bool pass = true;

	printf("test_hostid_from_hostnqn:\n");

	ctx = libnvme_create_global_ctx();
	shr_assert(ctx);

	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	libnvme_create_host(ctx, HOSTNQN_1, NULL, &h);
	shr_assert(h);

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
	struct libnvme_host *h;
	bool pass = true;

	printf("test_host_attrs:\n");

	ctx = libnvme_create_global_ctx();
	shr_assert(ctx);

	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	shr_assert(!libnvme_get_host(ctx, HOSTNQN_1, HOSTID_1, &h));
	shr_assert(h);

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
	struct libnvme_host *h;
	unsigned int count = 0;
	bool pass = true;

	printf("test_host_iteration:\n");

	ctx = libnvme_create_global_ctx();
	shr_assert(ctx);

	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	shr_assert(!libnvme_get_host(ctx, HOSTNQN_1, HOSTID_1, &h));
	shr_assert(h);
	shr_assert(!libnvme_get_host(ctx, HOSTNQN_2, HOSTID_2, &h));
	shr_assert(h);
	shr_assert(!libnvme_get_host(ctx, HOSTNQN_3, HOSTID_3, &h));
	shr_assert(h);

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
 * test_subsystem_dedup - libnvme_get_subsystem() must return the same
 * pointer for the same name+subsysnqn, and a different pointer for different
 * ones.
 */
static bool test_subsystem_dedup(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvme_host *h;
	struct libnvme_subsystem *s1, *s2, *s3;
	bool pass = true;

	printf("test_subsystem_dedup:\n");

	ctx = libnvme_create_global_ctx();
	shr_assert(ctx);

	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	shr_assert(!libnvme_get_host(ctx, HOSTNQN_1, HOSTID_1, &h));
	shr_assert(h);

	shr_assert(!libnvme_get_subsystem(ctx, h, SUBSYSNAME_1, SUBSYSNQN_1, &s1));
	shr_assert(s1);

	shr_assert(!libnvme_get_subsystem(ctx, h, SUBSYSNAME_1, SUBSYSNQN_1, &s2));
	shr_assert(s2);

	if (s1 != s2) {
		printf(" - same name+subsysnqn must return same pointer [FAIL]\n");
		pass = false;
	} else {
		printf(" - same name+subsysnqn returns same pointer [PASS]\n");
	}

	shr_assert(!libnvme_get_subsystem(ctx, h, SUBSYSNAME_2, SUBSYSNQN_2, &s3));
	shr_assert(s3);

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
	struct libnvme_host *h;
	struct libnvme_subsystem *s;
	bool pass = true;

	printf("test_subsystem_attrs:\n");

	ctx = libnvme_create_global_ctx();
	shr_assert(ctx);

	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	shr_assert(!libnvme_get_host(ctx, HOSTNQN_1, HOSTID_1, &h));
	shr_assert(h);

	shr_assert(!libnvme_get_subsystem(ctx, h, SUBSYSNAME_1, SUBSYSNQN_1, &s));
	shr_assert(s);

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
 * test_ns_attr_not_null - the namespace attribute getters must not return
 * NULL when the device does not report the attribute.
 */
static bool test_ns_attr_not_null(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvme_host *h;
	struct libnvme_subsystem *s;
	struct libnvme_ns n = {};
	const char *firmware, *serial, *model;
	bool pass = true;

	printf("test_ns_attr_not_null:\n");

	ctx = libnvme_create_global_ctx();
	shr_assert(ctx);

	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	shr_assert(!libnvme_get_host(ctx, HOSTNQN_1, HOSTID_1, &h));
	shr_assert(h);

	shr_assert(!libnvme_get_subsystem(ctx, h, SUBSYSNAME_1, SUBSYSNQN_1, &s));
	shr_assert(s);

	n.s = s;

	firmware = libnvme_ns_get_firmware(&n);
	serial = libnvme_ns_get_serial(&n);
	model = libnvme_ns_get_model(&n);

	if (!firmware) {
		printf(" - firmware getter returned NULL [FAIL]\n");
		pass = false;
	} else {
		printf(" - firmware getter returned a string [PASS]\n");
	}

	if (!serial) {
		printf(" - serial getter returned NULL [FAIL]\n");
		pass = false;
	} else {
		printf(" - serial getter returned a string [PASS]\n");
	}

	if (!model) {
		printf(" - model getter returned NULL [FAIL]\n");
		pass = false;
	} else {
		printf(" - model getter returned a string [PASS]\n");
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
	struct libnvme_host *h;
	struct libnvme_subsystem *s;
	unsigned int count = 0;
	bool pass = true;

	printf("test_subsystem_iteration:\n");

	ctx = libnvme_create_global_ctx();
	shr_assert(ctx);

	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	shr_assert(!libnvme_get_host(ctx, HOSTNQN_1, HOSTID_1, &h));
	shr_assert(h);

	shr_assert(!libnvme_get_subsystem(ctx, h, SUBSYSNAME_1, SUBSYSNQN_1, &s));
	shr_assert(!libnvme_get_subsystem(ctx, h, SUBSYSNAME_2, SUBSYSNQN_2, &s));

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

/**
 * test_host_ref_unref - libnvme_host_ref() must increment h->refcount,
 * and libnvme_host_unref() must decrement it back down. A freshly
 * created host starts at refcount 1 (the tree's own reference).
 */
static bool test_host_ref_unref(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvme_host *h;
	bool pass = true;

	printf("test_host_ref_unref:\n");

	ctx = libnvme_create_global_ctx();
	shr_assert(ctx);

	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	shr_assert(!libnvme_get_host(ctx, HOSTNQN_1, HOSTID_1, &h));
	shr_assert(h);

	if (h->refcount != 1) {
		printf(" - new host refcount 1, got %d [FAIL]\n", h->refcount);
		pass = false;
	} else {
		printf(" - new host refcount 1 [PASS]\n");
	}

	libnvme_host_ref(h);
	if (h->refcount != 2) {
		printf(" - ref() refcount 2, got %d [FAIL]\n", h->refcount);
		pass = false;
	} else {
		printf(" - ref() refcount 2 [PASS]\n");
	}

	libnvme_host_unref(h);
	if (h->refcount != 1) {
		printf(" - unref() refcount 1, got %d [FAIL]\n", h->refcount);
		pass = false;
	} else {
		printf(" - unref() refcount 1 [PASS]\n");
	}

	libnvme_free_global_ctx(ctx);
	return pass;
}

/**
 * test_host_ref_survives_refresh_topology - a host with an outstanding
 * ref must not be freed by libnvme_refresh_topology()'s unconditional
 * free-every-host pass; it should only drop back to its pre-refresh
 * refcount (the reference taken here is released, not the tree's own).
 */
static bool test_host_ref_survives_refresh_topology(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvme_host *h;
	bool pass = true;

	printf("test_host_ref_survives_refresh_topology:\n");

	ctx = libnvme_create_global_ctx();
	shr_assert(ctx);

	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	shr_assert(!libnvme_get_host(ctx, HOSTNQN_1, HOSTID_1, &h));
	shr_assert(h);

	libnvme_host_ref(h);

	libnvme_refresh_topology(ctx);

	if (h->refcount != 1) {
		printf(" - survives refresh, got %d [FAIL]\n", h->refcount);
		pass = false;
	} else {
		printf(" - host survives refresh [PASS]\n");
	}

	libnvme_host_unref(h);

	libnvme_free_global_ctx(ctx);
	return pass;
}

/**
 * test_host_survives_ctx_teardown - tearing down the ctx while a host
 * is still ref'd must detach the host, not silently skip the
 * teardown. A detached host survives -- libnvme_host_get_global_ctx()
 * reports it as detached, but ctx itself stays alive, held by the
 * host's own reference on it -- and its last unref must still free it
 * cleanly, and release that last ctx reference too.
 */
static bool test_host_survives_ctx_teardown(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvme_host *h;
	bool pass = true;

	printf("test_host_survives_ctx_teardown:\n");

	ctx = libnvme_create_global_ctx();
	shr_assert(ctx);

	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	shr_assert(!libnvme_get_host(ctx, HOSTNQN_1, HOSTID_1, &h));
	shr_assert(h);

	libnvme_host_ref(h);

	libnvme_free_global_ctx(ctx);

	if (libnvme_host_get_global_ctx(h) != NULL) {
		printf(" - host ctx not cleared after teardown [FAIL]\n");
		pass = false;
	} else {
		printf(" - host detached from torn-down ctx [PASS]\n");
	}

	libnvme_host_unref(h);

	printf(" - last unref after ctx teardown did not crash [PASS]\n");

	return pass;
}

/**
 * test_double_free_host_does_not_steal_a_ref - calling
 * libnvme_free_host() twice on the same host must not unref it
 * twice. The first call releases the tree's own reference; a second
 * call must be a no-op, not steal the decrement that belongs to
 * whoever still holds a real reference.
 */
static bool test_double_free_host_does_not_steal_a_ref(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvme_host *h;
	bool pass = true;

	printf("test_double_free_host_does_not_steal_a_ref:\n");

	ctx = libnvme_create_global_ctx();
	shr_assert(ctx);

	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	shr_assert(!libnvme_get_host(ctx, HOSTNQN_1, HOSTID_1, &h));
	shr_assert(h);

	libnvme_host_ref(h);

	libnvme_free_host(h);
	libnvme_free_host(h);

	if (h->refcount != 1) {
		printf(" - double free_host() refcount %d, want 1 [FAIL]\n",
		       h->refcount);
		pass = false;
	} else {
		printf(" - double free_host() did not steal the ref [PASS]\n");
	}

	libnvme_host_unref(h);
	libnvme_free_global_ctx(ctx);

	return pass;
}

/**
 * test_host_ref_debug_log_disabled_by_default - ref()/unref() write
 * nothing to stderr when LIBNVME_REF_DEBUG is unset.
 */
static bool test_host_ref_debug_log_disabled_by_default(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvme_host *h;
	FILE *capture;
	int saved_stderr;
	char buf[256];
	size_t n;
	bool pass = true;

	printf("test_host_ref_debug_log_disabled_by_default:\n");

	unsetenv("LIBNVME_REF_DEBUG");

	ctx = libnvme_create_global_ctx();
	shr_assert(ctx);

	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	shr_assert(!libnvme_get_host(ctx, HOSTNQN_1, HOSTID_1, &h));
	shr_assert(h);

	capture = tmpfile();
	shr_assert(capture);
	saved_stderr = dup(fileno(stderr));
	shr_assert(saved_stderr != -1);
	shr_assert(dup2(fileno(capture), fileno(stderr)) != -1);

	libnvme_host_ref(h);
	libnvme_host_unref(h);

	fflush(stderr);
	dup2(saved_stderr, fileno(stderr));
	close(saved_stderr);
	rewind(capture);
	n = fread(buf, 1, sizeof(buf) - 1, capture);
	buf[n] = '\0';
	fclose(capture);

	if (n != 0) {
		printf(" - no stderr, got %zu bytes: %s [FAIL]\n", n, buf);
		pass = false;
	} else {
		printf(" - no stderr output when unset [PASS]\n");
	}

	libnvme_free_global_ctx(ctx);
	return pass;
}

/* Runs as the re-exec'd child for test_host_ref_debug_log_enabled().
 * LIBNVME_REF_DEBUG is set in the child's environment before exec, so
 * this is the first ref/unref this process sees: the pthread_once
 * cache in __libnvme_ref_debug_log() has not fired yet.
 */
static bool debug_log_enabled_child(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvme_host *h;
	FILE *capture;
	int saved_stderr;
	char buf[256];
	size_t n;
	bool pass;

	ctx = libnvme_create_global_ctx();
	shr_assert(ctx);

	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	shr_assert(!libnvme_get_host(ctx, HOSTNQN_1, HOSTID_1, &h));
	shr_assert(h);

	capture = tmpfile();
	shr_assert(capture);
	saved_stderr = dup(fileno(stderr));
	shr_assert(saved_stderr != -1);
	shr_assert(dup2(fileno(capture), fileno(stderr)) != -1);

	libnvme_host_ref(h);
	libnvme_host_unref(h);

	fflush(stderr);
	dup2(saved_stderr, fileno(stderr));
	close(saved_stderr);
	rewind(capture);
	n = fread(buf, 1, sizeof(buf) - 1, capture);
	buf[n] = '\0';
	fclose(capture);

	pass = n != 0 && strstr(buf, "tree.c") && strstr(buf, "ref host=") &&
	       strstr(buf, "count=2");
	if (!pass)
		fprintf(stderr, "stderr shows call site, got: %s\n", buf);

	libnvme_free_global_ctx(ctx);
	return pass;
}

/**
 * test_host_ref_debug_log_enabled - with LIBNVME_REF_DEBUG set,
 * libnvme_host_ref() logs call site and refcount to stderr.
 *
 * The env var is only read once per process (see
 * __libnvme_ref_debug_log() in tree.c), and some earlier test has
 * already forced that read with LIBNVME_REF_DEBUG unset. So this
 * re-execs the test binary in a fresh child with the var set, rather
 * than setenv() here, which the cache would never see.
 */
static bool test_host_ref_debug_log_enabled(void)
{
	pid_t pid;
	int status;
	bool pass = true;

	printf("test_host_ref_debug_log_enabled:\n");

	pid = fork();
	shr_assert(pid != -1);
	if (pid == 0) {
		setenv("LIBNVME_REF_DEBUG", "1", 1);
		execl("/proc/self/exe", "test-tree",
		      "--debug-log-enabled-child", NULL);
		_exit(127);
	}

	shr_assert(waitpid(pid, &status, 0) == pid);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		printf(" - debug log enabled check failed in child [FAIL]\n");
		pass = false;
	} else {
		printf(" - stderr shows call site and refcount [PASS]\n");
	}

	return pass;
}

/* Reliably reproduces the race without being tuned to this machine's
 * core count: pre-atomic this segfaults every run; post-atomic it's
 * clean every run.
 */
#define STRESS_THREAD_COUNT 8
#define STRESS_ITERATIONS   50000

static void *ref_unref_thread(void *arg)
{
	struct libnvme_host *h = arg;
	int i;

	for (i = 0; i < STRESS_ITERATIONS; i++) {
		libnvme_host_ref(h);
		libnvme_host_unref(h);
	}

	return NULL;
}

/**
 * test_host_ref_unref_is_thread_safe - concurrent libnvme_host_ref()/
 * libnvme_host_unref() calls from multiple threads must not corrupt
 * h->refcount via lost updates. Each thread does an equal number of
 * ref/unref pairs, so the net effect on the shared baseline must be
 * zero: refcount must be back to 1 once every thread has joined.
 */
static bool test_host_ref_unref_is_thread_safe(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvme_host *h;
	pthread_t threads[STRESS_THREAD_COUNT];
	int i;
	bool pass = true;

	printf("test_host_ref_unref_is_thread_safe:\n");

	ctx = libnvme_create_global_ctx();
	shr_assert(ctx);

	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	shr_assert(!libnvme_get_host(ctx, HOSTNQN_1, HOSTID_1, &h));
	shr_assert(h);

	for (i = 0; i < STRESS_THREAD_COUNT; i++)
		shr_assert(!pthread_create(&threads[i], NULL,
				ref_unref_thread, h));

	for (i = 0; i < STRESS_THREAD_COUNT; i++)
		shr_assert(!pthread_join(threads[i], NULL));

	if (h->refcount != 1) {
		printf(" - refcount 1 after %d x %d ref/unref, got %d [FAIL]\n",
			STRESS_THREAD_COUNT, STRESS_ITERATIONS, h->refcount);
		pass = false;
	} else {
		printf(" - refcount 1 after %d x %d ref/unref [PASS]\n",
			STRESS_THREAD_COUNT, STRESS_ITERATIONS);
	}

	libnvme_free_global_ctx(ctx);
	return pass;
}

#define RACE_THREAD_COUNT 4
#define RACE_ITERATIONS   5000

static void *lookup_ref_thread(void *arg)
{
	struct libnvme_global_ctx *ctx = arg;
	int i;

	for (i = 0; i < RACE_ITERATIONS; i++) {
		struct libnvme_host *h;

		libnvme_topology_lock(ctx);
		if (libnvme_get_host(ctx, HOSTNQN_1, HOSTID_1, &h))
			h = NULL;
		else
			libnvme_host_ref(h);
		libnvme_topology_unlock(ctx);

		if (h) {
			shr_assert(streq(libnvme_host_get_hostnqn(h),
					  HOSTNQN_1));
			libnvme_host_unref(h);
		}
	}

	return NULL;
}

static void *churn_thread(void *arg)
{
	struct libnvme_global_ctx *ctx = arg;
	int i;

	for (i = 0; i < RACE_ITERATIONS; i++) {
		struct libnvme_host *h;

		libnvme_topology_lock(ctx);
		h = libnvme_first_host(ctx);
		if (h)
			libnvme_free_host(h);
		libnvme_topology_unlock(ctx);
	}

	return NULL;
}

/**
 * test_lookup_ref_races_with_free - a lookup+ref must not race with
 * another thread detaching and freeing the same host (reported in
 * review: lookup could return a host whose count another thread had
 * just dropped to zero). Both sides hold topology_lock, so a lookup
 * always sees either the live host or a freshly recreated one --
 * never a stale pointer.
 */
static bool test_lookup_ref_races_with_free(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvme_host *h;
	pthread_t lookers[RACE_THREAD_COUNT], churners[RACE_THREAD_COUNT];
	int i;
	bool pass = true;

	printf("test_lookup_ref_races_with_free:\n");

	ctx = libnvme_create_global_ctx();
	shr_assert(ctx);

	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	for (i = 0; i < RACE_THREAD_COUNT; i++) {
		shr_assert(!pthread_create(&lookers[i], NULL,
				lookup_ref_thread, ctx));
		shr_assert(!pthread_create(&churners[i], NULL,
				churn_thread, ctx));
	}
	for (i = 0; i < RACE_THREAD_COUNT; i++) {
		shr_assert(!pthread_join(lookers[i], NULL));
		shr_assert(!pthread_join(churners[i], NULL));
	}

	if (libnvme_get_host(ctx, HOSTNQN_1, HOSTID_1, &h) ||
	    !streq(libnvme_host_get_hostnqn(h), HOSTNQN_1)) {
		printf(" - tree unusable after the race [FAIL]\n");
		pass = false;
	} else {
		printf(" - concurrent lookup/ref vs free survived [PASS]\n");
	}

	libnvme_free_global_ctx(ctx);
	return pass;
}

int main(int argc, char *argv[])
{
	bool pass = true;

	if (argc > 1 && !strcmp(argv[1], "--debug-log-enabled-child"))
		exit(debug_log_enabled_child() ? EXIT_SUCCESS : EXIT_FAILURE);

	pass &= test_host_dedup();
	pass &= test_hostid_from_hostnqn();
	pass &= test_host_attrs();
	pass &= test_host_iteration();
	pass &= test_subsystem_dedup();
	pass &= test_subsystem_attrs();
	pass &= test_ns_attr_not_null();
	pass &= test_subsystem_iteration();
	pass &= test_host_ref_unref();
	pass &= test_host_ref_survives_refresh_topology();
	pass &= test_host_survives_ctx_teardown();
	pass &= test_double_free_host_does_not_steal_a_ref();
	pass &= test_host_ref_debug_log_disabled_by_default();
	pass &= test_host_ref_debug_log_enabled();
	pass &= test_host_ref_unref_is_thread_safe();
	pass &= test_lookup_ref_races_with_free();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
