// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <daemon-util/resolve.h>

#define DELAY_MS	300
#define USEC_PER_MSEC	1000ULL

struct result {
	int calls;
	int gai;
	int sys_errno;
	char addr[INET6_ADDRSTRLEN];
};

static sd_event *event;
static struct dmn_resolver *resolver;
static int pending;

static bool check(const char *name, bool ok)
{
	printf(" - %s [%s]\n", name, ok ? "PASS" : "FAIL");
	return ok;
}

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*
 * A slow resolver. "fail" is not found. Any other name sleeps DELAY_MS,
 * then resolves to 127.0.0.1 through getaddrinfo(), so that the result can
 * be freed with freeaddrinfo().
 */
static int slow_lookup(const char *host, const char *service,
		       const struct addrinfo *hints __attribute__((unused)),
		       struct addrinfo **res)
{
	struct addrinfo numeric = {
		.ai_flags = AI_NUMERICHOST,
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
	};

	if (!strcmp(host, "fail"))
		return EAI_NONAME;

	usleep(DELAY_MS * USEC_PER_MSEC);

	return getaddrinfo("127.0.0.1", service, &numeric, res);
}

static void on_result(int gai, const struct addrinfo *res, void *user_data)
{
	struct result *r = user_data;

	r->sys_errno = errno;
	r->calls++;
	r->gai = gai;
	if (!gai && res && res->ai_family == AF_INET)
		inet_ntop(AF_INET,
			  &((struct sockaddr_in *)res->ai_addr)->sin_addr,
			  r->addr, sizeof(r->addr));
	pending--;
}

// Run the event loop until no callback is pending, at most @limit_ms.
static void run(unsigned int limit_ms)
{
	uint64_t end = now_ms() + limit_ms;

	while (pending > 0 && now_ms() < end)
		sd_event_run(event, 50 * USEC_PER_MSEC);
}

static void setup(unsigned int max_workers, bool slow)
{
	if (dmn_resolver_new(event, max_workers, &resolver)) {
		printf("cannot create the resolver\n");
		exit(EXIT_FAILURE);
	}
	if (slow)
		dmn_resolver_set_lookup(resolver, slow_lookup);
	pending = 0;
}

static void start(const char *host, uint64_t timeout_ms, struct result *r,
		  struct dmn_resolve_query **q)
{
	struct addrinfo hints = { .ai_socktype = SOCK_STREAM };

	memset(r, 0, sizeof(*r));
	if (dmn_resolve(resolver, host, "4420", &hints,
			timeout_ms * USEC_PER_MSEC, on_result, r, q)) {
		printf("dmn_resolve(%s) failed\n", host);
		exit(EXIT_FAILURE);
	}
	pending++;
}

// Let a worker that is still in slow_lookup() finish and free its query.
static void drain_workers(void)
{
	usleep(2 * DELAY_MS * USEC_PER_MSEC);
}

static bool test_numeric(void)
{
	struct result r;
	bool pass;

	printf("numeric address:\n");
	setup(1, false);
	start("127.0.0.1", 0, &r, NULL);
	run(5000);
	pass = check("callback called once", r.calls == 1);
	pass &= check("found", r.gai == 0);
	pass &= check("address", !strcmp(r.addr, "127.0.0.1"));
	dmn_resolver_free(resolver);

	return pass;
}

static bool test_parallel(void)
{
	struct result r[4];
	uint64_t t0, elapsed;
	bool pass = true;
	int i;

	printf("parallel lookups:\n");
	setup(4, true);
	t0 = now_ms();
	for (i = 0; i < 4; i++)
		start("slow", 0, &r[i], NULL);
	run(10 * DELAY_MS);
	elapsed = now_ms() - t0;

	for (i = 0; i < 4; i++)
		pass &= r[i].calls == 1 && r[i].gai == 0;
	pass = check("4 lookups found", pass);
	pass &= check("they ran at the same time", elapsed < 3 * DELAY_MS);
	dmn_resolver_free(resolver);

	return pass;
}

static bool test_queue(void)
{
	struct result r[3];
	uint64_t t0, elapsed;
	bool pass = true;
	int i;

	printf("more lookups than workers:\n");
	setup(1, true);
	t0 = now_ms();
	for (i = 0; i < 3; i++)
		start("slow", 0, &r[i], NULL);
	run(10 * DELAY_MS);
	elapsed = now_ms() - t0;

	for (i = 0; i < 3; i++)
		pass &= r[i].calls == 1 && r[i].gai == 0;
	pass = check("3 lookups found", pass);
	pass &= check("one at a time", elapsed >= 3 * DELAY_MS);
	dmn_resolver_free(resolver);

	return pass;
}

static bool test_not_found(void)
{
	struct result r;
	bool pass;

	printf("name not found:\n");
	setup(1, true);
	start("fail", 0, &r, NULL);
	run(5000);
	pass = check("callback called once", r.calls == 1);
	pass &= check("EAI_NONAME", r.gai == EAI_NONAME);
	dmn_resolver_free(resolver);

	return pass;
}

static bool test_timeout(void)
{
	uint64_t t0, elapsed;
	struct result r;
	bool pass;

	printf("timeout:\n");
	setup(1, true);
	t0 = now_ms();
	start("slow", DELAY_MS / 6, &r, NULL);
	run(5000);
	elapsed = now_ms() - t0;
	pass = check("callback called once", r.calls == 1);
	pass &= check("EAI_SYSTEM, ETIMEDOUT",
		      r.gai == EAI_SYSTEM && r.sys_errno == ETIMEDOUT);
	pass &= check("before the lookup ended", elapsed < DELAY_MS);

	// The late result must not call the callback again.
	pending = 1;
	run(2 * DELAY_MS);
	pass &= check("no second callback", r.calls == 1);
	dmn_resolver_free(resolver);

	return pass;
}

static bool test_cancel(void)
{
	struct dmn_resolve_query *q1, *q2;
	struct result r1, r2;
	bool pass;

	printf("cancel:\n");
	setup(1, true);
	start("slow", 0, &r1, &q1);
	start("slow", 0, &r2, &q2);
	// q1 is running or about to run, q2 is queued.
	dmn_resolve_cancel(q1);
	dmn_resolve_cancel(q2);
	pending = 1;
	run(3 * DELAY_MS);
	pass = check("no callback for a running query", r1.calls == 0);
	pass &= check("no callback for a queued query", r2.calls == 0);
	dmn_resolver_free(resolver);
	drain_workers();

	return pass;
}

static bool test_free_busy(void)
{
	struct result r;

	printf("free while a lookup runs:\n");
	setup(2, true);
	start("slow", 0, &r, NULL);
	start("slow", 0, &r, NULL);
	usleep(DELAY_MS / 3 * USEC_PER_MSEC);
	dmn_resolver_free(resolver);
	drain_workers();

	return check("no callback", r.calls == 0);
}

static struct result free_r[2];

static void free_from_callback(int gai, const struct addrinfo *res,
			       void *user_data)
{
	on_result(gai, res, user_data);
	dmn_resolver_free(resolver);
	resolver = NULL;
	pending = 0;
}

static bool test_free_in_callback(void)
{
	struct addrinfo hints = { .ai_socktype = SOCK_STREAM };
	bool pass;
	int i;

	printf("free from a callback:\n");
	setup(2, true);
	for (i = 0; i < 2; i++) {
		if (dmn_resolve(resolver, "slow", NULL, &hints, 0,
				free_from_callback, &free_r[i], NULL)) {
			printf("dmn_resolve failed\n");
			exit(EXIT_FAILURE);
		}
	}
	pending = 2;
	run(5000);
	pass = check("one callback",
		     free_r[0].calls + free_r[1].calls == 1);
	pass &= check("resolver freed", !resolver);
	drain_workers();

	return pass;
}

int main(void)
{
	bool pass = true;

	if (sd_event_new(&event) < 0) {
		printf("cannot create the event loop\n");
		return EXIT_FAILURE;
	}

	pass &= test_numeric();
	pass &= test_parallel();
	pass &= test_queue();
	pass &= test_not_found();
	pass &= test_timeout();
	pass &= test_cancel();
	pass &= test_free_busy();
	pass &= test_free_in_callback();

	sd_event_unref(event);
	fflush(stdout);

	return pass ? EXIT_SUCCESS : EXIT_FAILURE;
}
