// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <daemon-util/work.h>

#define DELAY_MS	200
#define USEC_PER_MSEC	1000ULL

struct job {
	unsigned int sleep_ms;
	int in;
	int out;		// written by the work
	int done_calls;
	bool timed_out;
	bool free_pool;		// free the pool from the done callback
	bool submit_again;	// submit another job from the done callback
};

static sd_event *event;
static struct dmn_work_pool *pool;
static int pending;
static atomic_int nr_freed;
static atomic_int nr_running;
static atomic_int max_running;

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

static void work(void *data)
{
	struct job *j = data;
	int n = atomic_fetch_add(&nr_running, 1) + 1;
	int max = atomic_load(&max_running);

	while (n > max && !atomic_compare_exchange_weak(&max_running, &max, n))
		;
	usleep(j->sleep_ms * USEC_PER_MSEC);
	j->out = j->in * 2;
	atomic_fetch_sub(&nr_running, 1);
}

// The jobs are owned by the test: count the frees only.
static void job_free(void *data __attribute__((unused)))
{
	atomic_fetch_add(&nr_freed, 1);
}

static struct job extra;

static void done(void *data, bool timed_out)
{
	struct job *j = data;

	j->done_calls++;
	j->timed_out = timed_out;
	pending--;
	if (j->free_pool) {
		dmn_work_pool_free(pool);
		pool = NULL;
	}
	if (j->submit_again &&
	    !dmn_work_submit(pool, work, done, job_free, &extra, 0, NULL))
		pending++;
}

static void run(unsigned int limit_ms)
{
	uint64_t end = now_ms() + limit_ms;

	while (pending > 0 && now_ms() < end)
		sd_event_run(event, 50 * USEC_PER_MSEC);
}

static void setup(unsigned int max_workers)
{
	if (dmn_work_pool_new(event, max_workers, &pool)) {
		printf("cannot create the pool\n");
		exit(EXIT_FAILURE);
	}
	pending = 0;
	atomic_store(&nr_freed, 0);
	atomic_store(&max_running, 0);
}

static void submit(struct job *j, unsigned int sleep_ms, uint64_t timeout_ms,
		   struct dmn_work **w)
{
	*j = (struct job){ .sleep_ms = sleep_ms, .in = 21 };
	if (dmn_work_submit(pool, work, done, job_free, j,
			    timeout_ms * USEC_PER_MSEC, w)) {
		printf("dmn_work_submit() failed\n");
		exit(EXIT_FAILURE);
	}
	pending++;
}

// Let a worker that still runs a job finish and free it.
static void drain_workers(void)
{
	usleep(2 * DELAY_MS * USEC_PER_MSEC);
}

static void teardown(void)
{
	dmn_work_pool_free(pool);
	pool = NULL;
	drain_workers();
}

static bool test_result(void)
{
	struct job j;
	bool pass;

	printf("test_result:\n");
	setup(2);
	submit(&j, 0, 0, NULL);
	run(1000);
	pass = check("the done callback is called once",
		     j.done_calls == 1 && !j.timed_out);
	pass &= check("it sees the result of the work", j.out == 42);
	pass &= check("the job is freed", atomic_load(&nr_freed) == 1);
	teardown();

	return pass;
}

static bool test_max_workers(void)
{
	struct job j[4];
	bool pass = true;
	int i;

	printf("test_max_workers:\n");
	setup(2);
	for (i = 0; i < 4; i++)
		submit(&j[i], DELAY_MS, 0, NULL);
	run(5000);
	for (i = 0; i < 4; i++)
		pass &= j[i].done_calls == 1 && j[i].out == 42;
	pass = check("all jobs end", pass);
	pass &= check("at most 2 jobs run at the same time",
		      atomic_load(&max_running) == 2);
	teardown();

	return pass;
}

static bool test_timeout(void)
{
	uint64_t t0, elapsed;
	struct job j;
	bool pass;

	printf("test_timeout:\n");
	setup(1);
	// The event loop does not run, so its time of the last wakeup gets old.
	sd_event_run(event, 0);
	usleep(DELAY_MS * USEC_PER_MSEC);

	t0 = now_ms();
	submit(&j, 2 * DELAY_MS, DELAY_MS / 2, NULL);
	run(1000);
	elapsed = now_ms() - t0;
	pass = check("the done callback reports the timeout",
		     j.done_calls == 1 && j.timed_out);
	pass &= check("not before the timeout", elapsed >= DELAY_MS / 2);
	pass &= check("before the work ends", elapsed < 2 * DELAY_MS);
	pass &= check("the job is not freed yet", atomic_load(&nr_freed) == 0);
	drain_workers();
	pass &= check("the worker frees it when the work ends",
		      atomic_load(&nr_freed) == 1);
	teardown();

	return pass;
}

static bool test_cancel(void)
{
	struct dmn_work *wa, *wb;
	struct job a, b;
	bool pass;

	printf("test_cancel:\n");
	setup(1);
	submit(&a, DELAY_MS, 0, &wa);
	submit(&b, DELAY_MS, 0, &wb);
	usleep(DELAY_MS / 2 * USEC_PER_MSEC);	// a runs, b waits

	dmn_work_cancel(wb);
	pass = check("a waiting job is freed at once",
		     atomic_load(&nr_freed) == 1);
	dmn_work_cancel(wa);
	pass &= check("a running job is not freed yet",
		      atomic_load(&nr_freed) == 1);
	drain_workers();
	sd_event_run(event, 0);
	pass &= check("the worker frees it when the work ends",
		      atomic_load(&nr_freed) == 2);
	pass &= check("no done callback is called",
		      !a.done_calls && !b.done_calls);
	teardown();

	return pass;
}

static bool test_free_from_callback(void)
{
	struct job a, b;
	bool pass;

	printf("test_free_from_callback:\n");
	setup(2);
	submit(&a, 0, 0, NULL);
	submit(&b, DELAY_MS, 0, NULL);
	a.free_pool = true;
	run(DELAY_MS / 2);
	pass = check("the first done callback frees the pool",
		     a.done_calls == 1 && !pool);
	drain_workers();
	pass &= check("the other job is freed, without callback",
		      !b.done_calls && atomic_load(&nr_freed) == 2);

	return pass;
}

static bool test_submit_from_callback(void)
{
	struct job a;
	bool pass;

	printf("test_submit_from_callback:\n");
	setup(1);
	submit(&a, 0, 0, NULL);
	a.submit_again = true;
	extra = (struct job){ .in = 5 };
	run(1000);
	pass = check("a job submitted from a done callback runs",
		     extra.done_calls == 1 && extra.out == 10);
	teardown();

	return pass;
}

int main(void)
{
	bool pass = true;

	if (sd_event_new(&event) < 0) {
		printf("cannot create the event loop\n");
		return EXIT_FAILURE;
	}

	pass &= test_result();
	pass &= test_max_workers();
	pass &= test_timeout();
	pass &= test_cancel();
	pass &= test_free_from_callback();
	pass &= test_submit_from_callback();

	sd_event_unref(event);

	fflush(stdout);
	return pass ? EXIT_SUCCESS : EXIT_FAILURE;
}
