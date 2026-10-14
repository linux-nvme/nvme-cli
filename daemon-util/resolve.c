// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <ccan/list/list.h>

#include "resolve.h"

enum query_state {
	QUERY_QUEUED,	// waiting for a worker
	QUERY_RUNNING,	// a worker is in getaddrinfo()
	QUERY_DONE,	// waiting for the event loop
	QUERY_DROPPED,	// cancelled while running: the worker frees it
};

/*
 * The state shared with the workers. A worker can outlive the resolver
 * while it is in getaddrinfo(), so the pool is freed by its last user.
 */
struct pool {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	struct list_head queued;
	struct list_head done;
	unsigned int max_workers;
	unsigned int nr_workers;
	unsigned int nr_idle;
	unsigned int nr_queued;
	unsigned int refs;	// the resolver and each worker
	bool closing;
	int fd;			// eventfd: the workers wake up the event loop
	dmn_getaddrinfo_fn lookup;
};

struct dmn_resolver {
	struct pool *pool;
	sd_event *event;
	sd_event_source *io;
	struct list_head active;	// event loop only
	bool dispatching;
	bool free_pending;
};

struct dmn_resolve_query {
	struct list_node pool_node;	// in pool->queued or pool->done
	struct list_node node;		// in resolver->active
	struct dmn_resolver *r;
	sd_event_source *timer;
	enum query_state state;		// pool->lock
	char *host;
	char *service;
	struct addrinfo hints;
	bool has_hints;
	struct addrinfo *res;
	int gai;
	int sys_errno;		// for EAI_SYSTEM
	dmn_resolve_callback cb;
	void *user_data;
};

static void query_free(struct dmn_resolve_query *q)
{
	if (!q)
		return;
	free(q->host);
	free(q->service);
	free(q);
}

// Called with pool->lock held. Unlocks it.
static void pool_unref_unlock(struct pool *p)
{
	bool last = --p->refs == 0;

	pthread_mutex_unlock(&p->lock);
	if (!last)
		return;

	pthread_cond_destroy(&p->cond);
	pthread_mutex_destroy(&p->lock);
	close(p->fd);
	free(p);
}

static void *worker(void *arg)
{
	static const uint64_t one = 1;
	struct pool *p = arg;
	struct dmn_resolve_query *q;
	dmn_getaddrinfo_fn lookup;
	struct addrinfo *res;
	int gai, sys_errno;

	pthread_mutex_lock(&p->lock);
	for (;;) {
		while (!p->closing && list_empty(&p->queued)) {
			p->nr_idle++;
			pthread_cond_wait(&p->cond, &p->lock);
			p->nr_idle--;
		}
		if (p->closing)
			break;

		q = list_pop(&p->queued, struct dmn_resolve_query, pool_node);
		p->nr_queued--;
		q->state = QUERY_RUNNING;
		lookup = p->lookup;
		pthread_mutex_unlock(&p->lock);

		res = NULL;
		gai = lookup(q->host, q->service,
			     q->has_hints ? &q->hints : NULL, &res);
		sys_errno = errno;

		pthread_mutex_lock(&p->lock);
		if (q->state == QUERY_DROPPED) {
			if (res)
				freeaddrinfo(res);
			query_free(q);
			continue;
		}

		q->state = QUERY_DONE;
		q->gai = gai;
		q->sys_errno = sys_errno;
		q->res = res;
		list_add_tail(&p->done, &q->pool_node);
		// Cannot fail: the counter is far from overflowing.
		(void)!write(p->fd, &one, sizeof(one));
	}
	pool_unref_unlock(p);

	return NULL;
}

// Called with pool->lock held.
static int start_worker(struct pool *p)
{
	pthread_attr_t attr;
	sigset_t all, old;
	pthread_t t;
	int ret;

	ret = pthread_attr_init(&attr);
	if (ret)
		return -ret;
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	// Signals go to the event loop thread, not to a worker.
	sigfillset(&all);
	pthread_sigmask(SIG_BLOCK, &all, &old);
	ret = pthread_create(&t, &attr, worker, p);
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	pthread_attr_destroy(&attr);
	if (ret)
		return -ret;

	p->refs++;
	p->nr_workers++;

	return 0;
}

/*
 * Take @q away from the pool and from the event loop. Returns the query if
 * the caller must free it, NULL if a worker frees it.
 */
static struct dmn_resolve_query *detach(struct dmn_resolve_query *q)
{
	struct pool *p = q->r->pool;
	bool running;

	list_del(&q->node);
	q->timer = sd_event_source_disable_unref(q->timer);

	pthread_mutex_lock(&p->lock);
	running = q->state == QUERY_RUNNING;
	if (running)
		q->state = QUERY_DROPPED;
	else
		list_del(&q->pool_node);
	if (q->state == QUERY_QUEUED)
		p->nr_queued--;
	pthread_mutex_unlock(&p->lock);

	if (running)
		return NULL;

	if (q->res)
		freeaddrinfo(q->res);
	q->res = NULL;

	return q;
}

static void destroy(struct dmn_resolver *r)
{
	struct dmn_resolve_query *q, *next;
	struct pool *p = r->pool;

	list_for_each_safe(&r->active, q, next, node) {
		q = detach(q);
		if (q)
			query_free(q);
	}
	sd_event_source_disable_unref(r->io);
	sd_event_unref(r->event);
	free(r);

	pthread_mutex_lock(&p->lock);
	p->closing = true;
	pthread_cond_broadcast(&p->cond);
	pool_unref_unlock(p);
}

// Detach @q, free it, then call its callback.
static void finish(struct dmn_resolve_query *q, int gai, int sys_errno,
		   struct addrinfo *res)
{
	dmn_resolve_callback cb = q->cb;
	void *user_data = q->user_data;

	q->res = NULL;
	q = detach(q);
	query_free(q);

	errno = sys_errno;
	cb(gai, res, user_data);
	if (res)
		freeaddrinfo(res);
}

static int on_done(sd_event_source *src __attribute__((unused)), int fd,
		   uint32_t revents __attribute__((unused)), void *user_data)
{
	struct dmn_resolver *r = user_data;
	struct dmn_resolve_query *q;
	uint64_t n;

	(void)!read(fd, &n, sizeof(n));

	r->dispatching = true;
	while (!r->free_pending) {
		pthread_mutex_lock(&r->pool->lock);
		q = list_top(&r->pool->done, struct dmn_resolve_query,
			     pool_node);
		pthread_mutex_unlock(&r->pool->lock);
		if (!q)
			break;

		finish(q, q->gai, q->sys_errno, q->res);
	}
	r->dispatching = false;

	if (r->free_pending)
		destroy(r);

	return 0;
}

static int on_timeout(sd_event_source *src __attribute__((unused)),
		      uint64_t usec __attribute__((unused)), void *user_data)
{
	struct dmn_resolve_query *q = user_data;
	struct pool *p = q->r->pool;
	bool done;

	// A result that is ready is reported by on_done().
	pthread_mutex_lock(&p->lock);
	done = q->state == QUERY_DONE;
	pthread_mutex_unlock(&p->lock);
	if (done)
		return 0;

	finish(q, EAI_SYSTEM, ETIMEDOUT, NULL);

	return 0;
}

int dmn_resolver_new(sd_event *event, unsigned int max_workers,
		     struct dmn_resolver **ret)
{
	struct dmn_resolver *r;
	struct pool *p;
	int err;

	if (!event || !max_workers || !ret)
		return -EINVAL;

	r = calloc(1, sizeof(*r));
	p = calloc(1, sizeof(*p));
	if (!r || !p) {
		free(r);
		free(p);
		return -ENOMEM;
	}

	p->fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (p->fd < 0) {
		err = -errno;
		free(r);
		free(p);
		return err;
	}
	pthread_mutex_init(&p->lock, NULL);
	pthread_cond_init(&p->cond, NULL);
	list_head_init(&p->queued);
	list_head_init(&p->done);
	p->max_workers = max_workers;
	p->refs = 1;
	p->lookup = getaddrinfo;

	r->pool = p;
	r->event = sd_event_ref(event);
	list_head_init(&r->active);

	err = sd_event_add_io(event, &r->io, p->fd, EPOLLIN, on_done, r);
	if (err < 0) {
		destroy(r);
		return err;
	}

	*ret = r;

	return 0;
}

void dmn_resolver_free(struct dmn_resolver *r)
{
	if (!r)
		return;

	if (r->dispatching) {
		r->free_pending = true;
		return;
	}
	destroy(r);
}

void dmn_resolver_set_lookup(struct dmn_resolver *r, dmn_getaddrinfo_fn fn)
{
	pthread_mutex_lock(&r->pool->lock);
	r->pool->lookup = fn;
	pthread_mutex_unlock(&r->pool->lock);
}

static struct dmn_resolve_query *query_new(const char *host,
		const char *service, const struct addrinfo *hints)
{
	struct dmn_resolve_query *q = calloc(1, sizeof(*q));

	if (!q)
		return NULL;

	if (host)
		q->host = strdup(host);
	if (service)
		q->service = strdup(service);
	if ((host && !q->host) || (service && !q->service)) {
		query_free(q);
		return NULL;
	}

	if (hints) {
		q->hints.ai_flags = hints->ai_flags;
		q->hints.ai_family = hints->ai_family;
		q->hints.ai_socktype = hints->ai_socktype;
		q->hints.ai_protocol = hints->ai_protocol;
		q->has_hints = true;
	}

	return q;
}

int dmn_resolve(struct dmn_resolver *r, const char *host, const char *service,
		const struct addrinfo *hints, uint64_t timeout_usec,
		dmn_resolve_callback cb, void *user_data,
		struct dmn_resolve_query **ret)
{
	struct dmn_resolve_query *q;
	struct pool *p;
	int err = 0;

	if (!r || (!host && !service) || !cb)
		return -EINVAL;
	p = r->pool;

	q = query_new(host, service, hints);
	if (!q)
		return -ENOMEM;
	q->r = r;
	q->cb = cb;
	q->user_data = user_data;

	if (timeout_usec) {
		err = sd_event_add_time_relative(r->event, &q->timer,
						 CLOCK_MONOTONIC, timeout_usec,
						 0, on_timeout, q);
		if (err < 0) {
			query_free(q);
			return err;
		}
	}

	pthread_mutex_lock(&p->lock);
	q->state = QUERY_QUEUED;
	list_add_tail(&p->queued, &q->pool_node);
	p->nr_queued++;
	if (p->nr_queued > p->nr_idle && p->nr_workers < p->max_workers)
		err = start_worker(p);
	// Without any worker, the query would never run.
	if (err && !p->nr_workers) {
		list_del(&q->pool_node);
		p->nr_queued--;
		pthread_mutex_unlock(&p->lock);
		sd_event_source_disable_unref(q->timer);
		query_free(q);
		return err;
	}
	pthread_cond_signal(&p->cond);
	pthread_mutex_unlock(&p->lock);

	list_add_tail(&r->active, &q->node);
	if (ret)
		*ret = q;

	return 0;
}

void dmn_resolve_cancel(struct dmn_resolve_query *q)
{
	if (!q)
		return;

	q = detach(q);
	query_free(q);
}
