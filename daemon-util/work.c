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
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <ccan/list/list.h>

#include "work.h"

#define USEC_PER_SEC		1000000ULL
#define NSEC_PER_USEC		1000ULL
#define TIMER_ACCURACY_USEC	1000ULL

enum work_state {
	WORK_QUEUED,	// waiting for a worker
	WORK_RUNNING,	// a worker runs it
	WORK_DONE,	// waiting for the event loop
	WORK_DROPPED,	// cancelled while running: the worker frees it
};

/*
 * The state shared with the workers. A worker can outlive the pool while it
 * runs a work, so the shared state is freed by its last user.
 */
struct shared {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	struct list_head queued;
	struct list_head done;
	unsigned int max_workers;
	unsigned int nr_workers;
	unsigned int nr_idle;
	unsigned int nr_queued;
	unsigned int refs;	// the pool and each worker
	bool closing;
	int fd;			// eventfd: the workers wake up the event loop
};

struct dmn_work_pool {
	struct shared *s;
	sd_event *event;
	sd_event_source *io;
	struct list_head active;	// event loop only
	bool dispatching;
	bool free_pending;
};

struct dmn_work {
	struct list_node pool_node;	// in s->queued or s->done
	struct list_node node;		// in pool->active
	struct dmn_work_pool *p;
	sd_event_source *timer;
	enum work_state state;		// s->lock
	dmn_work_fn fn;
	dmn_work_done_fn done;
	dmn_work_free_fn free_fn;
	void *data;
};

static void work_free(struct dmn_work *w)
{
	if (!w)
		return;
	if (w->free_fn)
		w->free_fn(w->data);
	free(w);
}

// Called with s->lock held. Unlocks it.
static void shared_unref_unlock(struct shared *s)
{
	bool last = --s->refs == 0;

	pthread_mutex_unlock(&s->lock);
	if (!last)
		return;

	pthread_cond_destroy(&s->cond);
	pthread_mutex_destroy(&s->lock);
	close(s->fd);
	free(s);
}

static void *worker(void *arg)
{
	static const uint64_t one = 1;
	struct shared *s = arg;
	struct dmn_work *w;

	pthread_mutex_lock(&s->lock);
	for (;;) {
		while (!s->closing && list_empty(&s->queued)) {
			s->nr_idle++;
			pthread_cond_wait(&s->cond, &s->lock);
			s->nr_idle--;
		}
		if (s->closing)
			break;

		w = list_pop(&s->queued, struct dmn_work, pool_node);
		s->nr_queued--;
		w->state = WORK_RUNNING;
		pthread_mutex_unlock(&s->lock);

		w->fn(w->data);

		pthread_mutex_lock(&s->lock);
		if (w->state == WORK_DROPPED) {
			pthread_mutex_unlock(&s->lock);
			work_free(w);
			pthread_mutex_lock(&s->lock);
			continue;
		}

		w->state = WORK_DONE;
		list_add_tail(&s->done, &w->pool_node);
		// Cannot fail: the counter is far from overflowing.
		(void)!write(s->fd, &one, sizeof(one));
	}
	shared_unref_unlock(s);

	return NULL;
}

// Called with s->lock held.
static int start_worker(struct shared *s)
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
	ret = pthread_create(&t, &attr, worker, s);
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	pthread_attr_destroy(&attr);
	if (ret)
		return -ret;

	s->refs++;
	s->nr_workers++;

	return 0;
}

/*
 * Take @w away from the workers and from the event loop. Returns the work
 * if the caller must free it, NULL if a worker frees it.
 */
static struct dmn_work *detach(struct dmn_work *w)
{
	struct shared *s = w->p->s;
	bool running;

	list_del(&w->node);
	w->timer = sd_event_source_disable_unref(w->timer);

	pthread_mutex_lock(&s->lock);
	running = w->state == WORK_RUNNING;
	if (running)
		w->state = WORK_DROPPED;
	else
		list_del(&w->pool_node);
	if (w->state == WORK_QUEUED)
		s->nr_queued--;
	pthread_mutex_unlock(&s->lock);

	return running ? NULL : w;
}

static void destroy(struct dmn_work_pool *p)
{
	struct dmn_work *w, *next;
	struct shared *s = p->s;

	list_for_each_safe(&p->active, w, next, node)
		work_free(detach(w));
	sd_event_source_disable_unref(p->io);
	sd_event_unref(p->event);
	free(p);

	pthread_mutex_lock(&s->lock);
	s->closing = true;
	pthread_cond_broadcast(&s->cond);
	shared_unref_unlock(s);
}

// Detach @w, call its done callback, then free it.
static void finish(struct dmn_work *w, bool timed_out)
{
	dmn_work_done_fn done = w->done;
	void *data = w->data;

	w = detach(w);
	done(data, timed_out);
	work_free(w);
}

static int on_done(sd_event_source *src __attribute__((unused)), int fd,
		   uint32_t revents __attribute__((unused)), void *user_data)
{
	struct dmn_work_pool *p = user_data;
	struct dmn_work *w;
	uint64_t n;

	(void)!read(fd, &n, sizeof(n));

	p->dispatching = true;
	while (!p->free_pending) {
		pthread_mutex_lock(&p->s->lock);
		w = list_top(&p->s->done, struct dmn_work, pool_node);
		pthread_mutex_unlock(&p->s->lock);
		if (!w)
			break;

		finish(w, false);
	}
	p->dispatching = false;

	if (p->free_pending)
		destroy(p);

	return 0;
}

static int on_timeout(sd_event_source *src __attribute__((unused)),
		      uint64_t usec __attribute__((unused)), void *user_data)
{
	struct dmn_work *w = user_data;
	struct shared *s = w->p->s;
	bool done;

	// A work that ended is reported by on_done().
	pthread_mutex_lock(&s->lock);
	done = w->state == WORK_DONE;
	pthread_mutex_unlock(&s->lock);
	if (done)
		return 0;

	finish(w, true);

	return 0;
}

/*
 * sd_event_now() is the time of the last wakeup of the event loop, which
 * can be long ago when the caller ran for a while. Use the current time.
 */
static uint64_t now_usec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ts.tv_sec * USEC_PER_SEC + ts.tv_nsec / NSEC_PER_USEC;
}

int dmn_work_pool_new(sd_event *event, unsigned int max_workers,
		      struct dmn_work_pool **ret)
{
	struct dmn_work_pool *p;
	struct shared *s;
	int err;

	if (!event || !max_workers || !ret)
		return -EINVAL;

	p = calloc(1, sizeof(*p));
	s = calloc(1, sizeof(*s));
	if (!p || !s) {
		free(p);
		free(s);
		return -ENOMEM;
	}

	s->fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (s->fd < 0) {
		err = -errno;
		free(p);
		free(s);
		return err;
	}
	pthread_mutex_init(&s->lock, NULL);
	pthread_cond_init(&s->cond, NULL);
	list_head_init(&s->queued);
	list_head_init(&s->done);
	s->max_workers = max_workers;
	s->refs = 1;

	p->s = s;
	p->event = sd_event_ref(event);
	list_head_init(&p->active);

	err = sd_event_add_io(event, &p->io, s->fd, EPOLLIN, on_done, p);
	if (err < 0) {
		destroy(p);
		return err;
	}

	*ret = p;

	return 0;
}

void dmn_work_pool_free(struct dmn_work_pool *p)
{
	if (!p)
		return;

	if (p->dispatching) {
		p->free_pending = true;
		return;
	}
	destroy(p);
}

int dmn_work_submit(struct dmn_work_pool *p, dmn_work_fn fn,
		    dmn_work_done_fn done, dmn_work_free_fn free_fn,
		    void *data, uint64_t timeout_usec, struct dmn_work **ret)
{
	struct dmn_work *w;
	struct shared *s;
	int err = 0;

	if (!p || !fn || !done)
		return -EINVAL;
	s = p->s;

	w = calloc(1, sizeof(*w));
	if (!w)
		return -ENOMEM;
	w->p = p;
	w->fn = fn;
	w->done = done;
	w->free_fn = free_fn;
	w->data = data;

	if (timeout_usec) {
		err = sd_event_add_time(p->event, &w->timer, CLOCK_MONOTONIC,
					now_usec() + timeout_usec,
					TIMER_ACCURACY_USEC, on_timeout, w);
		if (err < 0) {
			free(w);
			return err;
		}
	}

	pthread_mutex_lock(&s->lock);
	w->state = WORK_QUEUED;
	list_add_tail(&s->queued, &w->pool_node);
	s->nr_queued++;
	if (s->nr_queued > s->nr_idle && s->nr_workers < s->max_workers)
		err = start_worker(s);
	// Without any worker, the work would never run.
	if (err && !s->nr_workers) {
		list_del(&w->pool_node);
		s->nr_queued--;
		pthread_mutex_unlock(&s->lock);
		sd_event_source_disable_unref(w->timer);
		free(w);
		return err;
	}
	pthread_cond_signal(&s->cond);
	pthread_mutex_unlock(&s->lock);

	list_add_tail(&p->active, &w->node);
	if (ret)
		*ret = w;

	return 0;
}

void dmn_work_cancel(struct dmn_work *w)
{
	if (!w)
		return;

	work_free(detach(w));
}
