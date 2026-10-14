// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "resolve.h"
#include "work.h"

struct dmn_resolver {
	struct dmn_work_pool *pool;
	dmn_getaddrinfo_fn lookup;
};

/*
 * The worker writes only res, gai and sys_errno. The other fields do not
 * change after dmn_resolve().
 */
struct dmn_resolve_query {
	struct dmn_work *work;
	dmn_getaddrinfo_fn lookup;
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

static void query_free(void *data)
{
	struct dmn_resolve_query *q = data;

	if (!q)
		return;
	if (q->res)
		freeaddrinfo(q->res);
	free(q->host);
	free(q->service);
	free(q);
}

static void lookup(void *data)
{
	struct dmn_resolve_query *q = data;

	q->gai = q->lookup(q->host, q->service,
			   q->has_hints ? &q->hints : NULL, &q->res);
	q->sys_errno = errno;
}

static void lookup_done(void *data, bool timed_out)
{
	struct dmn_resolve_query *q = data;

	if (timed_out) {
		errno = ETIMEDOUT;
		q->cb(EAI_SYSTEM, NULL, q->user_data);
		return;
	}

	errno = q->sys_errno;
	q->cb(q->gai, q->res, q->user_data);
}

int dmn_resolver_new(sd_event *event, unsigned int max_workers,
		     struct dmn_resolver **ret)
{
	struct dmn_resolver *r;
	int err;

	if (!event || !max_workers || !ret)
		return -EINVAL;

	r = calloc(1, sizeof(*r));
	if (!r)
		return -ENOMEM;

	err = dmn_work_pool_new(event, max_workers, &r->pool);
	if (err < 0) {
		free(r);
		return err;
	}
	r->lookup = getaddrinfo;

	*ret = r;

	return 0;
}

void dmn_resolver_free(struct dmn_resolver *r)
{
	if (!r)
		return;

	dmn_work_pool_free(r->pool);
	free(r);
}

void dmn_resolver_set_lookup(struct dmn_resolver *r, dmn_getaddrinfo_fn fn)
{
	r->lookup = fn;
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
	int err;

	if (!r || (!host && !service) || !cb)
		return -EINVAL;

	q = query_new(host, service, hints);
	if (!q)
		return -ENOMEM;
	q->lookup = r->lookup;
	q->cb = cb;
	q->user_data = user_data;

	err = dmn_work_submit(r->pool, lookup, lookup_done, query_free, q,
			      timeout_usec, &q->work);
	if (err < 0) {
		query_free(q);
		return err;
	}

	if (ret)
		*ret = q;

	return 0;
}

void dmn_resolve_cancel(struct dmn_resolve_query *q)
{
	if (q)
		dmn_work_cancel(q->work);
}
