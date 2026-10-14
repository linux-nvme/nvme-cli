/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <netdb.h>
#include <stdint.h>

#include <systemd/sd-event.h>

/*
 * Name resolution for an sd-event loop. getaddrinfo() blocks, so it runs in
 * worker threads. The results are reported from the event loop.
 */
struct dmn_resolver;
struct dmn_resolve_query;

/*
 * Called from the event loop when a lookup ends. @gai is the return code of
 * getaddrinfo(). For EAI_SYSTEM, errno is set: ETIMEDOUT when the lookup
 * timed out. @res is valid only during the call.
 */
typedef void (*dmn_resolve_callback)(int gai, const struct addrinfo *res,
				     void *user_data);

/*
 * Create a resolver that runs up to @max_workers lookups at the same time.
 * Return: 0 on success, a negative errno otherwise.
 */
int dmn_resolver_new(sd_event *event, unsigned int max_workers,
		     struct dmn_resolver **ret);

/*
 * Cancel all lookups and free @r. No callback is called. A worker that is
 * still in getaddrinfo() exits when the call returns. May be called from a
 * callback.
 */
void dmn_resolver_free(struct dmn_resolver *r);

/*
 * Look up @host and @service, as getaddrinfo() does. @hints may be NULL:
 * only its ai_flags, ai_family, ai_socktype and ai_protocol are used.
 * A @timeout_usec of 0 means no timeout. *@ret, if @ret is not NULL, is
 * valid until the callback is called or the query is cancelled.
 * Return: 0 on success, a negative errno otherwise.
 */
int dmn_resolve(struct dmn_resolver *r, const char *host, const char *service,
		const struct addrinfo *hints, uint64_t timeout_usec,
		dmn_resolve_callback cb, void *user_data,
		struct dmn_resolve_query **ret);

/* Cancel @q. Its callback is not called. */
void dmn_resolve_cancel(struct dmn_resolve_query *q);

typedef int (*dmn_getaddrinfo_fn)(const char *host, const char *service,
				  const struct addrinfo *hints,
				  struct addrinfo **res);

/*
 * Replace getaddrinfo() for the tests. The results are freed with
 * freeaddrinfo(), so @fn must return them from getaddrinfo().
 */
void dmn_resolver_set_lookup(struct dmn_resolver *r, dmn_getaddrinfo_fn fn);
